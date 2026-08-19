package ftpreplay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/replay"
)

const maxDataBytes = 64 << 20

type Config struct {
	Control   *replay.Session
	Data      []*replay.Session
	Address   string
	Script    Script
	Variables map[string]string
	TLSConfig *tls.Config
	Timeout   time.Duration
	Verify    replay.VerifyMode
	Progress  func(string)
}

type TransferResult struct {
	Command        string `json:"command"`
	SessionID      string `json:"sessionId"`
	Direction      string `json:"direction"`
	ExpectedBytes  int    `json:"expectedBytes"`
	ActualBytes    int    `json:"actualBytes"`
	ExpectedSHA256 string `json:"expectedSha256"`
	ActualSHA256   string `json:"actualSha256"`
	Matched        bool   `json:"matched"`
}

type Result struct {
	Commands    int                 `json:"commands"`
	Replies     int                 `json:"replies"`
	Differences []replay.Difference `json:"differences,omitempty"`
	Transfers   []TransferResult    `json:"transfers,omitempty"`
	TLS         bool                `json:"tls"`
	Completed   bool                `json:"completed"`
}

func RunContext(ctx context.Context, cfg Config) (result Result, retErr error) {
	if cfg.Control == nil || cfg.Address == "" {
		return Result{}, fmt.Errorf("ftpreplay: control session and target address are required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Timeout > 10*time.Minute {
		return Result{}, fmt.Errorf("ftpreplay: timeout must not exceed 10 minutes")
	}
	_, portText, err := net.SplitHostPort(cfg.Address)
	if err != nil {
		return Result{}, fmt.Errorf("ftpreplay: invalid target address: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return Result{}, fmt.Errorf("ftpreplay: target port must be between 1 and 65535")
	}
	if cfg.Progress == nil {
		cfg.Progress = func(string) {}
	}
	dialer := net.Dialer{Timeout: cfg.Timeout}
	raw, err := dialer.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		return Result{}, err
	}
	var control net.Conn = raw
	var dataConn net.Conn
	var active net.Listener
	defer func() {
		var cleanup []error
		if dataConn != nil {
			cleanup = append(cleanup, wrapClose("data connection", dataConn.Close()))
		}
		if active != nil {
			cleanup = append(cleanup, wrapClose("active listener", active.Close()))
		}
		if control != nil {
			cleanup = append(cleanup, wrapClose("control connection", control.Close()))
		}
		retErr = errors.Join(retErr, errors.Join(cleanup...))
		if retErr != nil {
			result.Completed = false
		}
	}()
	if cfg.Script.Implicit {
		if cfg.TLSConfig == nil {
			return result, fmt.Errorf("ftpreplay: implicit FTPS requires TLS configuration")
		}
		secured := tls.Client(raw, cfg.TLSConfig.Clone())
		if err := secured.HandshakeContext(ctx); err != nil {
			return result, fmt.Errorf("ftpreplay: implicit TLS handshake: %w", err)
		}
		control, result.TLS = secured, true
	}
	reader := bufio.NewReaderSize(control, 64<<10)
	state := &replay.RuntimeState{Variables: copyVariables(cfg.Variables), Learned: map[string][]byte{}}
	ftp := adapters.FTP{}
	type pendingCommand struct {
		name       string
		protection *bool
	}
	var pending []pendingCommand
	protectData := false
	dataIndex := 0
	for i, turn := range cfg.Script.Turns {
		if err := control.SetDeadline(time.Now().Add(cfg.Timeout)); err != nil {
			return result, err
		}
		if turn.Direction == replay.ClientToServer {
			command := messageString(turn.Message, "command")
			prepared, err := ftp.Prepare(turn.Direction, turn.Message, state)
			if err != nil {
				return result, err
			}
			if command == "PORT" || command == "EPRT" {
				if active != nil {
					if err := active.Close(); err != nil {
						return result, fmt.Errorf("ftpreplay: close previous active listener: %w", err)
					}
					active = nil
				}
				active, prepared, err = prepareActive(control, command, cfg.Variables["ftp.advertise-ip"])
				if err != nil {
					return result, err
				}
			}
			if _, err := control.Write(prepared); err != nil {
				return result, fmt.Errorf("ftpreplay: write command %d: %w", i, err)
			}
			result.Commands++
			pending = append(pending, pendingCommand{name: command, protection: requestedProtection(command, prepared)})
			cfg.Progress("FTP " + command)
			continue
		}

		rawReply, actual, err := readReply(reader, cfg.Timeout)
		if err != nil {
			return result, fmt.Errorf("ftpreplay: read reply %d: %w", i, err)
		}
		result.Replies++
		diffs := ftp.Compare(turn.Message, actual, cfg.Verify)
		result.Differences = append(result.Differences, diffs...)
		code := messageInt(actual, "code")
		replyCommand := pendingCommand{}
		if len(pending) > 0 {
			replyCommand = pending[0]
		}
		if (replyCommand.name == "PASV" || replyCommand.name == "EPSV") && code/100 == 2 {
			if dataConn != nil {
				if err := dataConn.Close(); err != nil {
					return result, fmt.Errorf("ftpreplay: close previous data connection: %w", err)
				}
				dataConn = nil
			}
			endpoint, err := passiveTarget(rawReply, control.RemoteAddr())
			if err != nil {
				return result, err
			}
			dataConn, err = dialer.DialContext(ctx, "tcp", endpoint)
			if err != nil {
				return result, fmt.Errorf("ftpreplay: passive data connection: %w", err)
			}
		}
		if replyCommand.name == "AUTH" && code/100 == 2 && !result.TLS {
			if cfg.TLSConfig == nil {
				return result, fmt.Errorf("ftpreplay: explicit FTPS requires TLS configuration")
			}
			secured := tls.Client(control, cfg.TLSConfig.Clone())
			if err := secured.HandshakeContext(ctx); err != nil {
				return result, fmt.Errorf("ftpreplay: explicit TLS handshake: %w", err)
			}
			control, reader, result.TLS = secured, bufio.NewReaderSize(secured, 64<<10), true
		}
		if replyCommand.name == "PROT" && code/100 == 2 && replyCommand.protection != nil {
			protectData = *replyCommand.protection
		}
		if isTransferCommand(replyCommand.name) && code/100 == 1 {
			if dataIndex >= len(cfg.Data) {
				return result, fmt.Errorf("ftpreplay: no mapped data session for %s", replyCommand.name)
			}
			if dataConn == nil {
				if active == nil {
					return result, fmt.Errorf("ftpreplay: %s has no negotiated data connection", replyCommand.name)
				}
				accepted, err := acceptContext(ctx, active, cfg.Timeout)
				if err != nil {
					return result, err
				}
				dataConn = accepted
				if err := active.Close(); err != nil {
					active = nil
					return result, fmt.Errorf("ftpreplay: close accepted active listener: %w", err)
				}
				active = nil
			}
			if protectData {
				if cfg.TLSConfig == nil {
					return result, fmt.Errorf("ftpreplay: PROT P requires TLS configuration for the data connection")
				}
				secured := tls.Client(dataConn, cfg.TLSConfig.Clone())
				if err := secured.HandshakeContext(ctx); err != nil {
					return result, fmt.Errorf("ftpreplay: protected data handshake: %w", err)
				}
				dataConn = secured
			}
			transfer, transferErr := runTransfer(dataConn, cfg.Control, cfg.Data[dataIndex], replyCommand.name)
			closeErr := dataConn.Close()
			dataConn = nil
			if err := errors.Join(transferErr, wrapClose("data connection", closeErr)); err != nil {
				return result, err
			}
			result.Transfers = append(result.Transfers, transfer)
			dataIndex++
		}
		if code/100 != 1 && len(pending) > 0 {
			pending = pending[1:]
		}
	}
	result.Completed = true
	for _, transfer := range result.Transfers {
		if !transfer.Matched && cfg.Verify == replay.VerifyStrict {
			return result, fmt.Errorf("ftpreplay: %s data differs from capture", transfer.Command)
		}
	}
	if len(result.Differences) > 0 && cfg.Verify == replay.VerifyStrict {
		return result, fmt.Errorf("ftpreplay: %d strict control-channel difference(s)", len(result.Differences))
	}
	return result, nil
}

func isTransferCommand(command string) bool {
	switch command {
	case "LIST", "NLST", "RETR", "STOR", "APPE", "STOU":
		return true
	default:
		return false
	}
}

func requestedProtection(command string, raw []byte) *bool {
	if command != "PROT" {
		return nil
	}
	fields := strings.Fields(string(raw))
	if len(fields) != 2 {
		return nil
	}
	protected := strings.EqualFold(fields[1], "P")
	return &protected
}

func wrapClose(resource string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("ftpreplay: close %s: %w", resource, err)
}

func readReply(reader *bufio.Reader, timeout time.Duration) ([]byte, replay.Message, error) {
	var raw []byte
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, replay.Message{}, err
	}
	raw = append(raw, line...)
	if len(line) < 4 {
		return nil, replay.Message{}, fmt.Errorf("short FTP reply")
	}
	if line[3] == '-' {
		terminator := line[:3] + " "
		for len(raw) <= 1<<20 {
			line, err = reader.ReadString('\n')
			if err != nil {
				return nil, replay.Message{}, err
			}
			raw = append(raw, line...)
			if strings.HasPrefix(line, terminator) {
				break
			}
		}
	}
	messages, err := (adapters.FTP{}).Decode(replay.ServerToClient, raw)
	if err != nil || len(messages) != 1 {
		return nil, replay.Message{}, fmt.Errorf("decode FTP reply: %w", err)
	}
	return raw, messages[0], nil
}

func passiveTarget(reply []byte, remote net.Addr) (string, error) {
	line := string(reply)
	host, _, err := net.SplitHostPort(remote.String())
	if err != nil {
		return "", err
	}
	start, end := strings.LastIndex(line, "("), strings.LastIndex(line, ")")
	if start < 0 || end <= start {
		return "", fmt.Errorf("ftpreplay: passive response has no endpoint")
	}
	value := line[start+1 : end]
	if strings.Contains(value, "|||") {
		parts := strings.Split(value, "|")
		port, err := strconv.Atoi(parts[len(parts)-2])
		if err != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("ftpreplay: invalid EPSV port")
		}
		return net.JoinHostPort(host, strconv.Itoa(port)), nil
	}
	parts := strings.Split(value, ",")
	if len(parts) != 6 {
		return "", fmt.Errorf("ftpreplay: invalid PASV endpoint")
	}
	p1, err1 := strconv.Atoi(strings.TrimSpace(parts[4]))
	p2, err2 := strconv.Atoi(strings.TrimSpace(parts[5]))
	port := p1<<8 | p2
	if err1 != nil || err2 != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("ftpreplay: invalid PASV port")
	}
	// Use the authenticated control peer address to prevent FTP bounce/NAT
	// advertisements from redirecting Livewire to a third-party host.
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func prepareActive(control net.Conn, command, advertised string) (net.Listener, []byte, error) {
	local, ok := control.LocalAddr().(*net.TCPAddr)
	if !ok {
		return nil, nil, fmt.Errorf("ftpreplay: control connection has no TCP local address")
	}
	ip := netip.MustParseAddr(local.IP.String()).Unmap()
	if advertised != "" {
		parsed, err := netip.ParseAddr(advertised)
		if err != nil || parsed.IsUnspecified() || parsed.IsMulticast() {
			return nil, nil, fmt.Errorf("ftpreplay: invalid ftp.advertise-ip %q", advertised)
		}
		ip = parsed.Unmap()
	}
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: local.IP, Port: 0})
	if err != nil {
		return nil, nil, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if command == "PORT" && ip.Is4() {
		octets := ip.As4()
		line := fmt.Sprintf("PORT %d,%d,%d,%d,%d,%d\r\n", octets[0], octets[1], octets[2], octets[3], port>>8, port&255)
		return listener, []byte(line), nil
	}
	family := 2
	if ip.Is4() {
		family = 1
	}
	return listener, []byte(fmt.Sprintf("EPRT |%d|%s|%d|\r\n", family, ip, port)), nil
}

func acceptContext(ctx context.Context, listener net.Listener, timeout time.Duration) (net.Conn, error) {
	if tcp, ok := listener.(*net.TCPListener); ok {
		if err := tcp.SetDeadline(time.Now().Add(timeout)); err != nil {
			return nil, fmt.Errorf("ftpreplay: set active listener deadline: %w", err)
		}
	}
	type answer struct {
		conn net.Conn
		err  error
	}
	ch := make(chan answer, 1)
	go func() { conn, err := listener.Accept(); ch <- answer{conn, err} }()
	select {
	case <-ctx.Done():
		return nil, errors.Join(ctx.Err(), wrapClose("active listener", listener.Close()))
	case result := <-ch:
		return result.conn, result.err
	}
}

func runTransfer(conn net.Conn, control, data *replay.Session, command string) (TransferResult, error) {
	clientStream, serverStream, err := replay.TCPPayloadStreams(data)
	if err != nil {
		return TransferResult{}, err
	}
	ftpClientIsTCPClient := data.Client.IP == control.Client.IP
	fromFTPClient, fromFTPServer := clientStream, serverStream
	if !ftpClientIsTCPClient {
		fromFTPClient, fromFTPServer = serverStream, clientStream
	}
	upload := command == "STOR" || command == "APPE" || command == "STOU"
	expected := fromFTPServer
	direction := "server-to-client"
	if upload {
		expected, direction = fromFTPClient, "client-to-server"
	}
	wantHash := sha256.Sum256(expected)
	result := TransferResult{Command: command, SessionID: data.ID, Direction: direction, ExpectedBytes: len(expected), ExpectedSHA256: fmt.Sprintf("sha256:%x", wantHash)}
	if upload {
		n, err := io.Copy(conn, bytes.NewReader(expected))
		result.ActualBytes = int(n)
		result.ActualSHA256 = result.ExpectedSHA256
		result.Matched = err == nil && n == int64(len(expected))
		return result, err
	}
	limited := io.LimitReader(conn, maxDataBytes+1)
	actual, err := io.ReadAll(limited)
	if err != nil {
		return result, err
	}
	if len(actual) > maxDataBytes {
		return result, fmt.Errorf("ftpreplay: data transfer exceeds %d bytes", maxDataBytes)
	}
	gotHash := sha256.Sum256(actual)
	result.ActualBytes = len(actual)
	result.ActualSHA256 = fmt.Sprintf("sha256:%x", gotHash)
	result.Matched = result.ActualBytes == result.ExpectedBytes && result.ActualSHA256 == result.ExpectedSHA256
	return result, nil
}

func messageString(message replay.Message, key string) string {
	value, _ := message.Fields[key].(string)
	return value
}

func messageInt(message replay.Message, key string) int {
	value, _ := message.Fields[key].(int)
	return value
}

func copyVariables(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
