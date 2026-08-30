package ftpreplay

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/tlsreplay"
)

func ftpControlSession(passivePort uint16) *replay.Session {
	client := replay.Endpoint{IP: netip.MustParseAddr("192.0.2.10"), Port: 41000}
	server := replay.Endpoint{IP: netip.MustParseAddr("192.0.2.20"), Port: 21}
	payloads := []struct {
		dir replay.Direction
		at  time.Duration
		p   string
	}{
		{replay.ServerToClient, 0, "220 ready\r\n"},
		{replay.ClientToServer, time.Millisecond, "USER capture\r\n"},
		{replay.ServerToClient, 2 * time.Millisecond, "331 password\r\n"},
		{replay.ClientToServer, 3 * time.Millisecond, "PASS capture-secret\r\n"},
		{replay.ServerToClient, 4 * time.Millisecond, "230 logged in\r\n"},
		{replay.ClientToServer, 5 * time.Millisecond, "EPSV\r\n"},
		{replay.ServerToClient, 6 * time.Millisecond, fmt.Sprintf("229 Entering Extended Passive Mode (|||%d|)\r\n", passivePort)},
		{replay.ClientToServer, 7 * time.Millisecond, "RETR file.bin\r\n"},
		{replay.ServerToClient, 8 * time.Millisecond, "150 opening data\r\n"},
		{replay.ServerToClient, 10 * time.Millisecond, "226 transfer complete\r\n"},
		{replay.ClientToServer, 11 * time.Millisecond, "QUIT\r\n"},
		{replay.ServerToClient, 12 * time.Millisecond, "221 bye\r\n"},
	}
	session := &replay.Session{ID: "tcp-0", Transport: replay.TransportTCP, Client: client, Server: server}
	for i, payload := range payloads {
		session.Events = append(session.Events, replay.Event{PacketIndex: i, At: payload.at, Direction: payload.dir, Payload: []byte(payload.p)})
	}
	return session
}

func ftpDataSession(passivePort uint16, payload string) *replay.Session {
	return &replay.Session{
		ID: "tcp-1", Transport: replay.TransportTCP,
		Client: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.10"), Port: 42000},
		Server: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.20"), Port: passivePort},
		Events: []replay.Event{{PacketIndex: 20, At: 9 * time.Millisecond, Direction: replay.ServerToClient, Payload: []byte(payload)}},
	}
}

func TestPassiveFTPReplayCoordinatesDataAndCredentials(t *testing.T) {
	dataListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dataListener.Close()
	dataPort := uint16(dataListener.Addr().(*net.TCPAddr).Port)
	controlListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer controlListener.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := controlListener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		write := func(line string) bool {
			_, err := conn.Write([]byte(line))
			if err != nil {
				serverErr <- err
				return false
			}
			return true
		}
		if !write("220 ready\r\n") {
			return
		}
		line, _ := reader.ReadString('\n')
		if line != "USER live\r\n" {
			serverErr <- fmt.Errorf("USER=%q", line)
			return
		}
		if !write("331 password\r\n") {
			return
		}
		line, _ = reader.ReadString('\n')
		if line != "PASS live-secret\r\n" {
			serverErr <- fmt.Errorf("PASS=%q", line)
			return
		}
		if !write("230 logged in\r\n") {
			return
		}
		line, _ = reader.ReadString('\n')
		if strings.TrimSpace(line) != "EPSV" {
			serverErr <- fmt.Errorf("EPSV=%q", line)
			return
		}
		if !write(fmt.Sprintf("229 Entering Extended Passive Mode (|||%d|)\r\n", dataPort)) {
			return
		}
		dataConn, err := dataListener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		line, _ = reader.ReadString('\n')
		if strings.TrimSpace(line) != "RETR file.bin" {
			serverErr <- fmt.Errorf("RETR=%q", line)
			return
		}
		if !write("150 opening data\r\n") {
			return
		}
		_, err = dataConn.Write([]byte("hello ftp"))
		_ = dataConn.Close()
		if err != nil {
			serverErr <- err
			return
		}
		if !write("226 transfer complete\r\n") {
			return
		}
		line, _ = reader.ReadString('\n')
		if strings.TrimSpace(line) != "QUIT" {
			serverErr <- fmt.Errorf("QUIT=%q", line)
			return
		}
		if !write("221 bye\r\n") {
			return
		}
		serverErr <- nil
	}()

	control := ftpControlSession(40000)
	data := ftpDataSession(40000, "hello ftp")
	script, err := BuildScript(control, nil)
	if err != nil {
		t.Fatal(err)
	}
	trace := &replay.Trace{Packets: 21, Sessions: []*replay.Session{control, data}}
	mapped, err := MatchDataSessions(trace, control, script)
	if err != nil || len(mapped) != 1 || mapped[0].ID != data.ID {
		t.Fatalf("mapped=%v err=%v", mapped, err)
	}
	result, err := RunContext(context.Background(), Config{
		Control: control, Data: mapped, Address: controlListener.Addr().String(), Script: script,
		Variables: map[string]string{"ftp.user": "live", "ftp.password": "live-secret"},
		Timeout:   5 * time.Second, Verify: replay.VerifyStrict,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Completed || !result.Verified || len(result.Transfers) != 1 || !result.Transfers[0].Matched {
		t.Fatalf("result=%+v", result)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestBuildScriptRequiresKeyLogForExplicitFTPS(t *testing.T) {
	session := &replay.Session{ID: "tcp-0", Transport: replay.TransportTCP}
	session.Events = []replay.Event{
		{PacketIndex: 0, At: 0, Direction: replay.ClientToServer, Payload: append([]byte("AUTH TLS\r\n"), []byte{22, 3, 3, 0, 1, 1}...)},
		{PacketIndex: 1, At: time.Millisecond, Direction: replay.ServerToClient, Payload: append([]byte("234 proceed\r\n"), []byte{22, 3, 3, 0, 1, 1}...)},
	}
	if _, err := BuildScript(session, nil); err == nil || !strings.Contains(err.Error(), "key log") {
		t.Fatalf("error=%v", err)
	}
}

func TestActiveFTPUploadRewritesEndpoint(t *testing.T) {
	controlListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer controlListener.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := controlListener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		if _, err := conn.Write([]byte("220 ready\r\n")); err != nil {
			serverErr <- err
			return
		}
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "PORT ") {
			serverErr <- fmt.Errorf("PORT=%q err=%v", line, err)
			return
		}
		endpoint, ok := capturedPORT(strings.TrimSpace(strings.TrimPrefix(line, "PORT ")))
		if !ok {
			serverErr <- fmt.Errorf("invalid rewritten PORT %q", line)
			return
		}
		if _, err := conn.Write([]byte("200 PORT accepted\r\n")); err != nil {
			serverErr <- err
			return
		}
		line, err = reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "STOR upload.bin" {
			serverErr <- fmt.Errorf("STOR=%q err=%v", line, err)
			return
		}
		data, err := net.DialTimeout("tcp", endpoint.String(), time.Second)
		if err != nil {
			serverErr <- err
			return
		}
		if _, err := conn.Write([]byte("150 opening\r\n")); err != nil {
			serverErr <- err
			return
		}
		body, err := io.ReadAll(data)
		_ = data.Close()
		if err != nil || string(body) != "uploaded bytes" {
			serverErr <- fmt.Errorf("upload=%q err=%v", body, err)
			return
		}
		if _, err := conn.Write([]byte("226 done\r\n")); err != nil {
			serverErr <- err
			return
		}
		line, err = reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "QUIT" {
			serverErr <- fmt.Errorf("QUIT=%q err=%v", line, err)
			return
		}
		_, err = conn.Write([]byte("221 bye\r\n"))
		serverErr <- err
	}()

	client := replay.Endpoint{IP: netip.MustParseAddr("192.0.2.10"), Port: 41000}
	server := replay.Endpoint{IP: netip.MustParseAddr("192.0.2.20"), Port: 21}
	control := &replay.Session{ID: "tcp-0", Transport: replay.TransportTCP, Client: client, Server: server}
	turns := []struct {
		dir replay.Direction
		raw string
	}{
		{replay.ServerToClient, "220 ready\r\n"},
		{replay.ClientToServer, "PORT 192,0,2,10,195,80\r\n"},
		{replay.ServerToClient, "200 PORT accepted\r\n"},
		{replay.ClientToServer, "STOR upload.bin\r\n"},
		{replay.ServerToClient, "150 opening\r\n"},
		{replay.ServerToClient, "226 done\r\n"},
		{replay.ClientToServer, "QUIT\r\n"},
		{replay.ServerToClient, "221 bye\r\n"},
	}
	for i, turn := range turns {
		control.Events = append(control.Events, replay.Event{PacketIndex: i, At: time.Duration(i) * time.Millisecond, Direction: turn.dir, Payload: []byte(turn.raw)})
	}
	data := &replay.Session{ID: "tcp-1", Transport: replay.TransportTCP, Client: replay.Endpoint{IP: client.IP, Port: 42000}, Server: replay.Endpoint{IP: server.IP, Port: 50000}, Events: []replay.Event{{PacketIndex: 20, At: 4 * time.Millisecond, Direction: replay.ClientToServer, Payload: []byte("uploaded bytes")}}}
	script, err := BuildScript(control, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := RunContext(context.Background(), Config{Control: control, Data: []*replay.Session{data}, Address: controlListener.Addr().String(), Script: script, Timeout: 5 * time.Second, Verify: replay.VerifyStrict})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Completed || len(result.Transfers) != 1 || !result.Transfers[0].Matched || result.Transfers[0].Direction != "client-to-server" {
		t.Fatalf("result=%+v", result)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestExplicitFTPSUpgradesControlConnection(t *testing.T) {
	template := httptest.NewTLSServer(nil)
	certificate := template.TLS.Certificates[0]
	template.Close()
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("220 ready\r\n")); err != nil {
			serverErr <- err
			return
		}
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "AUTH TLS" {
			serverErr <- fmt.Errorf("AUTH=%q err=%v", line, err)
			return
		}
		if _, err := conn.Write([]byte("234 proceed\r\n")); err != nil {
			serverErr <- err
			return
		}
		serverErr <- tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}}).Handshake()
	}()
	control := &replay.Session{ID: "tcp-0", Transport: replay.TransportTCP}
	ftp := adapters.FTP{}
	message := func(direction replay.Direction, raw string) replay.Message {
		messages, err := ftp.Decode(direction, []byte(raw))
		if err != nil || len(messages) != 1 {
			t.Fatalf("decode %q: %v", raw, err)
		}
		return messages[0]
	}
	script := Script{Explicit: true, Turns: []Turn{
		{Direction: replay.ServerToClient, Message: message(replay.ServerToClient, "220 ready\r\n")},
		{Direction: replay.ClientToServer, Message: message(replay.ClientToServer, "AUTH TLS\r\n")},
		{Direction: replay.ServerToClient, Message: message(replay.ServerToClient, "234 proceed\r\n")},
	}}
	result, err := RunContext(context.Background(), Config{Control: control, Address: listener.Addr().String(), Script: script, TLSConfig: &tls.Config{RootCAs: roots, ServerName: "example.com"}, Timeout: 5 * time.Second, Verify: replay.VerifyStrict})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Completed || !result.TLS {
		t.Fatalf("result=%+v", result)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestImplicitFTPSCertificateFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	_, err = RunContext(context.Background(), Config{Control: &replay.Session{}, Address: listener.Addr().String(), Script: Script{Implicit: true}, TLSConfig: &tls.Config{ServerName: "example.com"}, Timeout: time.Second})
	if err == nil || !strings.Contains(err.Error(), "implicit TLS handshake") {
		t.Fatalf("certificate/handshake error=%v", err)
	}
}

func TestProtectedPassiveDataConnection(t *testing.T) {
	template := httptest.NewTLSServer(nil)
	certificate := template.TLS.Certificates[0]
	template.Close()
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	dataListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dataListener.Close()
	controlListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer controlListener.Close()
	dataPort := dataListener.Addr().(*net.TCPAddr).Port
	serverErr := make(chan error, 1)
	go func() {
		conn, err := controlListener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		if _, err = conn.Write([]byte("220 ready\r\n")); err != nil {
			serverErr <- err
			return
		}
		for _, exchange := range []struct{ command, reply string }{
			{"PBSZ 0", "200 PBSZ accepted\r\n"},
			{"PROT P", "200 protection accepted\r\n"},
			{"EPSV", fmt.Sprintf("229 Entering Extended Passive Mode (|||%d|)\r\n", dataPort)},
		} {
			line, readErr := reader.ReadString('\n')
			if readErr != nil || strings.TrimSpace(line) != exchange.command {
				serverErr <- fmt.Errorf("command=%q want=%q err=%v", line, exchange.command, readErr)
				return
			}
			if _, err = conn.Write([]byte(exchange.reply)); err != nil {
				serverErr <- err
				return
			}
		}
		dataConn, err := dataListener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		line, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "RETR protected.bin" {
			serverErr <- fmt.Errorf("RETR=%q err=%v", line, err)
			return
		}
		if _, err = conn.Write([]byte("150 protected data\r\n")); err != nil {
			serverErr <- err
			return
		}
		secured := tls.Server(dataConn, &tls.Config{Certificates: []tls.Certificate{certificate}})
		if err = secured.Handshake(); err == nil {
			_, err = secured.Write([]byte("protected bytes"))
		}
		closeErr := secured.Close()
		if err = errors.Join(err, closeErr); err != nil {
			serverErr <- err
			return
		}
		if _, err = conn.Write([]byte("226 done\r\n")); err != nil {
			serverErr <- err
			return
		}
		line, err = reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "QUIT" {
			serverErr <- fmt.Errorf("QUIT=%q err=%v", line, err)
			return
		}
		_, err = conn.Write([]byte("221 bye\r\n"))
		serverErr <- err
	}()

	control := &replay.Session{ID: "tcp-0", Transport: replay.TransportTCP, Client: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.10"), Port: 41000}, Server: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.20"), Port: 21}}
	turns := []struct {
		direction replay.Direction
		line      string
	}{
		{replay.ServerToClient, "220 ready\r\n"}, {replay.ClientToServer, "PBSZ 0\r\n"}, {replay.ServerToClient, "200 PBSZ accepted\r\n"},
		{replay.ClientToServer, "PROT P\r\n"}, {replay.ServerToClient, "200 protection accepted\r\n"}, {replay.ClientToServer, "EPSV\r\n"},
		{replay.ServerToClient, "229 Entering Extended Passive Mode (|||40000|)\r\n"}, {replay.ClientToServer, "RETR protected.bin\r\n"},
		{replay.ServerToClient, "150 protected data\r\n"}, {replay.ServerToClient, "226 done\r\n"}, {replay.ClientToServer, "QUIT\r\n"}, {replay.ServerToClient, "221 bye\r\n"},
	}
	ftp := adapters.FTP{}
	script := Script{ProtectData: true}
	for i, turn := range turns {
		messages, decodeErr := ftp.Decode(turn.direction, []byte(turn.line))
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		script.Turns = append(script.Turns, Turn{Direction: turn.direction, Message: messages[0], CapturedAt: replay.CapturePoint{PacketIndex: i}})
	}
	data := ftpDataSession(40000, "protected bytes")
	result, err := RunContext(context.Background(), Config{
		Control: control, Data: []*replay.Session{data}, Address: controlListener.Addr().String(), Script: script,
		TLSConfig: &tls.Config{RootCAs: roots, ServerName: "example.com"}, Timeout: 5 * time.Second, Verify: replay.VerifyStrict,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Completed || len(result.Transfers) != 1 || !result.Transfers[0].Matched {
		t.Fatalf("result=%+v", result)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestImplicitFTPSSuccessAndPipelinedReplies(t *testing.T) {
	template := httptest.NewTLSServer(nil)
	certificate := template.TLS.Certificates[0]
	template.Close()
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}})
		defer conn.Close()
		if err = conn.Handshake(); err != nil {
			serverErr <- err
			return
		}
		if _, err = conn.Write([]byte("220 ready\r\n")); err != nil {
			serverErr <- err
			return
		}
		reader := bufio.NewReader(conn)
		first, err1 := reader.ReadString('\n')
		second, err2 := reader.ReadString('\n')
		if err := errors.Join(err1, err2); err != nil || strings.TrimSpace(first) != "NOOP" || strings.TrimSpace(second) != "QUIT" {
			serverErr <- fmt.Errorf("pipelined commands=%q,%q err=%v", first, second, err)
			return
		}
		_, err = conn.Write([]byte("200 okay\r\n221 bye\r\n"))
		serverErr <- err
	}()
	ftp := adapters.FTP{}
	message := func(direction replay.Direction, raw string) replay.Message {
		messages, decodeErr := ftp.Decode(direction, []byte(raw))
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		return messages[0]
	}
	script := Script{Implicit: true, Turns: []Turn{
		{Direction: replay.ServerToClient, Message: message(replay.ServerToClient, "220 ready\r\n")},
		{Direction: replay.ClientToServer, Message: message(replay.ClientToServer, "NOOP\r\n")},
		{Direction: replay.ClientToServer, Message: message(replay.ClientToServer, "QUIT\r\n")},
		{Direction: replay.ServerToClient, Message: message(replay.ServerToClient, "200 okay\r\n")},
		{Direction: replay.ServerToClient, Message: message(replay.ServerToClient, "221 bye\r\n")},
	}}
	result, err := RunContext(context.Background(), Config{Control: &replay.Session{}, Address: listener.Addr().String(), Script: script, TLSConfig: &tls.Config{RootCAs: roots, ServerName: "example.com"}, Timeout: 5 * time.Second, Verify: replay.VerifyStrict})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Completed || !result.TLS || result.Commands != 2 || result.Replies != 3 {
		t.Fatalf("result=%+v", result)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestFTPTransferDirectionsForAllSupportedCommands(t *testing.T) {
	for _, command := range []string{"LIST", "NLST", "RETR", "STOR", "APPE", "STOU"} {
		t.Run(command, func(t *testing.T) {
			control := ftpControlSession(40000)
			data := ftpDataSession(40000, "payload")
			if command == "STOR" || command == "APPE" || command == "STOU" {
				data.Events[0].Direction = replay.ClientToServer
			}
			client, server := net.Pipe()
			peerErr := make(chan error, 1)
			if data.Events[0].Direction == replay.ClientToServer {
				go func() {
					body, err := io.ReadAll(server)
					if string(body) != "payload" {
						err = errors.Join(err, fmt.Errorf("body=%q", body))
					}
					peerErr <- errors.Join(err, server.Close())
				}()
			} else {
				go func() { _, err := server.Write([]byte("payload")); peerErr <- errors.Join(err, server.Close()) }()
			}
			result, err := runTransfer(client, control, data, command)
			closeErr := client.Close()
			if err = errors.Join(err, closeErr, <-peerErr); err != nil {
				t.Fatal(err)
			}
			if !result.Matched || result.Command != command {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestFTPSKeyLogMismatchIsActionable(t *testing.T) {
	session := &replay.Session{ID: "tcp-0", Transport: replay.TransportTCP, Events: []replay.Event{
		{PacketIndex: 0, Direction: replay.ClientToServer, Payload: append([]byte("AUTH TLS\r\n"), []byte{22, 3, 3, 0, 1, 1}...)},
		{PacketIndex: 1, Direction: replay.ServerToClient, Payload: append([]byte("234 proceed\r\n"), []byte{22, 3, 3, 0, 1, 1}...)},
	}}
	keylog, err := tlsreplay.ParseKeyLog(strings.NewReader("# no matching secrets\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildScript(session, keylog); err == nil || !strings.Contains(err.Error(), "decrypt control channel") {
		t.Fatalf("mismatch error=%v", err)
	}
}

func TestFTPTimeoutAndStrictServerFailure(t *testing.T) {
	ftp := adapters.FTP{}
	message := func(raw string) replay.Message {
		messages, err := ftp.Decode(replay.ServerToClient, []byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return messages[0]
	}
	t.Run("timeout", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			conn, acceptErr := listener.Accept()
			if acceptErr == nil {
				time.Sleep(100 * time.Millisecond)
				_ = conn.Close()
			}
		}()
		_, err = RunContext(context.Background(), Config{
			Control: &replay.Session{}, Address: listener.Addr().String(), Timeout: 20 * time.Millisecond,
			Script: Script{Turns: []Turn{{Direction: replay.ServerToClient, Message: message("220 ready\r\n")}}},
		})
		if err == nil || !strings.Contains(err.Error(), "read reply") {
			t.Fatalf("timeout error=%v", err)
		}
	})
	t.Run("strict server failure", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			conn, acceptErr := listener.Accept()
			if acceptErr == nil {
				_, _ = conn.Write([]byte("530 unavailable\r\n"))
				_ = conn.Close()
			}
		}()
		result, err := RunContext(context.Background(), Config{
			Control: &replay.Session{}, Address: listener.Addr().String(), Timeout: time.Second, Verify: replay.VerifyStrict,
			Script: Script{Turns: []Turn{{Direction: replay.ServerToClient, Message: message("220 ready\r\n")}}},
		})
		if err == nil || len(result.Differences) != 1 || result.Completed {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
}
