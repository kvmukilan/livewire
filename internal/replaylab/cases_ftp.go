package replaylab

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

func init() {
	for _, name := range []string{"ftp", "ftps-explicit", "ftps-implicit"} {
		Register(Case{Name: name, Setup: func(ctx context.Context, dir string) (*Fixture, error) { return setupFTP(ctx, dir, name) }})
	}
}

var ftpLabData = []byte("livewire software-lab transfer\x00\x01\xff\n")

func setupFTP(ctx context.Context, dir, mode string) (_ *Fixture, retErr error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	cert, ca, err := LabCertificate()
	if err != nil {
		return nil, err
	}
	secured := mode != "ftp"
	server, err := ServeTCP(ctx, func(conn net.Conn, stats *Stats) error { return serveFTP(conn, stats, mode, cert) })
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			_ = server.Close()
		}
	}()
	control := []Exchange{
		{Server: []byte("220 ready\r\n"), At: 100 * time.Millisecond},
		{Client: []byte("USER capture\r\n"), Server: []byte("331 password\r\n"), At: time.Second},
		{Client: []byte("PASS capture-only\r\n"), Server: []byte("230 logged in\r\n"), At: 2 * time.Second},
	}
	if secured {
		control = append(control, Exchange{Client: []byte("PBSZ 0\r\n"), Server: []byte("200 buffer accepted\r\n"), At: 3 * time.Second}, Exchange{Client: []byte("PROT P\r\n"), Server: []byte("200 protection accepted\r\n"), At: 4 * time.Second})
	}
	var lanes []TCPConversation
	var keys []byte
	for i, verb := range []string{"RETR", "STOR"} {
		base := time.Duration(i) * 8 * time.Second
		port := uint16(45000 + i)
		control = append(control,
			Exchange{Client: []byte("EPSV\r\n"), Server: []byte(fmt.Sprintf("229 Entering Extended Passive Mode (|||%d|)\r\n", port)), At: base + 6*time.Second},
			Exchange{Client: []byte(verb + " fixture.bin\r\n"), Server: []byte("150 opening data\r\n"), At: base + 8*time.Second},
			Exchange{Server: []byte("226 transfer complete\r\n"), At: base + 10*time.Second},
		)
		data := []Exchange{{Server: ftpLabData, At: 1500 * time.Millisecond}}
		if verb == "STOR" {
			data[0].Client, data[0].Server = ftpLabData, nil
		}
		if secured {
			var log []byte
			data, log, err = EncryptConversation(cert, data)
			if err != nil {
				return nil, err
			}
			keys = append(keys, log...)
		}
		lanes = append(lanes, TCPConversation{ServerPort: port, ClientPort: uint16(42000 + i), Start: base + 7*time.Second, Exchanges: data})
	}
	control = append(control, Exchange{Client: []byte("QUIT\r\n"), Server: []byte("221 bye\r\n"), At: 20 * time.Second})
	controlPort := uint16(21)
	if secured {
		if mode == "ftps-explicit" {
			control = control[1:]
		} // banner/AUTH precede TLS
		var log []byte
		control, log, err = EncryptConversation(cert, control)
		if err != nil {
			return nil, err
		}
		keys = append(keys, log...)
		if mode == "ftps-explicit" {
			for i := range control {
				control[i].At += 500 * time.Millisecond
			}
			control = append([]Exchange{{Server: []byte("220 ready\r\n"), At: 10 * time.Millisecond}, {Client: []byte("AUTH TLS\r\n"), Server: []byte("234 proceed\r\n"), At: 100 * time.Millisecond}}, control...)
			for i := range lanes {
				lanes[i].Start += 500 * time.Millisecond
			}
		} else {
			controlPort = 990
		}
	}
	capture := filepath.Join(dir, "fixture.pcap")
	lanes = append([]TCPConversation{{ServerPort: controlPort, ClientPort: 41000, Exchanges: control}}, lanes...)
	if err = WriteTCPConversations(capture, lanes); err != nil {
		return nil, err
	}
	// These deliberately different credentials are generated lab inputs, never
	// user credentials. The server checks that captured credentials were replaced.
	args := []string{"-t", server.Address(), "-set", "ftp.user=lab", "-set", "ftp.password=lab-only", "-timeout", "10s"}
	if secured {
		keyPath, caPath := filepath.Join(dir, "fixture.keys"), filepath.Join(dir, "fixture-ca.pem")
		if err = os.WriteFile(keyPath, keys, 0600); err != nil {
			return nil, err
		}
		if err = os.WriteFile(caPath, ca, 0600); err != nil {
			return nil, err
		}
		args = append(args, "-keylog", keyPath, "-ca", caPath, "-server-name", "localhost")
	}
	return &Fixture{Capture: capture, Args: args, Snapshot: server.Stats.Snapshot, Events: server.Stats.Events, Close: server.Close}, nil
}

func serveFTP(raw net.Conn, stats *Stats, mode string, cert tls.Certificate) error {
	var conn net.Conn = raw
	config := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if mode == "ftps-implicit" {
		t := tls.Server(conn, config)
		if err := t.Handshake(); err != nil {
			return err
		}
		conn = t
	}
	reader := bufio.NewReader(conn)
	write := func(line string) error {
		_, err := io.WriteString(conn, line)
		if err == nil {
			stats.Response()
		}
		return err
	}
	read := func(want string) error {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if line != want+"\r\n" {
			return fmt.Errorf("FTP command did not match independent synthetic transcript")
		}
		stats.Request()
		return nil
	}
	if err := write("220 ready\r\n"); err != nil {
		return err
	}
	if mode == "ftps-explicit" {
		if err := read("AUTH TLS"); err != nil {
			return err
		}
		if err := write("234 proceed\r\n"); err != nil {
			return err
		}
		t := tls.Server(conn, config)
		if err := t.Handshake(); err != nil {
			return err
		}
		conn = t
		reader = bufio.NewReader(conn)
	}
	for _, step := range [][2]string{{"USER lab", "331 password\r\n"}, {"PASS lab-only", "230 logged in\r\n"}} {
		if err := read(step[0]); err != nil {
			return err
		}
		if err := write(step[1]); err != nil {
			return err
		}
	}
	if mode != "ftp" {
		for _, step := range [][2]string{{"PBSZ 0", "200 buffer accepted\r\n"}, {"PROT P", "200 protection accepted\r\n"}} {
			if err := read(step[0]); err != nil {
				return err
			}
			if err := write(step[1]); err != nil {
				return err
			}
		}
	}
	for _, verb := range []string{"RETR", "STOR"} {
		if err := read("EPSV"); err != nil {
			return err
		}
		if err := ftpTransferPeer(stats, config, mode != "ftp", verb, read, write); err != nil {
			return err
		}
	}
	if err := read("QUIT"); err != nil {
		return err
	}
	return write("221 bye\r\n")
}

func ftpTransferPeer(stats *Stats, config *tls.Config, secure bool, verb string, read func(string) error, write func(string) error) (retErr error) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = listener.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if err = write(fmt.Sprintf("229 Entering Extended Passive Mode (|||%d|)\r\n", listener.Addr().(*net.TCPAddr).Port)); err != nil {
		return err
	}
	raw, err := listener.AcceptTCP()
	if err != nil {
		return err
	}
	defer raw.Close()
	stats.active.Add(1)
	defer stats.active.Add(-1)
	if err = raw.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if err = read(verb + " fixture.bin"); err != nil {
		return err
	}
	if err = write("150 opening data\r\n"); err != nil {
		return err
	}
	var conn net.Conn = raw
	if secure {
		t := tls.Server(raw, config)
		if err = t.Handshake(); err != nil {
			return err
		}
		conn = t
	}
	if verb == "RETR" {
		_, err = conn.Write(ftpLabData)
	} else {
		var got []byte
		got, err = io.ReadAll(io.LimitReader(conn, 1024))
		if err == nil && !bytes.Equal(got, ftpLabData) {
			err = fmt.Errorf("FTP upload bytes differ: captured ciphertext or stale data was sent")
		}
	}
	err = errors.Join(err, conn.Close())
	if err != nil {
		return err
	}
	stats.Note("FTP %s transfer verified; protected=%v", verb, secure)
	return write("226 transfer complete\r\n")
}
