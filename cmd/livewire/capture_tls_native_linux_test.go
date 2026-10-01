package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/pcapio"
)

// This gate uses the real CLI, Linux AF_PACKET loopback, an independent Python
// TLS client that honors SSLKEYLOGFILE, and fresh Go TLS application peers.
// It is opt-in locally and mandatory in Linux release-toolchain CI.
func TestTLSRecordingNativeLoopback(t *testing.T) {
	if os.Getenv("LIVEWIRE_NATIVE_CAPTURE_TEST") != "1" {
		t.Skip("requires approved local raw loopback capture")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	bin := buildBinary(t)
	client := filepath.Join(t.TempDir(), "record_client.py")
	const script = `import socket, ssl, sys
ctx = ssl.create_default_context(cafile=sys.argv[2])
version = ssl.TLSVersion.TLSv1_2 if sys.argv[3] == "12" else ssl.TLSVersion.TLSv1_3
ctx.minimum_version = ctx.maximum_version = version
request, expected = bytes.fromhex(sys.argv[4]), bytes.fromhex(sys.argv[5])
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5) as raw:
    with ctx.wrap_socket(raw, server_hostname="localhost") as conn:
        conn.sendall(request)
        response = b""
        while len(response) < len(expected):
            chunk = conn.recv(len(expected)-len(response))
            if not chunk: raise RuntimeError("incomplete application response")
            response += chunk
        if response != expected: raise RuntimeError("application response mismatch")
`
	if err := os.WriteFile(client, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	dns := []byte{0, 11, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1}
	dnsResponse := append([]byte(nil), dns...)
	dnsResponse[2], dnsResponse[3] = 0x81, 0x80
	frame := func(data []byte) []byte {
		return append(binary.BigEndian.AppendUint16(nil, uint16(len(data))), data...)
	}
	dnpRequest := (dissect.DNP3{Control: 0xc4, Source: 1, Dest: 4, UserData: []byte{0xc1, 0xc1, 1, 30, 1, 6}}).Encode()
	dnpResponse := (dissect.DNP3{Control: 0x44, Source: 4, Dest: 1, UserData: []byte{0xc1, 0xc1, 0x81, 0, 0, 30, 1, 0, 0, 0, 1, 42, 0, 0, 0}}).Encode()
	cases := []struct {
		name, adapter     string
		request, response []byte
	}{
		{"http", "http/1", []byte("GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")},
		{"modbus", "modbus", []byte{0, 11, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1}, []byte{0, 11, 0, 0, 0, 5, 1, 3, 2, 0, 17}},
		{"dns", "dns", frame(dns), frame(dnsResponse)},
		{"mqtt311", "mqtt", []byte{0x10, 15, 0, 4, 'M', 'Q', 'T', 'T', 4, 2, 0, 60, 0, 3, 'l', 'a', 'b'}, []byte{0x20, 2, 0, 0}},
		{"mqtt5", "mqtt", []byte{0x10, 16, 0, 4, 'M', 'Q', 'T', 'T', 5, 2, 0, 60, 0, 0, 3, 'l', 'a', 'b'}, []byte{0x20, 3, 0, 0, 0}},
		{"dnp3", "dnp3", dnpRequest, dnpResponse},
	}
	for _, version := range []string{"12", "13"} {
		for _, tc := range cases {
			t.Run(tc.name+"/TLS1"+version[1:], func(t *testing.T) {
				cert, ca := testTLSCertificate(t)
				dir := t.TempDir()
				caPath := filepath.Join(dir, "ca.pem")
				if err := os.WriteFile(caPath, ca, 0600); err != nil {
					t.Fatal(err)
				}
				listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				done := make(chan error, 2)
				go func() {
					for i := 0; i < 2; i++ {
						conn, err := listener.Accept()
						if err != nil {
							done <- err
							return
						}
						_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
						got := make([]byte, len(tc.request))
						_, err = io.ReadFull(conn, got)
						reply := append([]byte(nil), tc.response...)
						if tc.name == "modbus" {
							copy(reply[:2], got[:2])
							copy(got[:2], tc.request[:2])
						}
						if tc.name == "dns" {
							copy(reply[2:4], got[2:4])
							copy(got[2:4], tc.request[2:4])
						}
						if err == nil && !bytes.Equal(got, tc.request) {
							err = fmt.Errorf("fresh application request differs")
						}
						if err == nil {
							_, err = conn.Write(reply)
						}
						_ = conn.Close()
						done <- err
						if err != nil {
							return
						}
					}
				}()
				capture := filepath.Join(dir, "recording.pcapng")
				port := fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)
				out, err := runBinary(t, bin, "capture", "-i", "lo", "-promisc=false", "-o", capture, "-tls", "-duration", "10s", "--", python, client, port, caPath, version, hex.EncodeToString(tc.request), hex.EncodeToString(tc.response))
				if err != nil {
					t.Fatalf("native recording: %v\n%s", err, out)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				loaded, err := pcapio.LoadFile(capture, pcapio.DefaultLimits())
				if err != nil || len(loaded.TLSKeyLog()) == 0 {
					t.Fatalf("native recording missing embedded secrets: %v", err)
				}
				reportPath := filepath.Join(dir, "replay.json")
				out, err = runBinary(t, bin, "live", capture, "-t", listener.Addr().String(), "-server-name", "localhost", "-ca", caPath, "-strict", "-strict-exit", "-report", reportPath)
				if err != nil {
					t.Fatalf("native replay: %v\n%s", err, out)
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(6 * time.Second):
					t.Fatal("fresh peer did not finish")
				}
				data, err := os.ReadFile(reportPath)
				if err != nil {
					t.Fatal(err)
				}
				var report reterminationReport
				if err := json.Unmarshal(data, &report); err != nil {
					t.Fatal(err)
				}
				o := report.Outcome
				if !o.ApplicationReplayCompleted || !o.Verified || !o.Matched || o.TLSSecretsSource != "embedded" || o.Requests != 1 || o.Compared != 1 {
					t.Fatalf("native application replay failed: %+v", o)
				}
			})
		}
	}
}
