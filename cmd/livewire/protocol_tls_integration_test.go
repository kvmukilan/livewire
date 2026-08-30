package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

type tlsWireEvent struct {
	client bool
	data   []byte
}

type tlsWireTimeline struct {
	mu     sync.Mutex
	events []tlsWireEvent
}

type tlsTimelineConn struct {
	net.Conn
	timeline *tlsWireTimeline
	client   bool
}

func (c *tlsTimelineConn) Write(data []byte) (int, error) {
	// net.Pipe writes are all-or-nothing. Record before the blocking write so
	// the cross-direction order mirrors when each TLS flight was emitted.
	c.timeline.mu.Lock()
	c.timeline.events = append(c.timeline.events, tlsWireEvent{client: c.client, data: append([]byte(nil), data...)})
	c.timeline.mu.Unlock()
	return c.Conn.Write(data)
}

func testTLSCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func captureHTTPOverTLS(t *testing.T, cert tls.Certificate) ([]tlsWireEvent, []byte) {
	t.Helper()
	clientRaw, serverRaw := net.Pipe()
	timeline := &tlsWireTimeline{}
	var keylog bytes.Buffer
	server := tls.Server(&tlsTimelineConn{Conn: serverRaw, timeline: timeline}, &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	})
	client := tls.Client(&tlsTimelineConn{Conn: clientRaw, timeline: timeline, client: true}, &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- capture fixture only; the replay itself verifies the peer.
		MinVersion:         tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, KeyLogWriter: &keylog,
	})
	request := []byte("GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	serverDone := make(chan error, 1)
	go func() {
		defer serverRaw.Close()
		if err := server.Handshake(); err != nil {
			serverDone <- err
			return
		}
		got := make([]byte, len(request))
		if _, err := io.ReadFull(server, got); err != nil {
			serverDone <- err
			return
		}
		if !bytes.Equal(got, request) {
			serverDone <- io.ErrUnexpectedEOF
			return
		}
		_, err := server.Write(response)
		serverDone <- err
	}()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(response))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, response) {
		t.Fatalf("captured TLS response mismatch")
	}
	_ = clientRaw.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	timeline.mu.Lock()
	defer timeline.mu.Unlock()
	return append([]tlsWireEvent(nil), timeline.events...), append([]byte(nil), keylog.Bytes()...)
}

func writeTLSFixture(t *testing.T, dir string, events []tlsWireEvent, keylog, ca []byte) (capture, keylogPath, caPath string) {
	t.Helper()
	capture = filepath.Join(dir, "tls-http.pcap")
	keylogPath = filepath.Join(dir, "tls-http.keylog")
	caPath = filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(keylogPath, keylog, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(capture)
	if err != nil {
		t.Fatal(err)
	}
	w, err := pcapio.NewWriter(f, wire.LinkEthernet, true)
	if err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	frames := [][]byte{
		ethTCP("192.0.2.10", "192.0.2.20", 41000, 443, 100, 0, wire.FlagSYN, nil),
		ethTCP("192.0.2.20", "192.0.2.10", 443, 41000, 900, 101, wire.FlagSYN|wire.FlagACK, nil),
		ethTCP("192.0.2.10", "192.0.2.20", 41000, 443, 101, 901, wire.FlagACK, nil),
	}
	clientSeq, serverSeq := uint32(101), uint32(901)
	for _, event := range events {
		if event.client {
			frames = append(frames, ethTCP("192.0.2.10", "192.0.2.20", 41000, 443, clientSeq, serverSeq, wire.FlagACK|wire.FlagPSH, event.data))
			clientSeq += uint32(len(event.data))
		} else {
			frames = append(frames, ethTCP("192.0.2.20", "192.0.2.10", 443, 41000, serverSeq, clientSeq, wire.FlagACK|wire.FlagPSH, event.data))
			serverSeq += uint32(len(event.data))
		}
	}
	base := time.Unix(1_700_000_000, 0)
	for i, frame := range frames {
		if err := w.Write(&pcapio.Record{Time: base.Add(time.Duration(i) * time.Millisecond), Data: frame}); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return capture, keylogPath, caPath
}

func TestUnifiedReproduceReterminatesVerifiedTLS(t *testing.T) {
	cert, ca := testTLSCertificate(t)
	events, keylog := captureHTTPOverTLS(t, cert)
	capture, keylogPath, caPath := writeTLSFixture(t, t.TempDir(), events, keylog, ca)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		request := make([]byte, len("GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
		if _, err := io.ReadFull(conn, request); err != nil {
			serverDone <- err
			return
		}
		_, err = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
		serverDone <- err
	}()

	report := filepath.Join(t.TempDir(), "tls.report.json")
	err = cmdReproduce([]string{capture, "-keylog", keylogPath, "-t", listener.Addr().String(), "-server-name", "localhost", "-ca", caPath, "-strict", "-timeout", "2s", "-report", report})
	if err != nil {
		t.Fatalf("unified TLS reproduce: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range [][]byte{[]byte(`"kind": "tls"`), []byte(`"completed": true`), []byte(`"peerIdentityChecked": true`)} {
		if !bytes.Contains(body, want) {
			t.Errorf("TLS report missing %s:\n%s", want, body)
		}
	}
	if bytes.Contains(body, []byte("CLIENT_RANDOM")) {
		t.Fatalf("TLS key-log material leaked into report:\n%s", body)
	}
}

func TestUnifiedTLSIterationsReportActualIntermittence(t *testing.T) {
	cert, ca := testTLSCertificate(t)
	events, keylog := captureHTTPOverTLS(t, cert)
	capture, keylogPath, caPath := writeTLSFixture(t, t.TempDir(), events, keylog, ca)

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		for attempt := 0; attempt < 2; attempt++ {
			conn, err := listener.Accept()
			if err != nil {
				serverDone <- err
				return
			}
			request := make([]byte, len("GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
			if _, err := io.ReadFull(conn, request); err != nil {
				_ = conn.Close()
				serverDone <- err
				return
			}
			status := "200 OK"
			if attempt == 1 {
				status = "500 Internal Server Error"
			}
			_, writeErr := conn.Write([]byte("HTTP/1.1 " + status + "\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
			closeErr := conn.Close()
			if err := errors.Join(writeErr, closeErr); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()

	reportBase := filepath.Join(t.TempDir(), "tls.report.json")
	bin := buildBinary(t)
	out, runErr := runBinary(t, bin, "reproduce", capture,
		"-keylog", keylogPath, "-t", listener.Addr().String(), "-server-name", "localhost", "-ca", caPath,
		"-timeout", "2s", "-n", "2", "-gap", "0s", "-report", reportBase)
	if runErr != nil {
		t.Fatalf("repeated unified TLS replay: %v\n%s", runErr, out)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"OVERALL: INTERMITTENT", "same as the recording", "different"} {
		if !strings.Contains(out, want) {
			t.Errorf("secure iteration summary missing %q:\n%s", want, out)
		}
	}
	for attempt := 1; attempt <= 2; attempt++ {
		path := attemptReportPath(reportBase, attempt, 2)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("attempt report %d missing: %v", attempt, err)
		}
	}
}
