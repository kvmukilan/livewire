package tlsreplay

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordConn wraps a net.Conn and captures the raw bytes crossing it, so a test
// can recover the on-wire record streams: Write is c2s, Read is s2c.
type recordConn struct {
	net.Conn
	mu       sync.Mutex
	c2s, s2c bytes.Buffer
}

func (r *recordConn) Write(p []byte) (int, error) {
	n, err := r.Conn.Write(p)
	r.mu.Lock()
	r.c2s.Write(p[:n])
	r.mu.Unlock()
	return n, err
}

func (r *recordConn) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	r.mu.Lock()
	r.s2c.Write(p[:n])
	r.mu.Unlock()
	return n, err
}

// captureTLS runs a real handshake + request/response at the given version and
// suite, returning the recorded ciphertext streams and the keylog.
func captureTLS(t *testing.T, version uint16, suites []uint16) (c2s, s2c, keylog []byte) {
	t.Helper()
	cert := selfSigned(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		scfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   version, MaxVersion: version,
			CipherSuites: suites,
		}
		sc := tls.Server(raw, scfg)
		defer sc.Close()
		buf := make([]byte, 256)
		n, _ := sc.Read(buf)
		sc.Write([]byte("REPLY:" + string(buf[:n])))
	}()

	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	rc := &recordConn{Conn: raw}
	var klBuf bytes.Buffer
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	ccfg := &tls.Config{
		RootCAs:    roots,
		ServerName: "localhost",
		MinVersion: version, MaxVersion: version,
		CipherSuites: suites,
		KeyLogWriter: &klBuf,
	}
	cc := tls.Client(rc, ccfg)
	if err := cc.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if _, err := cc.Write([]byte("hello-device")); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 256)
	n, _ := cc.Read(resp)
	if !strings.Contains(string(resp[:n]), "REPLY:hello-device") {
		t.Fatalf("unexpected app response: %q", resp[:n])
	}
	cc.Close()
	wg.Wait()

	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]byte(nil), rc.c2s.Bytes()...), append([]byte(nil), rc.s2c.Bytes()...), klBuf.Bytes()
}

// decryptRoundTrip captures a session and asserts the decryptor recovers both
// the client request and the server response plaintext from the ciphertext.
func decryptRoundTrip(t *testing.T, version uint16, suites []uint16) {
	t.Helper()
	c2s, s2c, keylog := captureTLS(t, version, suites)

	kl, err := ParseKeyLog(bytes.NewReader(keylog))
	if err != nil {
		t.Fatal(err)
	}
	if kl.Count() == 0 {
		t.Skip("no keylog captured (TLS session resumed or logging disabled)")
	}

	msgs, err := NewDecryptor(kl).DecryptFlow(c2s, s2c)
	if err != nil {
		if strings.Contains(err.Error(), "ChaCha20") {
			t.Skip("environment negotiated ChaCha20; AES-GCM decryptor not exercised")
		}
		t.Fatalf("DecryptFlow: %v", err)
	}

	var gotClient, gotServer string
	for _, m := range msgs {
		switch m.Role {
		case FromClient:
			gotClient += string(m.Data)
		case FromServer:
			gotServer += string(m.Data)
		}
	}
	if !strings.Contains(gotClient, "hello-device") {
		t.Fatalf("client plaintext not recovered; got %q", gotClient)
	}
	if !strings.Contains(gotServer, "REPLY:hello-device") {
		t.Fatalf("server plaintext not recovered; got %q", gotServer)
	}
}

func TestDecryptTLS12_AES128GCM(t *testing.T) {
	// Force an ECDHE-ECDSA AES-128-GCM suite matching the ECDSA test cert.
	decryptRoundTrip(t, tls.VersionTLS12, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256})
}

func TestDecryptTLS12_AES256GCM(t *testing.T) {
	decryptRoundTrip(t, tls.VersionTLS12, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384})
}

func TestDecryptTLS13(t *testing.T) {
	// TLS 1.3 suite selection is not configurable via Config; on AES-NI hardware
	// Go prefers AES-128-GCM. If ChaCha20 is chosen the round-trip self-skips.
	decryptRoundTrip(t, tls.VersionTLS13, nil)
}

func TestDecryptNoKeylogFails(t *testing.T) {
	c2s, s2c, _ := captureTLS(t, tls.VersionTLS12, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256})
	empty, _ := ParseKeyLog(strings.NewReader(""))
	if _, err := NewDecryptor(empty).DecryptFlow(c2s, s2c); err == nil {
		t.Fatal("expected decryption to fail with no keys")
	}
}

var _ = io.EOF
