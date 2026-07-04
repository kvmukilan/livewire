package tlsreplay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// selfSigned builds an in-memory certificate for a loopback TLS server.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "livewire-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: mustParse(t, der)}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestReTerminateLoopback exercises the re-termination path end to end: fresh
// handshake, replay the script, read server responses back byte-accurately.
func TestReTerminateLoopback(t *testing.T) {
	cert := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Stand-in device: upper-cases each request.
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 512)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				c.Write([]byte(strings.ToUpper(string(buf[:n]))))
			}
			if err != nil {
				return
			}
		}
	}()

	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	script := []AppMessage{
		{Role: FromClient, Data: []byte("read-coils")},
		{Role: FromServer, Data: []byte("READ-COILS")},
		{Role: FromClient, Data: []byte("write-reg")},
		{Role: FromServer, Data: []byte("WRITE-REG")},
	}
	res, err := ReTerminate(ReTermConfig{
		Address:   ln.Addr().String(),
		TLSConfig: &tls.Config{RootCAs: roots, ServerName: "localhost"},
		Script:    script,
		Timeout:   5 * time.Second,
		Verify:    true,
	})
	if err != nil {
		t.Fatalf("ReTerminate: %v", err)
	}
	if res.Mismatches != 0 {
		t.Fatalf("expected byte-accurate responses, got %d mismatches: %q", res.Mismatches, res.Responses)
	}
	if !res.HandshakeState.HandshakeComplete {
		t.Fatal("fresh handshake did not complete")
	}
}

func TestReTerminateRequiresConfig(t *testing.T) {
	if _, err := ReTerminate(ReTermConfig{Address: "127.0.0.1:1"}); err == nil {
		t.Fatal("expected error when TLSConfig is nil")
	}
}

func TestParseKeyLog(t *testing.T) {
	const cr = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	log := "# comment\n" +
		"CLIENT_RANDOM " + cr + " 0011223344556677\n" +
		"SERVER_TRAFFIC_SECRET_0 " + cr + " 8899aabb\n" +
		"garbage line\n"
	kl, err := ParseKeyLog(strings.NewReader(log))
	if err != nil {
		t.Fatal(err)
	}
	if kl.Count() != 1 || !kl.Has(cr) {
		t.Fatalf("expected 1 session for %s, count=%d", cr, kl.Count())
	}
	if s, ok := kl.Secret(cr, "CLIENT_RANDOM"); !ok || len(s) != 8 {
		t.Fatalf("CLIENT_RANDOM secret wrong: ok=%v len=%d", ok, len(s))
	}
	if !kl.Has(strings.ToUpper(cr)) {
		t.Fatal("lookup should be case-insensitive on client random")
	}
}
