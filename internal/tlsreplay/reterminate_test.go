package tlsreplay

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/replay"
)

type lengthAdapter struct{}

func (lengthAdapter) Name() string                            { return "length-test" }
func (lengthAdapter) Detect(replay.Session) replay.Confidence { return 100 }
func (lengthAdapter) Decode(_ replay.Direction, b []byte) ([]replay.Message, error) {
	if len(b) < 1 || len(b) != int(b[0])+1 {
		return nil, net.UnknownNetworkError("incomplete length frame")
	}
	return []replay.Message{{Kind: "length", Raw: append([]byte(nil), b...)}}, nil
}
func (lengthAdapter) Prepare(_ replay.Direction, m replay.Message, _ *replay.RuntimeState) ([]byte, error) {
	return m.Raw, nil
}
func (lengthAdapter) Correlate(_, _ replay.Message, _ *replay.RuntimeState) replay.Match {
	return replay.Match{Matched: true}
}
func (lengthAdapter) Compare(w, g replay.Message, _ replay.VerifyMode) []replay.Difference {
	if string(w.Raw) == string(g.Raw) {
		return nil
	}
	return []replay.Difference{{Field: "body", Structural: true}}
}

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

func TestReTerminateContextCancelsBlockedResponse(t *testing.T) {
	cert := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1)
		_, _ = io.ReadFull(conn, buf)
		buf = make([]byte, 1)
		_, _ = conn.Read(buf) // wait for the cancelled client to close
	}()
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = ReTerminateContext(ctx, ReTermConfig{
		Address: ln.Addr().String(), TLSConfig: &tls.Config{RootCAs: roots, ServerName: "localhost"},
		Script:  []AppMessage{{Role: FromClient, Data: []byte("x")}, {Role: FromServer, Data: []byte("y")}},
		Timeout: 5 * time.Second, Verify: true,
	})
	if err == nil || !strings.Contains(err.Error(), context.DeadlineExceeded.Error()) {
		t.Fatalf("expected context deadline, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("cancellation took %s", elapsed)
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("cancelled TLS connection was not released")
	}
}

func TestReTerminateUsesAdapterForDynamicResponseLength(t *testing.T) {
	cert := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 2)
		_, _ = io.ReadFull(c, buf)
		_, _ = c.Write([]byte{6, 'l', 'o', 'n', 'g', 'e', 'r'})
	}()
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	res, err := ReTerminate(ReTermConfig{
		Address: ln.Addr().String(), TLSConfig: &tls.Config{RootCAs: roots, ServerName: "localhost"},
		Script:  []AppMessage{{Role: FromClient, Data: []byte{1, 'x'}}, {Role: FromServer, Data: []byte{3, 'o', 'l', 'd'}}},
		Timeout: time.Second, Adapter: lengthAdapter{}, VerifyMode: replay.VerifyLenient,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Responses) != 1 || string(res.Responses[0]) != "\x06longer" || res.Mismatches != 1 {
		t.Fatalf("dynamic response result=%+v", res)
	}
}

func TestReTerminateUsesHTTPHeadExchangeContext(t *testing.T) {
	cert := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	request := []byte("HEAD /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n")
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		got := make([]byte, len(request))
		_, _ = io.ReadFull(c, got)
		_, _ = c.Write(response)
		time.Sleep(200 * time.Millisecond)
	}()
	a := adapters.HTTP{}
	peers, err := a.Decode(replay.ClientToServer, request)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := a.DecodeExchange(replay.ServerToClient, response, peers)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	started := time.Now()
	res, err := ReTerminate(ReTermConfig{
		Address: ln.Addr().String(), TLSConfig: &tls.Config{RootCAs: roots, ServerName: "localhost"},
		Script: []AppMessage{
			{Role: FromClient, Data: request},
			{Role: FromServer, Data: response, Expected: expected, Peers: peers},
		},
		Timeout: time.Second, Adapter: a, VerifyMode: replay.VerifyStrict,
	})
	if err != nil || res.Mismatches != 0 {
		t.Fatalf("HEAD retermination result=%+v err=%v", res, err)
	}
	if time.Since(started) >= 180*time.Millisecond {
		t.Fatal("HEAD response incorrectly waited for a Content-Length body or connection close")
	}
}

func TestReTerminateReadsPipelinedHTTPResponsesAsOneTurn(t *testing.T) {
	cert := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	requests := []byte("GET /one HTTP/1.1\r\nHost: localhost\r\n\r\nGET /two HTTP/1.1\r\nHost: localhost\r\n\r\n")
	responses := []byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\naHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb")
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer c.Close()
		got := make([]byte, len(requests))
		_, _ = io.ReadFull(c, got)
		_, _ = c.Write(responses)
	}()
	a := adapters.HTTP{}
	peers, err := a.Decode(replay.ClientToServer, requests)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := a.DecodeExchange(replay.ServerToClient, responses, peers)
	if err != nil || len(expected) != 2 {
		t.Fatalf("expected responses=%d err=%v", len(expected), err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	result, err := ReTerminate(ReTermConfig{
		Address: ln.Addr().String(), TLSConfig: &tls.Config{RootCAs: roots, ServerName: "localhost"},
		Script: []AppMessage{
			{Role: FromClient, Data: requests[:len(requests)/2]},
			{Role: FromClient, Data: requests[len(requests)/2:]},
			{Role: FromServer, Data: responses, Expected: expected, Peers: peers},
		},
		Timeout: time.Second, Adapter: a, VerifyMode: replay.VerifyStrict,
	})
	if err != nil || result.Mismatches != 0 || len(result.Responses) != 1 || !bytes.Equal(result.Responses[0], responses) {
		t.Fatalf("pipelined retermination result=%+v err=%v", result, err)
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
