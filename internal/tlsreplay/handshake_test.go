package tlsreplay

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"testing"
	"time"
)

type handshakeReadRecorder struct {
	net.Conn
	read bytes.Buffer
}

func (c *handshakeReadRecorder) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	_, _ = c.read.Write(p[:n])
	return n, err
}

func TestHandshakeContextFreshVerifiedSessionWithoutApplication(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			cert := selfSigned(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			type observation struct {
				hello *ClientHelloMetadata
				state tls.ConnectionState
				err   error
			}
			observed := make(chan observation, 2)
			go func() {
				for range 2 {
					raw, err := listener.Accept()
					if err != nil {
						observed <- observation{err: err}
						return
					}
					_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
					recorder := &handshakeReadRecorder{Conn: raw}
					// #nosec G402 -- test deliberately covers a TLS 1.2-only peer too.
					peer := tls.Server(recorder, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version, NextProtos: []string{"h2", "http/1.1"}})
					err = peer.Handshake()
					state := peer.ConnectionState()
					if err == nil {
						var payload [1]byte
						n, readErr := peer.Read(payload[:])
						if n != 0 || !errors.Is(readErr, io.EOF) {
							err = fmt.Errorf("application bytes=%d read=%v", n, readErr)
						}
					}
					hello, parseErr := ParseClientHello(recorder.read.Bytes())
					err = errors.Join(err, parseErr)
					_ = peer.Close()
					observed <- observation{hello, state, err}
				}
			}()
			roots := x509.NewCertPool()
			roots.AddCert(cert.Leaf)
			cache := tls.NewLRUClientSessionCache(2)
			// #nosec G402 -- test deliberately covers a TLS 1.2-only peer too.
			config := &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: version, MaxVersion: version, NextProtos: []string{"h2", "http/1.1"}, ClientSessionCache: cache}
			var previousRandom string
			for range 2 {
				result, err := HandshakeContext(context.Background(), listener.Addr().String(), config, 3*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				if !result.State.HandshakeComplete || len(result.State.VerifiedChains) == 0 || result.State.DidResume || result.State.Version != version || result.State.NegotiatedProtocol != "h2" || result.Cleanup != "complete" {
					t.Fatalf("fresh verified handshake evidence incomplete: %+v", result)
				}
				select {
				case peer := <-observed:
					if peer.err != nil {
						t.Fatal(peer.err)
					}
					if !peer.state.HandshakeComplete || peer.state.DidResume || !reflect.DeepEqual(peer.hello, result.ClientHello) {
						t.Fatal("client evidence does not match independently received ClientHello")
					}
				case <-time.After(4 * time.Second):
					t.Fatal("peer did not observe connection closure")
				}
				if result.ClientHello.RandomSHA256 == previousRandom {
					t.Fatal("fresh connection reused ClientHello randomness")
				}
				previousRandom = result.ClientHello.RandomSHA256
			}
			if config.ClientSessionCache != cache || config.SessionTicketsDisabled || !reflect.DeepEqual(config.NextProtos, []string{"h2", "http/1.1"}) {
				t.Fatal("handshake mutated caller configuration")
			}
		})
	}
}

func TestHandshakeContextRejectsUntrustedIdentityAndCloses(t *testing.T) {
	for _, name := range []string{"untrusted", "wrong-name"} {
		t.Run(name, func(t *testing.T) {
			cert := selfSigned(t)
			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			peerDone := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					peerDone <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				peerDone <- conn.(*tls.Conn).Handshake()
			}()
			roots := x509.NewCertPool()
			config := &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}
			if name == "wrong-name" {
				roots.AddCert(cert.Leaf)
				config.ServerName = "other.example"
			}
			result, err := HandshakeContext(context.Background(), listener.Addr().String(), config, 3*time.Second)
			var verification *tls.CertificateVerificationError
			if !errors.As(err, &verification) || result == nil || result.State.HandshakeComplete || result.Cleanup != "complete" {
				t.Fatalf("bad certificate accepted or not cleaned up: result=%+v err=%v", result, err)
			}
			select {
			case err := <-peerDone:
				if err == nil {
					t.Fatal("peer accepted untrusted handshake")
				}
			case <-time.After(4 * time.Second):
				t.Fatal("failed handshake left peer connected")
			}
		})
	}
}

func TestHandshakeContextCancellationAndDeadlineCloseBlockedPeer(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			peerDone := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					peerDone <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				if mode == "cancel" {
					cancel()
				}
				_, err = io.Copy(io.Discard, conn)
				peerDone <- err
			}()
			budget, want := 2*time.Second, error(context.Canceled)
			if mode == "deadline" {
				budget, want = 75*time.Millisecond, context.DeadlineExceeded
			}
			started := time.Now()
			result, err := HandshakeContext(ctx, listener.Addr().String(), &tls.Config{ServerName: "localhost", MinVersion: tls.VersionTLS12}, budget)
			if !errors.Is(err, want) || result != nil && result.State.HandshakeComplete {
				t.Fatalf("cancellation result=%+v err=%v", result, err)
			}
			if time.Since(started) > time.Second {
				t.Fatal("cancellation failed to interrupt handshake")
			}
			select {
			case err := <-peerDone:
				if err != nil {
					t.Fatalf("peer connection not cleanly released: %v", err)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("cancelled handshake left peer connected")
			}
		})
	}
}

func TestHandshakeContextRejectsInvalidInputsBeforeDial(t *testing.T) {
	for _, test := range []struct {
		config  *tls.Config
		timeout time.Duration
	}{{nil, time.Second}, {&tls.Config{}, 0}, {&tls.Config{}, -time.Second}} {
		if got, err := HandshakeContext(context.Background(), "this is not an address", test.config, test.timeout); err == nil || got != nil {
			t.Fatalf("invalid input result=%+v err=%v", got, err)
		}
	}
}
