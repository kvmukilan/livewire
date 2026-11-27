package replaylab

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/replayintent"
	"github.com/kvmukilan/livewire/internal/secureexec"
)

// helloServer accepts TLS connections, records what each ClientHello offered,
// and answers every read with a fixed reply.
type helloServer struct {
	listener net.Listener
	mu       sync.Mutex
	hellos   []string
}

func newHelloServer(t *testing.T, cert tls.Certificate, alpn []string, reply []byte) *helloServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &helloServer{listener: listener}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: alpn, GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
					s.mu.Lock()
					s.hellos = append(s.hellos, fmt.Sprintf("sni=%s alpn=%s", h.ServerName, strings.Join(h.SupportedProtos, ",")))
					s.mu.Unlock()
					return nil, nil
				}})
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				buffer := make([]byte, 4096)
				for {
					if _, err := conn.Read(buffer); err != nil {
						return
					}
					if _, err := conn.Write(reply); err != nil {
						return
					}
				}
			}()
		}
	}()
	return s
}

func (s *helloServer) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.hellos...)
}

func prepareTLSCapture(t *testing.T, path string, keys, ca []byte, target string) (*secureexec.Prepared, error) {
	t.Helper()
	capture, err := pcapio.LoadFile(path, pcapio.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	registry := adapters.DefaultRegistry()
	inspection, err := replayintent.Inspect(capture.Records, replayintent.Options{KeyLog: keys, Mode: "application", Profile: "functional"}, registry)
	if err != nil {
		t.Fatal(err)
	}
	return secureexec.Prepare(secureexec.Config{Inspection: inspection, Registry: registry, Target: target, KeyLog: keys, CA: ca, Timeout: 5 * time.Second, Verify: replay.VerifyLenient})
}

// A key log that covers only some of the selected TLS sessions must stop the
// job before anything is sent, not replay the covered ones and report a match.
func TestPartialKeyLogStopsMultiSessionReplayBeforeSending(t *testing.T) {
	cert, ca, err := LabCertificate()
	if err != nil {
		t.Fatal(err)
	}
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	server := newHelloServer(t, cert, []string{"http/1.1"}, response)
	port := uint16(server.listener.Addr().(*net.TCPAddr).Port)
	var conversations []TCPConversation
	var keys [][]byte
	for i := 0; i < 3; i++ {
		request := []byte(fmt.Sprintf("GET /s%d HTTP/1.1\r\nHost: localhost\r\n\r\n", i))
		encrypted, sessionKeys, err := encryptConversation(cert, []Exchange{{Client: request, Server: response}}, []string{"http/1.1"})
		if err != nil {
			t.Fatal(err)
		}
		conversations = append(conversations, TCPConversation{ServerPort: port, ClientPort: uint16(41000 + i), Start: time.Duration(i) * time.Second, Exchanges: encrypted})
		keys = append(keys, sessionKeys)
	}
	path := filepath.Join(t.TempDir(), "multi.pcap")
	if err := WriteTCPConversations(path, conversations); err != nil {
		t.Fatal(err)
	}
	target := server.listener.Addr().String()

	if _, err := prepareTLSCapture(t, path, keys[0], ca, target); err == nil || !strings.Contains(err.Error(), "2 of 3 selected TLS sessions cannot be replayed with the supplied secrets") {
		t.Fatalf("partial key log: %v", err)
	}
	if hellos := server.seen(); len(hellos) != 0 {
		t.Fatalf("partial key log connected to the target: %v", hellos)
	}

	all := append(append(append([]byte(nil), keys[0]...), keys[1]...), keys[2]...)
	prepared, err := prepareTLSCapture(t, path, all, ca, target)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := prepared.Run(context.Background())
	if err != nil || !outcome.Completed || !outcome.Verified || !outcome.Matched || len(outcome.Sessions) != 3 {
		t.Fatalf("complete key log: %+v err=%v", outcome, err)
	}
}

// Decrypted replay must offer the captured SNI and ALPN, as the handshake-only
// path does, even when the target is given as an IP address.
func TestKeyLogReplayOffersCapturedServerNameAndALPN(t *testing.T) {
	cert, ca, err := LabCertificate()
	if err != nil {
		t.Fatal(err)
	}
	server := newHelloServer(t, cert, []string{"x-lab"}, []byte("pong"))
	port := uint16(server.listener.Addr().(*net.TCPAddr).Port)
	encrypted, keys, err := encryptConversation(cert, []Exchange{{Client: []byte("ping"), Server: []byte("pong")}}, []string{"x-lab"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "alpn.pcap")
	if err := WriteTCPCapture(path, port, encrypted); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareTLSCapture(t, path, keys, ca, server.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := prepared.Run(context.Background())
	if err != nil && err != io.EOF || !outcome.Completed || outcome.ALPN != "x-lab" {
		t.Fatalf("outcome: %+v err=%v", outcome, err)
	}
	if hellos := server.seen(); len(hellos) != 1 || hellos[0] != "sni=localhost alpn=x-lab" {
		t.Fatalf("fresh ClientHello offered %v", hellos)
	}
}
