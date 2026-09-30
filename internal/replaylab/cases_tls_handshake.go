package replaylab

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
)

func init() { Register(Case{Name: "tls-handshake", Setup: setupTLSHandshakeFixture}) }

func setupTLSHandshakeFixture(ctx context.Context, dir string) (_ *Fixture, retErr error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	cert, ca, err := LabCertificate()
	if err != nil {
		return nil, err
	}
	const protocol = "livewire-lab/1"
	encrypted, _, err := encryptConversation(cert, []Exchange{{Client: []byte("opaque captured request"), Server: []byte("opaque captured response")}}, []string{protocol})
	if err != nil {
		return nil, err
	}
	var clientStream []byte
	for _, event := range encrypted {
		clientStream = append(clientStream, event.Client...)
	}
	capturedRandom, err := independentHelloRandom(clientStream)
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	seen := map[string]bool{capturedRandom: true}
	server, err := ServeTCP(ctx, func(raw net.Conn, stats *Stats) error {
		recorder := &helloPeerConn{Conn: raw}
		var hello *tls.ClientHelloInfo
		config := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{protocol}, GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) { hello = h; return nil, nil }}
		conn := tls.Server(recorder, config)
		if err := conn.HandshakeContext(ctx); err != nil {
			return err
		}
		if hello == nil || hello.ServerName != "localhost" || len(hello.SupportedProtos) != 1 || hello.SupportedProtos[0] != protocol || len(hello.SupportedVersions) != 1 || hello.SupportedVersions[0] != tls.VersionTLS12 {
			return fmt.Errorf("fresh ClientHello did not retain fixture negotiation metadata")
		}
		freshRandom, err := independentHelloRandom(recorder.opening)
		if err != nil {
			return err
		}
		mu.Lock()
		repeated := seen[freshRandom]
		seen[freshRandom] = true
		mu.Unlock()
		if repeated {
			return fmt.Errorf("TLS handshake reused a ClientHello random")
		}
		var b [1]byte
		n, err := conn.Read(b[:])
		if n != 0 || err != io.EOF {
			return fmt.Errorf("handshake-only client must close with zero application bytes")
		}
		state := conn.ConnectionState()
		if state.NegotiatedProtocol != protocol || !state.HandshakeComplete {
			return fmt.Errorf("TLS handshake negotiation did not complete")
		}
		event := map[string]any{"serverName": hello.ServerName, "alpn": state.NegotiatedProtocol, "version": tls.VersionName(state.Version), "capturedRandomSHA256": capturedRandom, "clientRandomSHA256": freshRandom, "applicationBytes": 0, "completed": true}
		data, err := json.Marshal(event)
		if err != nil {
			return err
		}
		stats.Note("tls-handshake %s", data)
		return nil
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			_ = server.Close()
		}
	}()
	capture, caPath := filepath.Join(dir, "fixture.pcap"), filepath.Join(dir, "fixture-ca.pem")
	if err := WriteTCPCapture(capture, server.Port(), encrypted); err != nil {
		return nil, err
	}
	if err := writeNew(caPath, ca); err != nil {
		return nil, err
	}
	return &Fixture{Capture: capture, Args: []string{"-t", server.Address(), "-ca", caPath}, Snapshot: server.Stats.Snapshot, Events: server.Stats.Events, Close: server.Close}, nil
}

type helloPeerConn struct {
	net.Conn
	opening []byte
}

func (c *helloPeerConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if len(c.opening) < 256<<10 {
		take := n
		if take > (256<<10)-len(c.opening) {
			take = (256 << 10) - len(c.opening)
		}
		c.opening = append(c.opening, p[:take]...)
	}
	return n, err
}

// This peer witness parses only independent TLS framing and the public random;
// it does not share the replay implementation's metadata parser.
func independentHelloRandom(stream []byte) (string, error) {
	var handshake []byte
	for len(stream) >= 5 {
		n := int(binary.BigEndian.Uint16(stream[3:5]))
		if stream[0] != 22 || n > len(stream)-5 {
			break
		}
		handshake = append(handshake, stream[5:5+n]...)
		stream = stream[5+n:]
		if len(handshake) >= 38 {
			if handshake[0] != 1 {
				break
			}
			return fmt.Sprintf("sha256:%x", sha256.Sum256(handshake[6:38])), nil
		}
	}
	return "", fmt.Errorf("independent peer did not observe a complete ClientHello random")
}
