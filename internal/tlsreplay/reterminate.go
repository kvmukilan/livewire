package tlsreplay

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"
)

// AppRole is the originator of an application-layer message.
type AppRole uint8

const (
	// FromClient is a message the captured client sent to the server.
	FromClient AppRole = iota
	// FromServer is a message the captured server sent to the client.
	FromServer
)

// AppMessage is one decrypted application-layer message. The re-terminator sends
// FromClient messages on a fresh connection and reads back the FromServer ones.
type AppMessage struct {
	Role AppRole
	Data []byte
}

// ReTermConfig drives a re-termination.
type ReTermConfig struct {
	Address   string      // host:port of the live device
	TLSConfig *tls.Config // client config (SNI/ALPN/roots) for the fresh handshake
	Script    []AppMessage
	Timeout   time.Duration // per-connection deadline; 0 disables
	// Verify requires each server response to byte-match the captured one;
	// otherwise responses are just recorded for diffing.
	Verify bool
}

// ReTermResult reports the outcome.
type ReTermResult struct {
	HandshakeState tls.ConnectionState
	Responses      [][]byte // actual server responses, in script order
	Mismatches     int      // count of FromServer messages that differed (Verify mode)
}

// ReTerminate opens a fresh TLS connection and replays the decrypted script:
// write each client message, and at every server turn read exactly as many bytes
// as the capture recorded so the stream stays framed.
func ReTerminate(cfg ReTermConfig) (*ReTermResult, error) {
	if cfg.TLSConfig == nil {
		return nil, fmt.Errorf("tlsreplay: nil TLSConfig; a fresh client handshake is required")
	}
	d := &net.Dialer{Timeout: cfg.Timeout}
	conn, err := tls.DialWithDialer(d, "tcp", cfg.Address, cfg.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("tlsreplay: fresh handshake to %s failed: %w", cfg.Address, err)
	}
	defer conn.Close()
	if cfg.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(cfg.Timeout))
	}

	res := &ReTermResult{HandshakeState: conn.ConnectionState()}
	for i, msg := range cfg.Script {
		switch msg.Role {
		case FromClient:
			if _, err := conn.Write(msg.Data); err != nil {
				return res, fmt.Errorf("tlsreplay: writing client message %d: %w", i, err)
			}
		case FromServer:
			got := make([]byte, len(msg.Data))
			if _, err := io.ReadFull(conn, got); err != nil {
				return res, fmt.Errorf("tlsreplay: reading server message %d: %w", i, err)
			}
			res.Responses = append(res.Responses, got)
			if cfg.Verify && !bytes.Equal(got, msg.Data) {
				res.Mismatches++
			}
		}
	}
	return res, nil
}
