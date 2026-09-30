package tlsreplay

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"
)

type HandshakeResult struct {
	State       tls.ConnectionState
	ClientHello *ClientHelloMetadata
	Cleanup     string
}

// HandshakeContext establishes and closes a fresh TLS session without writing
// or interpreting any application data. The supplied config holds only public
// capture metadata and explicitly selected trust settings.
func HandshakeContext(ctx context.Context, address string, config *tls.Config, timeout time.Duration) (result *HandshakeResult, retErr error) {
	if config == nil || timeout <= 0 {
		return nil, fmt.Errorf("fresh TLS handshake requires a configuration and positive timeout")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	config = config.Clone()
	config.ClientSessionCache = nil
	config.SessionTicketsDisabled = true
	raw, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("fresh TLS connection: %w", replayContextError(ctx, err))
	}
	recorder := &helloRecordingConn{Conn: raw}
	conn := tls.Client(recorder, config)
	result = &HandshakeResult{}
	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			_ = raw.Close()
		case <-stop:
		}
	}()
	defer func() {
		// Keep cancellation active until Close finishes. TLS Close can write a
		// close_notify; its deadline must stay bounded too.
		err := conn.Close()
		close(stop)
		<-stopped
		result.Cleanup = "complete"
		if err != nil && !errors.Is(err, net.ErrClosed) {
			result.Cleanup = "failed"
			retErr = errors.Join(retErr, fmt.Errorf("close fresh TLS connection: %w", err))
		}
		if ctx.Err() != nil {
			retErr = errors.Join(retErr, ctx.Err())
		}
	}()
	deadline, _ := ctx.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		return result, err
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return result, fmt.Errorf("fresh TLS handshake: %w", replayContextError(ctx, err))
	}
	result.State = conn.ConnectionState()
	result.ClientHello, err = ParseClientHello(recorder.hello)
	if err != nil {
		return result, fmt.Errorf("fresh TLS ClientHello evidence: %w", err)
	}
	return result, nil
}

// Go's TLS client emits its opening ClientHello before any encrypted writes.
// Retain only those public bytes, bounded independently of the TLS connection.
type helloRecordingConn struct {
	net.Conn
	hello    []byte
	complete bool
}

func (c *helloRecordingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if !c.complete && n > 0 {
		if len(c.hello)+n <= maxClientHelloBytes {
			c.hello = append(c.hello, p[:n]...)
			if _, e := ParseClientHello(c.hello); e == nil {
				c.complete = true
			}
		} else {
			c.complete = true
			c.hello = nil
		}
	}
	return n, err
}
