package tlsreplay

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/kvmukilan/livewire/internal/replay"
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
	Role           AppRole
	Data           []byte
	Expected       []replay.Message
	Peers          []replay.Message
	CapturedAt     time.Duration
	CapturedPacket int
	HasCaptureTime bool
}

// ReTermConfig drives a re-termination.
type ReTermConfig struct {
	Address   string      // host:port of the live device
	TLSConfig *tls.Config // client config (SNI/ALPN/roots) for the fresh handshake
	Script    []AppMessage
	Timeout   time.Duration // per-connection deadline; 0 disables
	// Verify requires each server response to byte-match the captured one;
	// otherwise responses are just recorded for diffing.
	Verify     bool
	Adapter    replay.Adapter
	State      *replay.RuntimeState
	VerifyMode replay.VerifyMode
}

// ReTermResult reports the outcome.
type ReTermResult struct {
	HandshakeState tls.ConnectionState
	Responses      [][]byte // actual server responses, in script order
	Mismatches     int      // count of FromServer messages that differed (Verify mode)
	Differences    []replay.Difference
}

// ReTerminate opens a fresh TLS connection and replays the decrypted script:
// write each client message, and at every server turn read exactly as many bytes
// as the capture recorded so the stream stays framed.
func ReTerminate(cfg ReTermConfig) (*ReTermResult, error) {
	return ReTerminateContext(context.Background(), cfg)
}

// ReTerminateContext is ReTerminate with prompt cancellation for dialing,
// handshaking, reads, and writes. Cancellation closes the owned connection so
// blocked network I/O cannot outlive a stopped replay job.
func ReTerminateContext(ctx context.Context, cfg ReTermConfig) (*ReTermResult, error) {
	if cfg.TLSConfig == nil {
		return nil, fmt.Errorf("tlsreplay: nil TLSConfig; a fresh client handshake is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	d := &net.Dialer{Timeout: cfg.Timeout}
	raw, err := d.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("tlsreplay: fresh connection to %s failed: %w", cfg.Address, replayContextError(ctx, err))
	}
	conn := tls.Client(raw, cfg.TLSConfig)
	defer conn.Close()
	cancelWatchDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = raw.Close()
		case <-cancelWatchDone:
		}
	}()
	defer close(cancelWatchDone)
	if cfg.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(cfg.Timeout))
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tlsreplay: fresh handshake to %s failed: %w", cfg.Address, replayContextError(ctx, err))
	}

	res := &ReTermResult{HandshakeState: conn.ConnectionState()}
	if cfg.State == nil {
		cfg.State = &replay.RuntimeState{Variables: map[string]string{}, Learned: map[string][]byte{}}
	}
	for i, msg := range cfg.Script {
		switch msg.Role {
		case FromClient:
			if _, err := conn.Write(msg.Data); err != nil {
				return res, fmt.Errorf("tlsreplay: writing client message %d: %w", i, replayContextError(ctx, err))
			}
		case FromServer:
			got, err := readLiveResponse(conn, msg.Data, msg.Expected, msg.Peers, cfg.Adapter, cfg.Timeout)
			if err != nil {
				return res, fmt.Errorf("tlsreplay: reading server message %d: %w", i, replayContextError(ctx, err))
			}
			res.Responses = append(res.Responses, got)
			if cfg.Adapter != nil {
				diffs, err := compareAdapterResponse(cfg.Adapter, msg.Data, msg.Expected, msg.Peers, got, cfg.State, cfg.VerifyMode)
				if err != nil {
					return res, fmt.Errorf("tlsreplay: inner response %d: %w", i, err)
				}
				if len(diffs) > 0 {
					res.Mismatches++
					res.Differences = append(res.Differences, diffs...)
				}
			} else if cfg.Verify && !bytes.Equal(got, msg.Data) {
				res.Mismatches++
			}
		}
	}
	return res, nil
}

func replayContextError(ctx context.Context, fallback error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fallback
}

func readLiveResponse(conn net.Conn, expected []byte, expectedMessages, peers []replay.Message, adapter replay.Adapter, timeout time.Duration) ([]byte, error) {
	if adapter == nil {
		got := make([]byte, len(expected))
		_, err := io.ReadFull(conn, got)
		return got, err
	}
	if len(expectedMessages) == 0 {
		var err error
		expectedMessages, err = replay.DecodeWithContext(adapter, replay.ServerToClient, expected, peers)
		if err != nil {
			return nil, err
		}
	}
	if len(expectedMessages) == 0 {
		return nil, nil
	}
	waitEOF := false
	if f, ok := adapter.(replay.EOFFramingAdapter); ok {
		for _, msg := range expectedMessages {
			waitEOF = waitEOF || f.RequiresEOF(replay.ServerToClient, msg)
		}
	}
	deadline := time.Now().Add(timeout)
	if timeout <= 0 {
		deadline = time.Now().Add(30 * time.Second)
	}
	buf := make([]byte, 0, maxInt(len(expected), 1024))
	tmp := make([]byte, 16*1024)
	for {
		step := time.Now().Add(100 * time.Millisecond)
		if step.After(deadline) {
			step = deadline
		}
		_ = conn.SetReadDeadline(step)
		n, readErr := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) > 16<<20 {
				return nil, fmt.Errorf("inner response exceeds 16777216 bytes")
			}
			if got, derr := replay.DecodeWithContext(adapter, replay.ServerToClient, buf, peers); !waitEOF && derr == nil && len(got) >= len(expectedMessages) {
				return buf, nil
			}
		}
		if readErr == io.EOF {
			if _, derr := replay.DecodeWithContext(adapter, replay.ServerToClient, buf, peers); derr != nil {
				return nil, derr
			}
			return buf, nil
		}
		if readErr != nil {
			if ne, ok := readErr.(net.Error); !ok || !ne.Timeout() {
				return nil, readErr
			}
		}
		if !time.Now().Before(deadline) {
			return nil, context.DeadlineExceeded
		}
	}
}

func compareAdapterResponse(adapter replay.Adapter, expectedRaw []byte, expected, peers []replay.Message, actualRaw []byte, state *replay.RuntimeState, mode replay.VerifyMode) ([]replay.Difference, error) {
	if len(expected) == 0 {
		var err error
		expected, err = replay.DecodeWithContext(adapter, replay.ServerToClient, expectedRaw, peers)
		if err != nil {
			return nil, err
		}
	}
	actual, err := replay.DecodeWithContext(adapter, replay.ServerToClient, actualRaw, peers)
	if err != nil {
		return nil, err
	}
	if len(expected) != len(actual) {
		return []replay.Difference{{Field: "message-count", Expected: fmt.Sprint(len(expected)), Actual: fmt.Sprint(len(actual)), Structural: true}}, nil
	}
	expected, err = replay.NormalizeExpectedMessages(adapter, replay.ServerToClient, expected, state)
	if err != nil {
		return nil, err
	}
	var out []replay.Difference
	for i := range expected {
		if match := adapter.Correlate(expected[i], actual[i], state); !match.Matched {
			out = append(out, replay.Difference{Field: "correlation", Expected: match.Key, Actual: match.Reason, Structural: true})
		}
		out = append(out, adapter.Compare(expected[i], actual[i], mode)...)
	}
	return out, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
