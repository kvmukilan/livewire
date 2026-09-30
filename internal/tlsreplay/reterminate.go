package tlsreplay

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
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
	Request        *replay.Message
	Expected       []replay.Message
	Peers          []replay.Message
	CapturedAt     time.Duration
	CapturedPacket int
	HasCaptureTime bool
}

// ReTermConfig drives a re-termination.
type ReTermConfig struct {
	SessionID       string
	Address         string      // host:port of the live device
	TLSConfig       *tls.Config // client config (SNI/ALPN/roots) for the fresh handshake
	Script          []AppMessage
	Timeout         time.Duration // per-connection deadline; 0 disables
	ExchangeTimeout time.Duration // individual request/response budget; defaults to Timeout, or 30s
	Profile         replay.Profile
	Start           time.Time
	// Verify requires each server response to byte-match the captured one;
	// otherwise responses are just recorded for diffing.
	Verify     bool
	Adapter    replay.Adapter
	State      *replay.RuntimeState
	VerifyMode replay.VerifyMode
}

// ReTermResult reports the outcome.
type ReTermResult struct {
	Requests int // captured application messages successfully written
	replay.VerificationEvidence
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
func ReTerminateContext(ctx context.Context, cfg ReTermConfig) (res *ReTermResult, retErr error) {
	if cfg.TLSConfig == nil {
		return nil, fmt.Errorf("tlsreplay: nil TLSConfig; a fresh client handshake is required")
	}
	if cfg.Adapter != nil && cfg.Adapter.Name() == "http/1" {
		// Some HTTP endpoints require ALPN even for HTTP/1.1. Offer only the
		// protocol this adapter implements, without changing the caller's config.
		cfg.TLSConfig = cfg.TLSConfig.Clone()
		cfg.TLSConfig.NextProtos = []string{"http/1.1"}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	exchangeTimeout := cfg.ExchangeTimeout
	if exchangeTimeout <= 0 {
		exchangeTimeout = cfg.Timeout
	}
	if exchangeTimeout <= 0 {
		exchangeTimeout = 30 * time.Second
	}
	var futureResponses []replay.Message
	for i, message := range cfg.Script {
		if cfg.Profile == replay.ProfileTiming && !message.HasCaptureTime {
			return nil, fmt.Errorf("tlsreplay: timing profile requires capture chronology for message %d", i)
		}
		if cfg.Adapter != nil && message.Role == FromServer {
			expected := message.Expected
			if len(expected) == 0 {
				var err error
				expected, err = replay.DecodeWithContext(cfg.Adapter, replay.ServerToClient, message.Data, message.Peers)
				if err != nil {
					return nil, fmt.Errorf("tlsreplay: capture response %d framing: %w", i, err)
				}
			}
			futureResponses = append(futureResponses, expected...)
		}
	}
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}
	d := &net.Dialer{Timeout: cfg.Timeout}
	raw, err := d.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("tlsreplay: fresh connection to %s failed: %w", cfg.Address, replayContextError(ctx, err))
	}
	conn := tls.Client(raw, cfg.TLSConfig)
	defer func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			if res != nil {
				res.Cleanup = "failed"
			}
			retErr = errors.Join(retErr, fmt.Errorf("tlsreplay: close fresh connection: %w", err))
		} else if res != nil {
			res.Cleanup = "complete"
		}
	}()
	cancelWatchDone := make(chan struct{})
	cancelWatchResult := make(chan error, 1)
	go func() {
		select {
		case <-ctx.Done():
			err := raw.Close()
			if errors.Is(err, net.ErrClosed) {
				err = nil
			}
			cancelWatchResult <- err
		case <-cancelWatchDone:
			cancelWatchResult <- nil
		}
	}()
	defer func() {
		close(cancelWatchDone)
		if err := <-cancelWatchResult; err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("tlsreplay: close cancelled connection: %w", err))
		}
	}()
	if cfg.Timeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(cfg.Timeout)); err != nil {
			return nil, fmt.Errorf("tlsreplay: set connection deadline: %w", err)
		}
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tlsreplay: fresh handshake to %s failed: %w", cfg.Address, replayContextError(ctx, err))
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("tlsreplay: clear handshake deadline: %w", err)
	}

	res = &ReTermResult{HandshakeState: conn.ConnectionState()}
	res.Scope = "application messages"
	if cfg.Adapter == nil {
		res.Scope = "opaque plaintext captured-length chunks"
	}
	defer func() {
		res.Transformations = append(res.Transformations, cfg.State.Transformations...)
		if retErr != nil {
			res.ReasonCode = "execution_failed"
		}
	}()
	if cfg.State == nil {
		cfg.State = replay.NewRuntimeState(nil)
	}
	if cfg.State.Protocol == nil {
		cfg.State.Protocol = map[string]any{}
	}
	if cfg.State.Phase == "" {
		cfg.State.Phase = replay.SessionActive
	}
	cfg.State.Protocol["http.scheme"] = "https"
	var reader replay.MessageReader
	scenario := replay.Execution(ctx).Scenario
	cfg.State.Protocol["scenario"] = scenario
	cfg.State.Protocol["scenario.session"] = cfg.SessionID
	defer scenario.End(cfg.SessionID)
	requestOrdinal, responseOrdinal := 0, 0
	started := cfg.Start
	if started.IsZero() {
		started = time.Now()
	}
	var pendingPeers []replay.Message
	for i, msg := range cfg.Script {
		if cfg.Profile == replay.ProfileTiming {
			target := started.Add(msg.CapturedAt)
			if cfg.Adapter != nil {
				if err := reader.WaitUntil(ctx, conn, cfg.Adapter, futureResponses, pendingPeers, cfg.State, target, exchangeTimeout); err != nil {
					return res, fmt.Errorf("tlsreplay: waiting for message %d: %w", i, replayContextError(ctx, err))
				}
			} else if err := waitUntil(ctx, target); err != nil {
				return res, err
			}
		}
		switch msg.Role {
		case FromClient:
			requestOrdinal++
			if err := scenario.Before(ctx, cfg.SessionID, requestOrdinal, cfg.State); err != nil {
				return res, err
			}
			data := msg.Data
			if msg.Request != nil && cfg.Adapter != nil {
				data, err = cfg.Adapter.Prepare(replay.ClientToServer, *msg.Request, cfg.State)
				if err != nil {
					return res, err
				}
			}
			if msg.Request != nil && cfg.Adapter != nil {
				liveMessages, decodeErr := replay.DecodeWithContext(cfg.Adapter, replay.ClientToServer, data, nil)
				if decodeErr != nil || len(liveMessages) != 1 {
					return res, fmt.Errorf("prepared request has invalid framing")
				}
				if err := replay.Observe(cfg.Adapter, replay.ClientToServer, *msg.Request, liveMessages[0], cfg.State); err != nil {
					return res, err
				}
			}
			if err := replay.RecordOperation(ctx, "intent", requestOrdinal); err != nil {
				return res, err
			}
			if err := replay.WriteStateContext(ctx, conn, data, cfg.State, exchangeTimeout); err != nil {
				return res, fmt.Errorf("tlsreplay: writing client message %d: %w", i, replayContextError(ctx, err))
			}
			res.Requests++
			if msg.Request != nil {
				pendingPeers = append(pendingPeers, *msg.Request)
			}
		case FromServer:
			messageCount := 1
			var got []byte
			var liveMessages []replay.Message
			var err error
			if cfg.Adapter != nil {
				expected := msg.Expected
				if len(expected) == 0 {
					expected, err = replay.DecodeWithContext(cfg.Adapter, replay.ServerToClient, msg.Data, msg.Peers)
				}
				if err == nil {
					messageCount = len(expected)
					res.Expected += messageCount
					liveMessages, err = reader.ReadExchange(ctx, conn, cfg.Adapter, expected, msg.Peers, cfg.State, exchangeTimeout)
					res.Observed += len(liveMessages)
					for _, m := range liveMessages {
						got = append(got, m.Raw...)
					}
				}
			} else {
				res.Expected++
				got, err = readLiveResponse(conn, msg.Data, msg.Expected, msg.Peers, nil, exchangeTimeout)
				if err == nil && len(got) > 0 {
					res.Observed++
				}
			}
			if err != nil {
				return res, fmt.Errorf("tlsreplay: reading server message %d: %w", i, replayContextError(ctx, err))
			}
			res.Responses = append(res.Responses, got)
			if cfg.VerifyMode != replay.VerifyOff && cfg.Adapter != nil || cfg.Verify {
				res.Compared += messageCount
			}
			if cfg.Adapter != nil {
				diffs, err := compareAdapterMessages(cfg.Adapter, msg.Data, msg.Expected, msg.Peers, liveMessages, cfg.State, cfg.VerifyMode)
				if err != nil {
					return res, fmt.Errorf("tlsreplay: inner response %d: %w", i, err)
				}
				if len(diffs) > 0 {
					res.Mismatches++
					res.Differences = append(res.Differences, diffs...)
				}
				for _, m := range liveMessages {
					if replay.ConsumePeers(cfg.Adapter, replay.ServerToClient, []replay.Message{m}, 1) > 0 {
						responseOrdinal++
						if e := scenario.After(cfg.SessionID, responseOrdinal, cfg.Adapter, m); e != nil {
							return res, e
						}
					}
				}
				pendingPeers = pendingPeers[replay.ConsumePeers(cfg.Adapter, replay.ServerToClient, liveMessages, len(pendingPeers)):]
				futureResponses = futureResponses[messageCount:]
			} else if cfg.Verify && !bytes.Equal(got, msg.Data) {
				res.Mismatches++
			}
			if err := replay.RecordOperation(ctx, "ack", responseOrdinal); err != nil {
				return res, err
			}
		}
	}
	return res, nil
}

func waitUntil(ctx context.Context, target time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := time.NewTimer(time.Until(target))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func replayContextError(ctx context.Context, fallback error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// The socket deadline can fire before the context timer's goroutine updates
	// Err. Classify an I/O timeout at an elapsed context deadline consistently,
	// without converting an earlier exchange timeout or unrelated I/O failure.
	var networkError net.Error
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) && errors.As(fallback, &networkError) && networkError.Timeout() {
		return context.DeadlineExceeded
	}
	return fallback
}

func readLiveResponse(conn net.Conn, expected []byte, expectedMessages, peers []replay.Message, adapter replay.Adapter, timeout time.Duration) ([]byte, error) {
	if adapter == nil {
		if timeout > 0 {
			if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
				return nil, err
			}
		}
		got := make([]byte, len(expected))
		_, err := io.ReadFull(conn, got)
		if err != nil {
			err = &replay.ResponseReadError{Err: err}
		}
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
		if err := conn.SetReadDeadline(step); err != nil && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
			return nil, fmt.Errorf("set inner response read deadline: %w", err)
		}
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

func compareAdapterMessages(adapter replay.Adapter, expectedRaw []byte, expected, peers, actual []replay.Message, state *replay.RuntimeState, mode replay.VerifyMode) ([]replay.Difference, error) {
	if len(expected) == 0 {
		var err error
		expected, err = replay.DecodeWithContext(adapter, replay.ServerToClient, expectedRaw, peers)
		if err != nil {
			return nil, err
		}
	}
	actual, err := replay.AlignResponses(adapter, expected, actual, state)
	if err != nil {
		return nil, err
	}
	if len(expected) != len(actual) {
		return []replay.Difference{{Field: "message-count", Expected: fmt.Sprint(len(expected)), Actual: fmt.Sprint(len(actual)), Structural: true}}, nil
	}
	normalizedExpected, err := replay.NormalizeExpectedMessages(adapter, replay.ServerToClient, expected, state)
	if err != nil {
		return nil, err
	}
	var out []replay.Difference
	for i := range expected {
		if match := adapter.Correlate(normalizedExpected[i], actual[i], state); !match.Matched {
			return out, fmt.Errorf("inner response correlation failed: %s", match.Reason)
		} else if err := replay.Observe(adapter, replay.ServerToClient, expected[i], actual[i], state); err != nil {
			return out, err
		}
		ordinal, _ := state.Protocol["responseOrdinal"].(int)
		if replay.ConsumePeers(adapter, replay.ServerToClient, actual[i:i+1], 1) > 0 {
			ordinal++
			if state.Protocol != nil {
				state.Protocol["responseOrdinal"] = ordinal
			}
		}
		scenario, _ := state.Protocol["scenario"].(*replay.ScenarioRuntime)
		session, _ := state.Protocol["scenario.session"].(string)
		out = append(out, scenario.Compare(session, ordinal, adapter, normalizedExpected[i], actual[i], mode)...)
	}
	return out, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
