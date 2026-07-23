package replay

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"time"
)

const maxSemanticFrame = 16 << 20

type TCPSemanticConfig struct {
	Session    *Session
	TargetIP   netip.Addr
	TargetPort uint16
	Adapter    Adapter
	Profile    Profile
	Verify     VerifyMode
	Variables  map[string]string
	Timeout    time.Duration
	Start      time.Time
	Progress   func(ProgressEvent)
	Dial       func(context.Context, string, string) (net.Conn, error)
}

// RunTCPSemanticContext re-terminates an unencrypted TCP application session
// through a normal live socket. Segmentation is intentionally not claimed: use
// the transport profile for packet-level TCP behavior.
func RunTCPSemanticContext(ctx context.Context, cfg TCPSemanticConfig) (TransportResult, error) {
	if cfg.Session == nil || cfg.Session.Transport != TransportTCP || cfg.Adapter == nil {
		return TransportResult{}, fmt.Errorf("semantic TCP replay requires a TCP session and adapter")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	port := cfg.TargetPort
	if port == 0 {
		port = cfg.Session.Server.Port
	}
	dial := cfg.Dial
	if dial == nil {
		d := net.Dialer{Timeout: cfg.Timeout}
		dial = d.DialContext
	}
	conn, err := dial(ctx, "tcp", net.JoinHostPort(cfg.TargetIP.String(), strconv.Itoa(int(port))))
	if err != nil {
		return TransportResult{SessionID: cfg.Session.ID, Mode: ModeSemantic, Fidelity: FidelitySemantic, Error: err.Error()}, err
	}
	defer conn.Close()

	verified := cfg.Verify != VerifyOff
	res := TransportResult{SessionID: cfg.Session.ID, Mode: ModeSemantic, Fidelity: FidelitySemantic, Verified: verified, Matched: verified}
	state := &RuntimeState{Variables: copyVariables(cfg.Variables), Learned: map[string][]byte{}}
	turns, turnErr := semanticTurns(cfg.Session)
	if turnErr != nil {
		res.Error = turnErr.Error()
		return res, turnErr
	}
	var pendingPeers []Message
	started := cfg.Start
	if started.IsZero() {
		started = time.Now()
	}
	for _, turn := range turns {
		if ctx.Err() != nil {
			res.Error = "cancelled"
			return res, ctx.Err()
		}
		if paced(cfg.Profile) && !waitWallUntil(ctx, started.Add(turn.at)) {
			res.Error = "cancelled"
			return res, ctx.Err()
		}
		expected, derr := DecodeWithContext(cfg.Adapter, turn.dir, turn.data, pendingPeers)
		if derr != nil {
			res.Error = derr.Error()
			return res, fmt.Errorf("%s decode: %w", cfg.Adapter.Name(), derr)
		}
		if turn.dir == ClientToServer {
			for _, msg := range expected {
				prepared, perr := cfg.Adapter.Prepare(turn.dir, msg, state)
				if perr != nil {
					res.Error = perr.Error()
					return res, perr
				}
				if err := writeContext(ctx, conn, prepared, cfg.Timeout); err != nil {
					res.Error = err.Error()
					return res, err
				}
				res.Sent++
			}
			pendingPeers = append(pendingPeers, expected...)
			emitSemanticProgress(cfg, "send", fmt.Sprintf("sent %d %s message(s)", len(expected), cfg.Adapter.Name()))
			continue
		}

		actual, rerr := readAdapterMessages(ctx, conn, cfg.Adapter, turn.dir, expected, pendingPeers, cfg.Timeout)
		if rerr != nil {
			res.Error = rerr.Error()
			return res, rerr
		}
		res.Received += len(actual)
		normalizedExpected, normalizeErr := NormalizeExpectedMessages(cfg.Adapter, turn.dir, expected, state)
		if normalizeErr != nil {
			res.Error = normalizeErr.Error()
			return res, normalizeErr
		}
		if cfg.Verify != VerifyOff && len(actual) != len(expected) {
			res.Matched = false
			res.Differences = append(res.Differences, Difference{Field: "message-count", Expected: fmt.Sprint(len(expected)), Actual: fmt.Sprint(len(actual)), Structural: true})
		}
		for i := 0; cfg.Verify != VerifyOff && i < len(normalizedExpected) && i < len(actual); i++ {
			match := cfg.Adapter.Correlate(normalizedExpected[i], actual[i], state)
			if !match.Matched {
				res.Matched = false
				res.Differences = append(res.Differences, Difference{Field: "correlation", Expected: match.Key, Actual: match.Reason, Structural: true})
			}
			diffs := cfg.Adapter.Compare(normalizedExpected[i], actual[i], cfg.Verify)
			if len(diffs) > 0 {
				res.Matched = false
				res.Differences = append(res.Differences, diffs...)
			}
		}
		if cfg.Verify == VerifyStrict && !res.Matched {
			res.Error = "live application response differs from capture"
			return res, fmt.Errorf("%s", res.Error)
		}
		consumed := ConsumePeers(cfg.Adapter, turn.dir, actual, len(pendingPeers))
		pendingPeers = pendingPeers[consumed:]
		emitSemanticProgress(cfg, "receive", fmt.Sprintf("received %d %s message(s)", len(actual), cfg.Adapter.Name()))
	}
	res.Completed = true
	return res, nil
}

type semanticTurn struct {
	dir  Direction
	at   time.Duration
	data []byte
}

func semanticTurns(s *Session) ([]semanticTurn, error) {
	assembled, fallback, err := assembleTCPStreams(s)
	if err != nil {
		return nil, err
	}
	if fallback != nil {
		var out []semanticTurn
		for _, event := range s.Events {
			if len(event.Payload) == 0 {
				continue
			}
			if len(out) == 0 || out[len(out)-1].dir != event.Direction {
				out = append(out, semanticTurn{dir: event.Direction, at: event.At})
			}
			out[len(out)-1].data = append(out[len(out)-1].data, event.Payload...)
		}
		return out, nil
	}

	type captureRun struct {
		direction Direction
		at        time.Duration
		packets   map[int]bool
	}
	var runs []captureRun
	for _, event := range s.Events {
		if len(event.Payload) == 0 {
			continue
		}
		if len(runs) == 0 || runs[len(runs)-1].direction != event.Direction {
			runs = append(runs, captureRun{direction: event.Direction, at: event.At, packets: map[int]bool{}})
		}
		runs[len(runs)-1].packets[event.PacketIndex] = true
	}
	next := map[Direction]int64{}
	var out []semanticTurn
	for _, run := range runs {
		var segments []tcpPayloadSegment
		for _, segment := range assembled[run.direction].segments {
			if run.packets[segment.packet] {
				segments = append(segments, segment)
			}
		}
		sort.SliceStable(segments, func(i, j int) bool { return segments[i].offset < segments[j].offset })
		turn := semanticTurn{dir: run.direction, at: run.at}
		for _, segment := range segments {
			end := segment.offset + int64(len(segment.data))
			if end <= next[run.direction] {
				continue
			}
			if segment.offset > next[run.direction] {
				return nil, fmt.Errorf("%s TCP payload arrived across response turns; semantic ordering is ambiguous before packet %d", run.direction, segment.packet)
			}
			trim := next[run.direction] - segment.offset
			turn.data = append(turn.data, segment.data[trim:]...)
			next[run.direction] = end
		}
		if len(turn.data) > 0 {
			out = append(out, turn)
		}
	}
	return out, nil
}

func expectedBytes(msgs []Message) int {
	n := 0
	for _, m := range msgs {
		n += len(m.Raw)
	}
	return n
}

func readAdapterMessages(ctx context.Context, conn net.Conn, adapter Adapter, dir Direction, expected, peers []Message, timeout time.Duration) ([]Message, error) {
	if len(expected) == 0 {
		return nil, nil
	}
	waitEOF := adapterRequiresEOF(adapter, dir, expected)
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 0, maxInt(expectedBytes(expected), 1024))
	tmp := make([]byte, 16*1024)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		step := time.Now().Add(100 * time.Millisecond)
		if step.After(deadline) {
			step = deadline
		}
		_ = conn.SetReadDeadline(step)
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) > maxSemanticFrame {
				return nil, fmt.Errorf("%s: response exceeds %d bytes", adapter.Name(), maxSemanticFrame)
			}
			if msgs, derr := DecodeWithContext(adapter, dir, buf, peers); !waitEOF && derr == nil && len(msgs) >= len(expected) {
				return msgs, nil
			}
		}
		if err != nil && err != io.EOF {
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				return nil, err
			}
		}
		if err == io.EOF {
			msgs, derr := DecodeWithContext(adapter, dir, buf, peers)
			if derr != nil {
				return nil, derr
			}
			return msgs, nil
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("%s: response timed out", adapter.Name())
		}
	}
}

func adapterRequiresEOF(adapter Adapter, dir Direction, messages []Message) bool {
	f, ok := adapter.(EOFFramingAdapter)
	if !ok {
		return false
	}
	for _, msg := range messages {
		if f.RequiresEOF(dir, msg) {
			return true
		}
	}
	return false
}

func writeContext(ctx context.Context, conn net.Conn, data []byte, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		step := time.Now().Add(100 * time.Millisecond)
		if step.After(deadline) {
			step = deadline
		}
		_ = conn.SetWriteDeadline(step)
		n, err := conn.Write(data)
		data = data[n:]
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			return err
		}
	}
	return nil
}

func waitWallUntil(ctx context.Context, target time.Time) bool {
	d := time.Until(target)
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func emitSemanticProgress(cfg TCPSemanticConfig, stage, message string) {
	if cfg.Progress != nil {
		cfg.Progress(ProgressEvent{SessionID: cfg.Session.ID, Stage: stage, Message: message, At: time.Now()})
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
