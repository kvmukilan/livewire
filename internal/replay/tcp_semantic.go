package replay

import (
	"context"
	"errors"
	"fmt"
	"github.com/kvmukilan/livewire/internal/runstate"
	"github.com/kvmukilan/livewire/internal/wire"
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
func RunTCPSemanticContext(ctx context.Context, cfg TCPSemanticConfig) (res TransportResult, retErr error) {
	if cfg.Session == nil || cfg.Session.Transport != TransportTCP || cfg.Adapter == nil {
		return TransportResult{}, fmt.Errorf("semantic TCP replay requires a TCP session and adapter")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if ctx == nil {
		ctx = context.Background()
	}
	turns, turnErr := semanticAdapterTurns(cfg.Session, cfg.Adapter)
	if turnErr != nil {
		return res, turnErr
	}
	var preflightPeers []Message
	var futureResponses []Message
	for _, turn := range turns {
		if len(turn.data) == 0 {
			continue
		}
		messages, err := DecodeWithContext(cfg.Adapter, turn.dir, turn.data, preflightPeers)
		if err != nil {
			return res, fmt.Errorf("capture %s framing: %w", cfg.Adapter.Name(), err)
		}
		if turn.dir == ClientToServer {
			preflightPeers = append(preflightPeers, messages...)
		} else {
			futureResponses = append(futureResponses, messages...)
			preflightPeers = preflightPeers[ConsumePeers(cfg.Adapter, turn.dir, messages, len(preflightPeers)):]
		}
	}
	scenario := Execution(ctx).Scenario
	if scenario != nil {
		if err := scenario.Scenario.ValidateSession(cfg.Session, cfg.Adapter); err != nil {
			return res, err
		}
		defer scenario.End(cfg.Session.ID)
	}
	var saved *runstate.Result
	var beginErr error
	var scenarioSpec *Scenario
	if scenario != nil {
		scenarioSpec = scenario.Scenario
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
	openConnection := func(c context.Context) (net.Conn, error) {
		return dial(c, "tcp", net.JoinHostPort(cfg.TargetIP.String(), strconv.Itoa(int(port))))
	}
	restartSafe := ScenarioRestartSafe(cfg.Adapter, cfg.Session, scenarioSpec)
	if !restartSafe {
		safe, proven, err := CheckRecovery(ctx, cfg.Session, cfg.Adapter, cfg.Variables, cfg.Timeout, openConnection, false)
		if err != nil {
			return res, err
		}
		if proven != nil {
			key := fmt.Sprintf("%d/%s", Execution(ctx).Attempt+1, cfg.Session.ID)
			if err := Execution(ctx).Journal.Finish(key, *proven); err != nil {
				return res, err
			}
			return TransportResult{SessionID: cfg.Session.ID, Mode: ModeSemantic, Fidelity: FidelitySemantic, Completed: true, VerificationEvidence: VerificationEvidence{Scope: "recovery target-state probe", ReasonCode: "recovered_unverified", Cleanup: "complete"}}, nil
		}
		restartSafe = safe
	}
	ctx, saved, beginErr = BeginSession(ctx, cfg.Session.ID, restartSafe)
	if beginErr != nil {
		return res, beginErr
	}
	if saved != nil {
		return TransportResult{SessionID: cfg.Session.ID, Mode: ModeSemantic, Fidelity: FidelitySemantic, Completed: saved.Completed, Verified: saved.Verified, Matched: saved.Matched, Sent: saved.Sent, Received: saved.Received}, nil
	}
	defer func() {
		res.Matched = res.Matched && res.Completed && retErr == nil
		retErr = errors.Join(retErr, FinishSession(ctx, runstate.Result{Completed: res.Completed && retErr == nil, Verified: res.Verified, Matched: res.Matched, Sent: res.Sent, Received: res.Received}))
		if retErr != nil {
			res.Completed = false
			res.Matched = false
			res.Error = retErr.Error()
		}
		res.ReasonCode = FailureReason(res.Completed, res.Verified, res.Matched, retErr)
	}()
	conn, err := openConnection(ctx)
	if err != nil {
		return TransportResult{SessionID: cfg.Session.ID, Mode: ModeSemantic, Fidelity: FidelitySemantic, Error: err.Error()}, err
	}
	verified := cfg.Verify != VerifyOff
	res = TransportResult{SessionID: cfg.Session.ID, Mode: ModeSemantic, Fidelity: FidelitySemantic, Verified: verified, Matched: verified}
	res.Scope = "application messages"
	defer func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			res.Cleanup = "failed"
			retErr = errors.Join(retErr, fmt.Errorf("close semantic TCP connection: %w", err))
			res.Completed = false
			res.Matched = false
			res.Error = retErr.Error()
		} else {
			res.Cleanup = "complete"
		}
	}()
	state := NewRuntimeState(cfg.Variables)
	var reader MessageReader
	defer func() {
		res.Verified = res.Verified && res.Compared > 0
		res.Matched = res.Matched && res.Verified && res.Completed && retErr == nil
		res.Observed = res.Received
		res.Transformations = append(res.Transformations, state.Transformations...)
		res.ReasonCode = FailureReason(res.Completed, res.Verified, res.Matched, retErr)
	}()
	var timing timingRecorder
	defer func() { res.Timing = timing.result() }()
	var pendingPeers []Message
	responseOrdinal := 0
	started := cfg.Start
	if started.IsZero() {
		started = time.Now()
	}
	for _, turn := range turns {
		if ctx.Err() != nil {
			res.Error = "cancelled"
			return res, ctx.Err()
		}
		var scheduled time.Time
		if paced(cfg.Profile) {
			scheduled = started.Add(turn.at)
		}
		if paced(cfg.Profile) {
			if err := reader.WaitUntil(ctx, conn, cfg.Adapter, futureResponses, pendingPeers, state, scheduled, cfg.Timeout); err != nil {
				return res, err
			}
		}
		var expected []Message
		var derr error
		if len(turn.data) > 0 {
			expected, derr = DecodeWithContext(cfg.Adapter, turn.dir, turn.data, pendingPeers)
		}
		if derr != nil {
			res.Error = derr.Error()
			return res, fmt.Errorf("%s decode: %w", cfg.Adapter.Name(), derr)
		}
		if turn.dir == ClientToServer {
			messageEnd := 0
			for _, msg := range expected {
				messageEnd += len(msg.Raw)
				messageAt := turn.completionAt(messageEnd)
				if paced(cfg.Profile) {
					scheduled = started.Add(messageAt)
					if err := reader.WaitUntil(ctx, conn, cfg.Adapter, futureResponses, pendingPeers, state, scheduled, cfg.Timeout); err != nil {
						return res, err
					}
				}
				if err := scenario.Before(ctx, cfg.Session.ID, res.Sent+1, state); err != nil {
					return res, err
				}
				prepared, perr := cfg.Adapter.Prepare(turn.dir, msg, state)
				if perr != nil {
					res.Error = perr.Error()
					return res, perr
				}
				liveMessages, decodeErr := DecodeWithContext(cfg.Adapter, ClientToServer, prepared, nil)
				if decodeErr != nil || len(liveMessages) != 1 {
					return res, fmt.Errorf("prepared request has invalid framing")
				}
				if err := Observe(cfg.Adapter, ClientToServer, msg, liveMessages[0], state); err != nil {
					return res, err
				}
				if err := RecordOperation(ctx, "intent", res.Sent+1); err != nil {
					return res, err
				}
				if err := WriteStateContext(ctx, conn, prepared, state, cfg.Timeout); err != nil {
					res.Error = err.Error()
					return res, err
				}
				res.Sent++
				pendingPeers = append(pendingPeers, msg)
				timing.sent(messageAt, time.Now(), scheduled)
			}
			if turn.closeWrite {
				if paced(cfg.Profile) {
					if err := reader.WaitUntil(ctx, conn, cfg.Adapter, futureResponses, pendingPeers, state, started.Add(turn.closeAt), cfg.Timeout); err != nil {
						return res, err
					}
				}
				closer, ok := conn.(interface{ CloseWrite() error })
				if !ok {
					return res, fmt.Errorf("semantic TCP connection does not support the captured client half-close")
				}
				if err := closer.CloseWrite(); err != nil {
					return res, fmt.Errorf("close semantic TCP write half: %w", err)
				}
				state.Phase = SessionClosed
				state.Transformations = append(state.Transformations, "captured client FIN replayed as a TCP write half-close")
				emitSemanticProgress(cfg, "half-close", "closed the client TCP write half; server responses remain readable")
			}
			if len(expected) > 0 {
				emitSemanticProgress(cfg, "send", fmt.Sprintf("sent %d %s message(s)", len(expected), cfg.Adapter.Name()))
			}
			continue
		}

		actual, rerr := reader.ReadExchange(ctx, conn, cfg.Adapter, expected, pendingPeers, state, cfg.Timeout)
		res.Expected += len(expected)
		res.Received += len(actual)
		if rerr != nil {
			res.Error = rerr.Error()
			return res, rerr
		}
		timing.received(turn.at, time.Now())
		actual, rerr = AlignResponses(cfg.Adapter, expected, actual, state)
		if rerr != nil {
			return res, rerr
		}
		normalizedExpected, normalizeErr := NormalizeExpectedMessages(cfg.Adapter, turn.dir, expected, state)
		if normalizeErr != nil {
			res.Error = normalizeErr.Error()
			return res, normalizeErr
		}
		if cfg.Verify != VerifyOff && len(actual) != len(expected) {
			res.Matched = false
			res.Differences = append(res.Differences, Difference{Field: "message-count", Expected: fmt.Sprint(len(expected)), Actual: fmt.Sprint(len(actual)), Structural: true})
		}
		for i := 0; i < len(normalizedExpected) && i < len(actual); i++ {
			match := cfg.Adapter.Correlate(normalizedExpected[i], actual[i], state)
			if !match.Matched {
				res.Matched = false
				res.Differences = append(res.Differences, Difference{Field: "correlation", Expected: match.Key, Actual: match.Reason, Structural: true})
				return res, fmt.Errorf("response correlation failed: %s", match.Reason)
			} else if err := Observe(cfg.Adapter, ServerToClient, expected[i], actual[i], state); err != nil {
				return res, err
			}
			if ConsumePeers(cfg.Adapter, ServerToClient, actual[i:i+1], 1) > 0 {
				responseOrdinal++
				if err := scenario.After(cfg.Session.ID, responseOrdinal, cfg.Adapter, actual[i]); err != nil {
					return res, err
				}
			}
			if cfg.Verify == VerifyOff {
				continue
			}
			res.Compared++
			diffs := scenario.Compare(cfg.Session.ID, responseOrdinal, cfg.Adapter, normalizedExpected[i], actual[i], cfg.Verify)
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
		if err := RecordOperation(ctx, "ack", res.Received); err != nil {
			return res, err
		}
		pendingPeers = pendingPeers[consumed:]
		futureResponses = futureResponses[len(expected):]
		emitSemanticProgress(cfg, "receive", fmt.Sprintf("received %d %s message(s)", len(actual), cfg.Adapter.Name()))
	}
	res.Completed = true
	return res, nil
}

type semanticTurn struct {
	dir        Direction
	at         time.Duration
	data       []byte
	closeWrite bool
	closeAt    time.Duration
	chunks     []semanticChunk
}

type semanticChunk struct {
	end int
	at  time.Duration
}

func (t semanticTurn) completionAt(end int) time.Duration {
	at := t.at
	for _, chunk := range t.chunks {
		if chunk.at > at {
			at = chunk.at
		}
		if chunk.end >= end {
			break
		}
	}
	return at
}

func semanticAdapterTurns(s *Session, adapter Adapter) ([]semanticTurn, error) {
	turns, err := semanticTurns(s)
	if err != nil {
		return nil, err
	}
	if _, ok := adapter.(ConversationNormalizer); !ok {
		return turns, nil
	}
	var conversation []ConversationTurn
	for _, turn := range turns {
		if len(turn.chunks) == 0 {
			conversation = append(conversation, ConversationTurn{Direction: turn.dir, Payload: turn.data, At: turn.at, CloseWrite: turn.closeWrite, CloseAt: turn.closeAt})
			continue
		}
		start := 0
		for _, chunk := range turn.chunks {
			conversation = append(conversation, ConversationTurn{Direction: turn.dir, Payload: turn.data[start:chunk.end], At: turn.completionAt(chunk.end)})
			start = chunk.end
		}
		if turn.closeWrite {
			conversation = append(conversation, ConversationTurn{Direction: turn.dir, At: turn.closeAt, CloseWrite: true, CloseAt: turn.closeAt})
		}
	}
	conversation, err = NormalizeConversation(adapter, conversation)
	if err != nil {
		return nil, err
	}
	normalized := make([]semanticTurn, len(conversation))
	for i, turn := range conversation {
		normalized[i] = semanticTurn{dir: turn.Direction, data: turn.Payload, at: turn.At, closeWrite: turn.CloseWrite, closeAt: turn.CloseAt}
	}
	return normalized, nil
}

func semanticTurns(s *Session) ([]semanticTurn, error) {
	assembled, fallback, err := assembleTCPStreams(s)
	if err != nil {
		return nil, err
	}
	type captureRun struct {
		direction  Direction
		at         time.Duration
		packets    map[int]bool
		payload    []byte
		closeWrite bool
		closeAt    time.Duration
		chunks     []semanticChunk
	}
	var runs []captureRun
	seenFIN := false
	for _, event := range s.Events {
		closeWrite := false
		if !seenFIN && event.Direction == ClientToServer && event.Record != nil && len(event.Record.Data) > 0 {
			packet, err := wire.Parse(event.Record.Data, event.Record.LinkType)
			if err != nil {
				return nil, err
			}
			closeWrite = packet.IsTCP() && packet.HasFlags(wire.FlagFIN)
			seenFIN = closeWrite
		}
		if len(event.Payload) == 0 && !closeWrite {
			continue
		}
		if len(runs) == 0 || runs[len(runs)-1].direction != event.Direction || runs[len(runs)-1].closeWrite {
			runs = append(runs, captureRun{direction: event.Direction, at: event.At, packets: map[int]bool{}})
		}
		runs[len(runs)-1].packets[event.PacketIndex] = true
		runs[len(runs)-1].closeWrite = closeWrite
		if closeWrite {
			runs[len(runs)-1].closeAt = event.At
		}
		if fallback != nil {
			runs[len(runs)-1].payload = append(runs[len(runs)-1].payload, event.Payload...)
			if len(event.Payload) > 0 {
				runs[len(runs)-1].chunks = append(runs[len(runs)-1].chunks, semanticChunk{end: len(runs[len(runs)-1].payload), at: event.At})
			}
		}
	}
	next := map[Direction]int64{}
	var out []semanticTurn
	writeClosed := false
	for _, run := range runs {
		turn := semanticTurn{dir: run.direction, at: run.at, data: run.payload, closeWrite: run.closeWrite, closeAt: run.closeAt, chunks: run.chunks}
		var segments []tcpPayloadSegment
		for _, segment := range assembled[run.direction].segments {
			if run.packets[segment.packet] {
				segments = append(segments, segment)
			}
		}
		sort.SliceStable(segments, func(i, j int) bool { return segments[i].offset < segments[j].offset })
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
			turn.chunks = append(turn.chunks, semanticChunk{end: len(turn.data), at: segment.at})
			next[run.direction] = end
		}
		if writeClosed && turn.dir == ClientToServer && len(turn.data) > 0 {
			return nil, fmt.Errorf("client TCP payload arrived after FIN; semantic ordering is ambiguous")
		}
		if len(turn.data) > 0 || turn.closeWrite {
			out = append(out, turn)
		}
		writeClosed = writeClosed || turn.closeWrite
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
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		step := time.Now().Add(100 * time.Millisecond)
		if step.After(deadline) {
			step = deadline
		}
		if err := conn.SetWriteDeadline(step); err != nil {
			return fmt.Errorf("set request write deadline: %w", err)
		}
		n, err := conn.Write(data)
		data = data[n:]
		if n == 0 && err == nil {
			return io.ErrNoProgress
		}
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
