package replay

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

type ProgressEvent struct {
	SessionID string    `json:"sessionId"`
	Stage     string    `json:"stage"`
	Message   string    `json:"message"`
	At        time.Time `json:"at"`
}

type TransportRunConfig struct {
	Session    *Session
	Iface      string
	TargetIP   netip.Addr
	TargetPort uint16
	Profile    Profile
	Verify     VerifyMode
	Timeout    time.Duration
	Start      time.Time
	Adapter    Adapter
	Variables  map[string]string
	Progress   func(ProgressEvent)
}

type TransportResult struct {
	SessionID   string          `json:"sessionId"`
	Mode        Mode            `json:"mode"`
	Fidelity    Fidelity        `json:"fidelity"`
	Completed   bool            `json:"completed"`
	Verified    bool            `json:"verified"`
	Matched     bool            `json:"matched"`
	Sent        int             `json:"sent"`
	Received    int             `json:"received"`
	Differences []Difference    `json:"differences,omitempty"`
	Evidence    []pcapio.Record `json:"-"`
	Error       string          `json:"error,omitempty"`
}

func (r TransportResult) Succeeded() bool { return r.Completed && r.Error == "" }

// RunTransportContext opens the configured interface and drives one UDP or
// ICMP session. TCP continues through livereplay's richer state machine.
func RunTransportContext(ctx context.Context, cfg TransportRunConfig) (TransportResult, error) {
	if cfg.Session == nil {
		return TransportResult{}, fmt.Errorf("replay: nil session")
	}
	proto, icmpID, err := sessionProtocol(cfg.Session)
	if err != nil {
		return TransportResult{}, err
	}
	port := cfg.TargetPort
	if port == 0 {
		port = cfg.Session.Server.Port
	}
	lb, err := backend.OpenLive(backend.LiveConfig{
		Iface: cfg.Iface, Target: cfg.TargetIP, TargetPort: port,
		LocalPort: cfg.Session.Client.Port, Protocol: proto, ICMPID: icmpID, Promisc: true,
	})
	if err != nil {
		return TransportResult{}, err
	}
	defer lb.Backend.Close()
	return RunTransportWithBackendContext(ctx, cfg, lb)
}

// RunTransportWithBackendContext is the injectable core used by CI and the lab
// harness. The supplied backend is closed by its owner.
func RunTransportWithBackendContext(ctx context.Context, cfg TransportRunConfig, lb *backend.LiveBackend) (TransportResult, error) {
	s := cfg.Session
	if s == nil || lb == nil || lb.Backend == nil {
		return TransportResult{}, fmt.Errorf("replay: session and live backend are required")
	}
	if s.Transport != TransportUDP && s.Transport != TransportICMP4 && s.Transport != TransportICMP6 {
		return TransportResult{}, fmt.Errorf("replay: transport runner does not handle %s", s.Transport)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	port := cfg.TargetPort
	if port == 0 {
		port = s.Server.Port
	}
	mode, fidelity := ModeStateful, FidelityTransport
	if cfg.Adapter != nil && cfg.Profile != ProfileWire {
		mode, fidelity = ModeSemantic, FidelitySemantic
	}
	verified := cfg.Verify != VerifyOff
	res := TransportResult{SessionID: s.ID, Mode: mode, Fidelity: fidelity, Verified: verified, Matched: verified}

	var wireBackend backend.PacketBackend = backend.NewMACRewriter(lb.Backend, lb.LocalMAC, lb.NextHopMAC)
	recorder := &recordingBackend{PacketBackend: wireBackend, link: wireBackend.LinkType()}
	b := backend.NewTupleRewriter(recorder, backend.TupleRewrite{
		CapturedClient: backend.TupleEndpoint{IP: s.Client.IP, Port: s.Client.Port},
		CapturedServer: backend.TupleEndpoint{IP: s.Server.IP, Port: s.Server.Port},
		LiveClient:     backend.TupleEndpoint{IP: lb.LocalIP, Port: s.Client.Port},
		LiveServer:     backend.TupleEndpoint{IP: cfg.TargetIP, Port: port},
	})
	state := &RuntimeState{Variables: copyVariables(cfg.Variables), Learned: map[string][]byte{}}
	start := cfg.Start
	if start.IsZero() {
		start = b.Now()
	}
	for _, ev := range s.Events {
		if ev.Fragmented && len(ev.Reassembled) == 0 {
			continue
		}
		if ctx.Err() != nil {
			res.Error = "cancelled"
			res.Evidence = recorder.frames
			return res, ctx.Err()
		}
		if ev.Direction == ClientToServer {
			if paced(cfg.Profile) && !waitUntil(ctx, b, start.Add(ev.At)) {
				res.Error = "cancelled"
				res.Evidence = recorder.frames
				return res, ctx.Err()
			}
			frame := transportEventFrame(ev)
			if cfg.Adapter != nil && cfg.Profile != ProfileWire {
				prepared, perr := preparePayload(frame, ev.Record.LinkType, ev.Direction, cfg.Adapter, state)
				if perr != nil {
					res.Error = perr.Error()
					return res, perr
				}
				frame = prepared
			}
			if err := b.Send(frame); err != nil {
				res.Error = err.Error()
				res.Evidence = recorder.frames
				return res, err
			}
			res.Sent++
			emitProgress(cfg, "send", fmt.Sprintf("sent packet %d", ev.PacketIndex))
			continue
		}
		if ev.Direction != ServerToClient {
			continue
		}
		buf := make([]byte, 64*1024)
		n, ok, err := recvContext(ctx, b, buf, cfg.Timeout)
		if err != nil {
			res.Error = err.Error()
			res.Evidence = recorder.frames
			return res, err
		}
		if !ok {
			res.Matched = false
			res.Differences = append(res.Differences, Difference{Field: "response", Expected: fmt.Sprintf("packet %d", ev.PacketIndex), Actual: "timeout", Structural: true})
			if cfg.Verify == VerifyStrict {
				res.Error = "live peer response timed out"
				res.Evidence = recorder.frames
				return res, fmt.Errorf("%s", res.Error)
			}
			continue
		}
		res.Received++
		diffs := compareFramePayload(ev, buf[:n], cfg.Adapter, state, cfg.Verify)
		if len(diffs) > 0 {
			res.Matched = false
			res.Differences = append(res.Differences, diffs...)
			if cfg.Verify == VerifyStrict {
				res.Error = "live peer response differs from capture"
				res.Evidence = recorder.frames
				return res, fmt.Errorf("%s", res.Error)
			}
		}
		emitProgress(cfg, "receive", fmt.Sprintf("received response for packet %d", ev.PacketIndex))
	}
	res.Completed = true
	res.Evidence = recorder.frames
	return res, nil
}

func sessionProtocol(s *Session) (uint8, uint16, error) {
	switch s.Transport {
	case TransportUDP:
		return wire.ProtoUDP, 0, nil
	case TransportICMP4:
		return wire.ProtoICMPv4, firstICMPID(s), nil
	case TransportICMP6:
		return wire.ProtoICMPv6, firstICMPID(s), nil
	default:
		return 0, 0, fmt.Errorf("replay: unsupported live transport %s", s.Transport)
	}
}

func firstICMPID(s *Session) uint16 {
	for _, e := range s.Events {
		frame := transportEventFrame(e)
		if p, err := wire.Parse(frame, e.Record.LinkType); err == nil {
			_, id, _, ok := p.ICMPEcho()
			if ok {
				return id
			}
		}
	}
	return 0
}

func transportEventFrame(e Event) []byte {
	if len(e.Reassembled) > 0 {
		return append([]byte(nil), e.Reassembled...)
	}
	if e.Record == nil {
		return nil
	}
	return append([]byte(nil), e.Record.Data...)
}

type recordingBackend struct {
	backend.PacketBackend
	link   wire.LinkType
	frames []pcapio.Record
}

func (r *recordingBackend) record(frame []byte) {
	b := append([]byte(nil), frame...)
	r.frames = append(r.frames, pcapio.Record{Time: r.Now(), CapLen: len(b), OrigLen: len(b), Data: b, LinkType: r.link})
}
func (r *recordingBackend) Send(frame []byte) error {
	if err := r.PacketBackend.Send(frame); err != nil {
		return err
	}
	r.record(frame)
	return nil
}
func (r *recordingBackend) Recv(buf []byte, timeout time.Duration) (int, bool, error) {
	n, ok, err := r.PacketBackend.Recv(buf, timeout)
	if err == nil && ok {
		r.record(buf[:n])
	}
	return n, ok, err
}

func recvContext(ctx context.Context, b backend.PacketBackend, buf []byte, timeout time.Duration) (int, bool, error) {
	deadline := b.Now().Add(timeout)
	for {
		if err := ctx.Err(); err != nil {
			return 0, false, err
		}
		remaining := deadline.Sub(b.Now())
		if remaining <= 0 {
			return 0, false, nil
		}
		if remaining > 100*time.Millisecond {
			remaining = 100 * time.Millisecond
		}
		n, ok, err := b.Recv(buf, remaining)
		if err != nil || ok {
			return n, ok, err
		}
	}
}

func paced(p Profile) bool { return p == ProfileTiming || p == ProfileTransport || p == ProfileWire }

func waitUntil(ctx context.Context, b backend.PacketBackend, target time.Time) bool {
	for b.Now().Before(target) {
		d := target.Sub(b.Now())
		if d > 100*time.Millisecond {
			d = 100 * time.Millisecond
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return false
		case <-t.C:
		}
	}
	return true
}

func preparePayload(frame []byte, link wire.LinkType, dir Direction, a Adapter, state *RuntimeState) ([]byte, error) {
	p, err := wire.Parse(frame, link)
	if err != nil {
		return nil, err
	}
	msgs, err := a.Decode(dir, p.Payload())
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return frame, nil
	}
	var payload []byte
	for _, m := range msgs {
		b, err := a.Prepare(dir, m, state)
		if err != nil {
			return nil, err
		}
		payload = append(payload, b...)
	}
	return p.RebuildWithPayload(payload), nil
}

func compareFramePayload(expected Event, actual []byte, a Adapter, state *RuntimeState, mode VerifyMode) []Difference {
	ep, eerr := wire.Parse(transportEventFrame(expected), expected.Record.LinkType)
	ap, aerr := wire.Parse(actual, expected.Record.LinkType)
	if eerr != nil || aerr != nil {
		return []Difference{{Field: "frame", Expected: "parseable", Actual: "unparseable", Structural: true}}
	}
	if mode == VerifyOff {
		return nil
	}
	if a == nil {
		if ep.IsICMP() || ap.IsICMP() {
			expectedRequest, expectedID, expectedSeq, expectedOK := ep.ICMPEcho()
			actualRequest, actualID, actualSeq, actualOK := ap.ICMPEcho()
			var out []Difference
			if !expectedOK || !actualOK || expectedRequest != actualRequest {
				out = append(out, Difference{Field: "icmp.type", Expected: echoKind(expectedRequest, expectedOK), Actual: echoKind(actualRequest, actualOK), Structural: true})
			}
			if expectedID != actualID {
				out = append(out, Difference{Field: "icmp.identifier", Expected: fmt.Sprint(expectedID), Actual: fmt.Sprint(actualID), Structural: true})
			}
			if expectedSeq != actualSeq {
				out = append(out, Difference{Field: "icmp.sequence", Expected: fmt.Sprint(expectedSeq), Actual: fmt.Sprint(actualSeq), Structural: true})
			}
			if !bytes.Equal(ep.Payload(), ap.Payload()) {
				out = append(out, Difference{Field: "icmp.payload", Expected: fmt.Sprintf("%d bytes", len(ep.Payload())), Actual: fmt.Sprintf("%d bytes", len(ap.Payload())), Structural: len(ep.Payload()) != len(ap.Payload())})
			}
			return out
		}
		if bytes.Equal(ep.Payload(), ap.Payload()) {
			return nil
		}
		return []Difference{{Field: "payload", Expected: fmt.Sprintf("%d bytes", len(ep.Payload())), Actual: fmt.Sprintf("%d bytes", len(ap.Payload())), Structural: len(ep.Payload()) != len(ap.Payload())}}
	}
	exp, err := a.Decode(ServerToClient, ep.Payload())
	if err != nil {
		return []Difference{{Field: "adapter", Expected: "decodable captured response", Actual: err.Error(), Structural: true}}
	}
	got, err := a.Decode(ServerToClient, ap.Payload())
	if err != nil {
		return []Difference{{Field: "adapter", Expected: "decodable live response", Actual: err.Error(), Structural: true}}
	}
	if len(exp) != len(got) {
		return []Difference{{Field: "message-count", Expected: fmt.Sprint(len(exp)), Actual: fmt.Sprint(len(got)), Structural: true}}
	}
	exp, err = NormalizeExpectedMessages(a, ServerToClient, exp, state)
	if err != nil {
		return []Difference{{Field: "adapter", Expected: "normalizable captured response", Actual: err.Error(), Structural: true}}
	}
	var out []Difference
	for i := range exp {
		m := a.Correlate(exp[i], got[i], state)
		if !m.Matched {
			out = append(out, Difference{Field: "correlation", Expected: exp[i].String(), Actual: got[i].String(), Structural: true})
		}
		out = append(out, a.Compare(exp[i], got[i], mode)...)
	}
	return out
}

func echoKind(request, ok bool) string {
	if !ok {
		return "not-echo"
	}
	if request {
		return "request"
	}
	return "reply"
}

func emitProgress(cfg TransportRunConfig, stage, msg string) {
	if cfg.Progress != nil {
		cfg.Progress(ProgressEvent{SessionID: cfg.Session.ID, Stage: stage, Message: msg, At: time.Now()})
	}
}
func copyVariables(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
