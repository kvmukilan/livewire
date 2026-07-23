// Package livereplay is the shared core of an on-wire stateful replay: open a
// live backend, arm host-RST suppression, and drive the engine against a target.
// Both the CLI and the web dashboard call it.
package livereplay

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/hoststack"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

// Config parameterises one live replay.
type Config struct {
	Flow       *engine.Flow
	Iface      string
	TargetIP   netip.Addr
	TargetPort uint16
	Seed       int64
	NoGuard    bool              // skip host-RST suppression
	Trace      bool              // emit a per-frame TX/RX trace
	Verify     engine.VerifyMode // check live replies against the capture
	Adaptive   bool              // re-anchor the ACK clock on the live server's real output
	Pace       bool              // reproduce the capture's original inter-packet timing
	RawL4      bool              // replay the client's frames exactly as captured (no response gating)
}

type replayGuard interface {
	Release() error
	Describe() string
}

type runDependencies struct {
	openLive func(backend.LiveConfig) (*backend.LiveBackend, error)
	armGuard func(hoststack.Rule) (replayGuard, error)
	drive    func(context.Context, *engine.Flow, engine.Options, engine.ConvConfig, backend.PacketBackend) (engine.Outcome, uint32, error)
}

func defaultRunDependencies() runDependencies {
	return runDependencies{
		openLive: backend.OpenLive,
		armGuard: func(rule hoststack.Rule) (replayGuard, error) {
			return hoststack.Arm(rule)
		},
		drive: func(ctx context.Context, flow *engine.Flow, opts engine.Options, cfg engine.ConvConfig, b backend.PacketBackend) (engine.Outcome, uint32, error) {
			conv, err := engine.NewConversation(flow, opts, cfg)
			if err != nil {
				return engine.Outcome{}, 0, err
			}
			out, err := engine.DriveContext(ctx, conv, b, 10000)
			return out, conv.LearnedServerISN(), err
		},
	}
}

// Result reports the outcome of a replay.
type Result struct {
	Outcome          engine.Outcome
	LearnedServerISN uint32
	GuardArmed       bool
	Verified         bool
	Matched          bool
	// Evidence is the actual post-rewrite TX and live RX traffic observed by the
	// replay backend. Callers can persist it as a pcap for an auditable run.
	Evidence []pcapio.Record
}

type evidenceBackend struct {
	backend.PacketBackend
	link   wire.LinkType
	frames []pcapio.Record
}

func (e *evidenceBackend) record(frame []byte) {
	b := append([]byte(nil), frame...)
	e.frames = append(e.frames, pcapio.Record{
		Time: e.Now(), CapLen: len(b), OrigLen: len(b), Data: b, LinkType: e.link,
	})
}

func (e *evidenceBackend) Send(frame []byte) error {
	if err := e.PacketBackend.Send(frame); err != nil {
		return err
	}
	e.record(frame)
	return nil
}

func (e *evidenceBackend) Recv(buf []byte, timeout time.Duration) (int, bool, error) {
	n, ok, err := e.PacketBackend.Recv(buf, timeout)
	if err == nil && ok {
		e.record(buf[:n])
	}
	return n, ok, err
}

// SendStateless blasts a flow's captured frames onto the wire as-is, retargeting
// only the layer-2 addresses. Used for flows that can't be replayed statefully
// (no handshake to anchor). The device won't form a connection from these — they
// carry mid-stream sequence numbers — but the frames go out.
func SendStateless(cfg Config, log func(string)) error {
	f := cfg.Flow
	if f == nil {
		return fmt.Errorf("livereplay: nil flow")
	}
	lb, err := backend.OpenLive(backend.LiveConfig{
		Iface: cfg.Iface, Target: cfg.TargetIP, TargetPort: cfg.TargetPort, LocalPort: f.Client.Port, Promisc: true,
	})
	if err != nil {
		return err
	}
	defer lb.Backend.Close()
	b := backend.NewMACRewriter(lb.Backend, lb.LocalMAC, lb.NextHopMAC)
	n := 0
	for _, cp := range f.Packets {
		if err := b.Send(cp.Rec.Data); err != nil {
			return err
		}
		n++
	}
	log(fmt.Sprintf("stateless: sent %d frame(s)", n))
	return nil
}

// Run executes a stateful replay of cfg.Flow against the live target, sending
// progress and trace lines to log. It arms and releases the RST-suppression guard.
func Run(cfg Config, log func(string)) (Result, error) {
	return RunContext(context.Background(), cfg, log)
}

// RunContext executes a replay with cancellation propagated into the engine.
func RunContext(ctx context.Context, cfg Config, log func(string)) (Result, error) {
	return runContextWithDependencies(ctx, cfg, log, defaultRunDependencies())
}

func runContextWithDependencies(ctx context.Context, cfg Config, log func(string), deps runDependencies) (Result, error) {
	if log == nil {
		log = func(string) {}
	}
	f := cfg.Flow
	if f == nil {
		return Result{}, fmt.Errorf("livereplay: nil flow")
	}
	if !f.HasSyn || !f.HasSynAck {
		sf, serr := engine.SynthesizeHandshake(f)
		if serr != nil {
			return Result{}, fmt.Errorf("flow lacks a handshake and one can't be synthesized: %w", serr)
		}
		log("no handshake in capture; synthesizing a SYN to open the connection (experimental)")
		f = sf
	}
	localPort := f.Client.Port
	log(fmt.Sprintf("live stateful replay: %s -> %s:%d on %s", f.Client, cfg.TargetIP, cfg.TargetPort, cfg.Iface))

	lb, err := deps.openLive(backend.LiveConfig{
		Iface: cfg.Iface, Target: cfg.TargetIP, TargetPort: cfg.TargetPort, LocalPort: localPort, Promisc: true,
	})
	if err != nil {
		return Result{}, err
	}
	defer lb.Backend.Close()
	if caps := lb.Backend.Caps(); !caps.Has(backend.CanReceive | backend.StatefulSafe) {
		return Result{}, fmt.Errorf("backend lacks CanReceive|StatefulSafe; stateful replay cannot proceed")
	}

	var res Result
	if !cfg.NoGuard {
		guard, gerr := deps.armGuard(hoststack.Rule{TargetIP: cfg.TargetIP, TargetPort: cfg.TargetPort, LocalPort: localPort})
		if gerr != nil {
			return Result{}, fmt.Errorf("host-RST suppression failed (%w); retry with the guard disabled to bypass "+
				"(the host kernel may then reset the connection)", gerr)
		}
		defer guard.Release()
		log("host-RST suppression armed: " + guard.Describe())
		res.GuardArmed = true
	} else {
		log("host-RST suppression DISABLED (-no-rst-guard): the host kernel may reset the connection")
	}

	var wireBackend backend.PacketBackend = backend.NewMACRewriter(lb.Backend, lb.LocalMAC, lb.NextHopMAC)
	evidence := &evidenceBackend{PacketBackend: wireBackend, link: wireBackend.LinkType()}
	var b backend.PacketBackend = backend.NewTupleRewriter(evidence, backend.TupleRewrite{
		CapturedClient: backend.TupleEndpoint{IP: f.Client.Addr, Port: f.Client.Port},
		CapturedServer: backend.TupleEndpoint{IP: f.Server.Addr, Port: f.Server.Port},
		LiveClient:     backend.TupleEndpoint{IP: lb.LocalIP, Port: f.Client.Port},
		LiveServer:     backend.TupleEndpoint{IP: cfg.TargetIP, Port: cfg.TargetPort},
	})
	if cfg.Trace {
		b = newTracer(b, log)
	}

	if cfg.Verify != engine.VerifyOff {
		log("reply verification: " + cfg.Verify.String() + " (waiting for and checking server replies against the capture)")
	}
	if cfg.Adaptive {
		log("adaptive clock: acking the live server's real output; a shorter/longer reply than the capture won't stall the flow")
	}
	if cfg.Pace {
		log("pacing: reproducing the capture's original inter-packet timing")
	}
	if cfg.RawL4 {
		log("raw-L4: replaying the client's frames exactly as captured (retransmits, RSTs, original acks)")
	}
	out, learnedServerISN, err := deps.drive(ctx, f, engine.Options{Seed: cfg.Seed},
		engine.ConvConfig{Verify: cfg.Verify, Adaptive: cfg.Adaptive, Pace: cfg.Pace, RawL4: cfg.RawL4}, b)
	if err != nil {
		return Result{}, err
	}
	res.Outcome = out
	res.LearnedServerISN = learnedServerISN
	res.Evidence = evidence.frames
	res.Verified = cfg.Verify != engine.VerifyOff
	res.Matched = res.Verified && out.RepliesMatched()

	for _, line := range out.Log {
		log("  " + line)
	}
	if out.Succeeded() {
		log(fmt.Sprintf("SUCCESS: handshake-through-close completed; %d frames sent, %d retransmits", out.Sent, out.Retransmits))
	} else {
		log(fmt.Sprintf("replay ended in phase %s: %s (sent %d frames)", out.Phase, out.Reason, out.Sent))
	}
	if cfg.Verify != engine.VerifyOff {
		if out.RepliesMatched() {
			log(fmt.Sprintf("reply check: replies matched the capture (%d divergence note(s))", len(out.Mismatches)-out.ReplyMismatches))
		} else {
			log(fmt.Sprintf("reply check: %d structural divergence(s) from the capture", out.ReplyMismatches))
		}
	}
	return res, nil
}
