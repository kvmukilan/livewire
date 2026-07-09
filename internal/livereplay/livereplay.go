// Package livereplay is the shared core of an on-wire stateful replay: open a
// live backend, arm host-RST suppression, and drive the engine against a target.
// Both the CLI and the web dashboard call it.
package livereplay

import (
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/hoststack"
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

// Result reports the outcome of a replay.
type Result struct {
	Outcome          engine.Outcome
	LearnedServerISN uint32
	GuardArmed       bool
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

	lb, err := backend.OpenLive(backend.LiveConfig{
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
		guard, gerr := hoststack.Arm(hoststack.Rule{TargetIP: cfg.TargetIP, TargetPort: cfg.TargetPort, LocalPort: localPort})
		if gerr != nil {
			return Result{}, fmt.Errorf("host-RST suppression failed (%w); retry with the guard disabled to bypass "+
				"(the host kernel may then reset the connection)", gerr)
		}
		log("host-RST suppression armed: " + guard.Describe())
		res.GuardArmed = true
		defer guard.Release()
		// Signals bypass defers, so release the guard on SIGINT/SIGTERM too —
		// a leaked rule would break the host's own later connections.
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(stop)
		go func() {
			if _, ok := <-stop; ok {
				guard.Release()
				os.Exit(130)
			}
		}()
	} else {
		log("host-RST suppression DISABLED (-no-rst-guard): the host kernel may reset the connection")
	}

	var b backend.PacketBackend = backend.NewMACRewriter(lb.Backend, lb.LocalMAC, lb.NextHopMAC)
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
	conv, err := engine.NewConversation(f, engine.Options{Seed: cfg.Seed},
		engine.ConvConfig{Verify: cfg.Verify, Adaptive: cfg.Adaptive, Pace: cfg.Pace, RawL4: cfg.RawL4})
	if err != nil {
		return Result{}, err
	}
	out, err := engine.Drive(conv, b, 10000)
	if err != nil {
		return Result{}, err
	}
	res.Outcome = out
	res.LearnedServerISN = conv.LearnedServerISN()

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
