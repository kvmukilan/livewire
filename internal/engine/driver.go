package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
)

// Outcome summarises a driven conversation.
type Outcome struct {
	Phase       Phase
	Aborted     bool
	Reason      string
	Sent        int
	Retransmits int
	Log         []string
	// Mismatches lists reply divergences from the capture (empty unless a Verify
	// mode was set). ReplyMismatches counts the structural ones.
	Mismatches      []Mismatch
	ReplyMismatches int
}

// RepliesMatched reports whether reply verification ran and found no structural
// divergence. It is only meaningful when a Verify mode was configured.
func (o Outcome) RepliesMatched() bool { return o.ReplyMismatches == 0 }

// Succeeded reports a clean completion (handshake through close, no abort).
func (o Outcome) Succeeded() bool { return o.Phase == PhaseClosed && !o.Aborted }

// Drive bridges the pure Conversation to a concrete PacketBackend: it pumps the
// conversation, sends what it asks, feeds back received frames, and fires the
// retransmit timer on a Recv timeout. maxSteps bounds the loop so a misbehaving
// peer can't hang.
func Drive(c *Conversation, b backend.PacketBackend, maxSteps int) (out Outcome, err error) {
	var armed bool
	var pending = c.cfg.RTO
	var paceStart time.Time // wall clock of the first paced send

	// Attach reply-verification results on every return path.
	defer func() {
		out.Mismatches = c.Mismatches()
		for _, m := range out.Mismatches {
			if m.Structural {
				out.ReplyMismatches++
			}
		}
	}()

	apply := func(acts []Action) bool {
		for _, a := range acts {
			switch a.Kind {
			case ActSend:
				if c.cfg.Pace {
					if paceStart.IsZero() {
						paceStart = b.Now()
					}
					preciseWait(b, paceStart.Add(a.At))
				}
				if err := b.Send(a.Bytes); err != nil {
					out.Aborted, out.Reason = true, "send: "+err.Error()
					return true
				}
				out.Sent++
			case ActArmTimer:
				armed, pending = true, a.Delay
			case ActLog:
				out.Log = append(out.Log, a.Reason)
				if strings.HasPrefix(a.Reason, "retransmit") {
					out.Retransmits++
				}
			case ActDone:
				out.Phase = PhaseClosed
				return true
			case ActAbort:
				out.Aborted, out.Reason = true, a.Reason
				out.Phase = PhaseAborted
				return true
			}
		}
		return false
	}

	if apply(c.Poll(Event{Kind: EvStart, Now: b.Now()})) {
		out.Phase = c.Phase()
		return out, nil
	}

	buf := make([]byte, 64*1024)
	for step := 0; step < maxSteps; step++ {
		n, ok, err := b.Recv(buf, pending)
		if err != nil {
			return out, err
		}
		var acts []Action
		switch {
		case ok:
			armed = false
			acts = c.Poll(Event{Kind: EvRecv, Frame: append([]byte(nil), buf[:n]...), Now: b.Now()})
		case armed:
			armed = false
			acts = c.Poll(Event{Kind: EvTimeout, Now: b.Now()})
		default:
			// Nothing to receive and no timer armed: wedged.
			out.Aborted, out.Reason = true, fmt.Sprintf("stalled in phase %s", c.Phase())
			out.Phase = c.Phase()
			return out, nil
		}
		if apply(acts) {
			out.Phase = c.Phase()
			return out, nil
		}
	}
	out.Aborted, out.Reason = true, fmt.Sprintf("exceeded %d steps", maxSteps)
	out.Phase = c.Phase()
	return out, nil
}

// preciseWait blocks until the backend clock reaches target. It sleeps for the
// bulk of the wait, then busy-spins the final ~1ms so sub-millisecond
// inter-packet timing lands despite the OS scheduler's coarse sleep resolution
// (notably ~15ms on Windows). A no-op if target is already past.
func preciseWait(b backend.PacketBackend, target time.Time) {
	const spin = time.Millisecond
	if d := target.Sub(b.Now()); d > spin {
		time.Sleep(d - spin)
	}
	for b.Now().Before(target) {
		// busy-wait the remainder
	}
}
