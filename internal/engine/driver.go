package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
)

// Outcome summarises a driven conversation.
type Outcome struct {
	ExpectedResponseBytes int
	ObservedResponseBytes int
	ComparedResponseBytes int
	Phase                 Phase
	Aborted               bool
	Reason                string
	Sent                  int
	Retransmits           int
	Log                   []string
	// Mismatches lists reply divergences from the capture (empty unless a Verify
	// mode was set). ReplyMismatches counts the structural ones.
	Mismatches      []Mismatch
	ReplyMismatches int
}

// RepliesMatched reports whether reply verification ran and found no structural
// divergence. It is only meaningful when a Verify mode was configured.
func (o Outcome) RepliesMatched() bool { return o.ReplyMismatches == 0 && len(o.Mismatches) == 0 }

// Succeeded reports that the selected replay completed without an abort.
// RawL4 and captures without teardown do not establish a full TCP close.
func (o Outcome) Succeeded() bool { return o.Phase == PhaseClosed && !o.Aborted }

// Drive bridges the pure Conversation to a concrete PacketBackend: it pumps the
// conversation, sends what it asks, feeds back received frames, and fires the
// retransmit timer on a Recv timeout. maxSteps bounds the loop so a misbehaving
// peer can't hang.
func Drive(c *Conversation, b backend.PacketBackend, maxSteps int) (out Outcome, err error) {
	return DriveContext(context.Background(), c, b, maxSteps)
}

// DriveContext is Drive with prompt cancellation. Receive waits are sliced so
// a stopped web/lab job cannot remain blocked for a full retransmit timeout.
func DriveContext(ctx context.Context, c *Conversation, b backend.PacketBackend, maxSteps int) (out Outcome, err error) {
	var armed bool
	var pending = c.cfg.RTO
	var deadline time.Time
	var wakeArmed bool
	var wakeDeadline time.Time

	// Attach reply-verification results on every return path.
	defer func() {
		if err != nil {
			out.Aborted = true
			out.Reason = err.Error()
		}
		if out.Aborted {
			out.Phase, c.phase = PhaseAborted, PhaseAborted
		}
		if out.Phase == PhaseClosed && !out.Aborted {
			c.verify.finish()
		}
		if c.verify != nil {
			out.ExpectedResponseBytes = len(c.verify.exp)
			out.ObservedResponseBytes = c.verify.contig
			out.ComparedResponseBytes = c.verify.cmpOff
			if c.verify.msgDone > 0 {
				out.ComparedResponseBytes = min(len(c.verify.exp), c.verify.contig)
			}
		}
		out.Mismatches = c.Mismatches()
		for _, m := range out.Mismatches {
			if m.Structural {
				out.ReplyMismatches++
			}
		}
		if c.cfg.Verify == VerifyStrict && out.ReplyMismatches > 0 && !out.Aborted {
			out.Aborted, out.Phase, c.phase = true, PhaseAborted, PhaseAborted
			out.Reason = "live reply diverged from capture"
		}
	}()

	apply := func(acts []Action) bool {
		for _, a := range acts {
			if err := ctx.Err(); err != nil {
				out.Aborted, out.Reason, out.Phase = true, "cancelled", PhaseAborted
				return true
			}
			switch a.Kind {
			case ActSend:
				if err := b.Send(a.Bytes); err != nil {
					out.Aborted, out.Reason = true, "send: "+err.Error()
					return true
				}
				out.Sent++
			case ActArmTimer:
				next := b.Now().Add(a.Delay)
				if !armed || a.Restart || next.Before(deadline) {
					deadline = next
				}
				armed, pending = true, a.Delay
			case ActArmWake:
				wakeArmed, wakeDeadline = true, b.Now().Add(a.Delay)
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
	for step := 0; step < maxSteps; {
		if ctx.Err() != nil {
			out.Aborted, out.Reason, out.Phase = true, "cancelled", PhaseAborted
			return out, nil
		}
		// Service an expired deadline before reading another queued frame.
		// A busy interface can otherwise starve recovery indefinitely even
		// when every received frame is irrelevant to this conversation.
		if armed && !b.Now().Before(deadline) {
			step++
			armed = false
			if apply(c.Poll(Event{Kind: EvTimeout, Now: b.Now()})) {
				out.Phase = c.Phase()
				return out, nil
			}
			continue
		}
		if wakeArmed && !b.Now().Before(wakeDeadline) {
			step++
			wakeArmed = false
			if apply(c.Poll(Event{Kind: EvTick, Now: b.Now()})) {
				out.Phase = c.Phase()
				return out, nil
			}
			continue
		}
		wait := pending
		if !armed || wait > 100*time.Millisecond {
			wait = 100 * time.Millisecond
		}
		if armed {
			remaining := deadline.Sub(b.Now())
			if remaining < wait {
				wait = remaining
			}
		}
		if wakeArmed {
			wait = min(wait, wakeDeadline.Sub(b.Now()))
		}
		if wait <= 0 {
			wait = time.Millisecond
		}
		n, ok, err := b.Recv(buf, wait)
		if err != nil {
			return out, err
		}
		var acts []Action
		switch {
		case ok:
			step++
			// A malformed, unrelated, or duplicate frame can produce no actions.
			// Keep the existing deadline unless the conversation explicitly rearms
			// it; otherwise background traffic disables loss recovery.
			acts = c.Poll(Event{Kind: EvRecv, Frame: append([]byte(nil), buf[:n]...), Now: b.Now()})
		case armed && !b.Now().Before(deadline):
			step++
			armed = false
			acts = c.Poll(Event{Kind: EvTimeout, Now: b.Now()})
		case armed || wakeArmed:
			continue
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
