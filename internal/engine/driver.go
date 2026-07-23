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
	return DriveContext(context.Background(), c, b, maxSteps)
}

// DriveContext is Drive with prompt cancellation. Receive waits are sliced so
// a stopped web/lab job cannot remain blocked for a full retransmit timeout.
func DriveContext(ctx context.Context, c *Conversation, b backend.PacketBackend, maxSteps int) (out Outcome, err error) {
	var armed bool
	var pending = c.cfg.RTO
	var deadline time.Time
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
			if err := ctx.Err(); err != nil {
				out.Aborted, out.Reason, out.Phase = true, "cancelled", PhaseAborted
				return true
			}
			switch a.Kind {
			case ActSend:
				if c.cfg.Pace {
					if paceStart.IsZero() {
						paceStart = b.Now()
					}
					if !preciseWaitContext(ctx, b, paceStart.Add(a.At)) {
						out.Aborted, out.Reason, out.Phase = true, "cancelled", PhaseAborted
						return true
					}
				}
				if err := b.Send(a.Bytes); err != nil {
					out.Aborted, out.Reason = true, "send: "+err.Error()
					return true
				}
				out.Sent++
			case ActArmTimer:
				armed, pending = true, a.Delay
				deadline = b.Now().Add(a.Delay)
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
		if ctx.Err() != nil {
			out.Aborted, out.Reason, out.Phase = true, "cancelled", PhaseAborted
			return out, nil
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
			armed = false
			acts = c.Poll(Event{Kind: EvRecv, Frame: append([]byte(nil), buf[:n]...), Now: b.Now()})
		case armed && !b.Now().Before(deadline):
			armed = false
			acts = c.Poll(Event{Kind: EvTimeout, Now: b.Now()})
		case armed:
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

// preciseWait blocks until the backend clock reaches target. It sleeps for the
// bulk of the wait, then busy-spins the final ~1ms so sub-millisecond
// inter-packet timing lands despite the OS scheduler's coarse sleep resolution
// (notably ~15ms on Windows). A no-op if target is already past.
func preciseWait(b backend.PacketBackend, target time.Time) {
	preciseWaitContext(context.Background(), b, target)
}

func preciseWaitContext(ctx context.Context, b backend.PacketBackend, target time.Time) bool {
	const spin = time.Millisecond
	for {
		d := target.Sub(b.Now())
		if d <= spin {
			break
		}
		chunk := d - spin
		if chunk > 100*time.Millisecond {
			chunk = 100 * time.Millisecond
		}
		t := time.NewTimer(chunk)
		select {
		case <-ctx.Done():
			t.Stop()
			return false
		case <-t.C:
		}
	}
	for b.Now().Before(target) {
		if ctx.Err() != nil {
			return false
		}
	}
	return true
}
