package engine

import (
	"fmt"
	"strings"

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
}

// Succeeded reports a clean completion (handshake through close, no abort).
func (o Outcome) Succeeded() bool { return o.Phase == PhaseClosed && !o.Aborted }

// Drive bridges the pure Conversation to a concrete PacketBackend: it pumps the
// conversation, sends what it asks, feeds back received frames, and fires the
// retransmit timer on a Recv timeout. maxSteps bounds the loop so a misbehaving
// peer can't hang.
func Drive(c *Conversation, b backend.PacketBackend, maxSteps int) (Outcome, error) {
	var out Outcome
	var armed bool
	var pending = c.cfg.RTO

	apply := func(acts []Action) bool {
		for _, a := range acts {
			switch a.Kind {
			case ActSend:
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
