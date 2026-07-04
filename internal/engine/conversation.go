package engine

import (
	"fmt"
	"time"

	"github.com/kvmukilan/livewire/internal/units"
	"github.com/kvmukilan/livewire/internal/wire"
)

// Phase is a conversation's position in the connection lifecycle.
type Phase uint8

const (
	PhaseInit        Phase = iota // before the SYN is sent
	PhaseSynSent                  // SYN sent, awaiting live SYN-ACK
	PhaseEstablished              // handshake done, data flowing
	PhaseClosing                  // our FIN sent, awaiting peer FIN
	PhaseClosed                   // replayed to completion
	PhaseAborted                  // ended early (RST or budget exhausted)
)

func (p Phase) String() string {
	switch p {
	case PhaseInit:
		return "init"
	case PhaseSynSent:
		return "syn-sent"
	case PhaseEstablished:
		return "established"
	case PhaseClosing:
		return "closing"
	case PhaseClosed:
		return "closed"
	case PhaseAborted:
		return "aborted"
	}
	return "?"
}

// EventKind tags an input to the conversation transducer.
type EventKind uint8

const (
	EvStart   EventKind = iota // kick off the replay (send the SYN)
	EvRecv                     // frame received from the live peer
	EvTimeout                  // armed retransmit timer elapsed
	EvTick                     // clock update without a frame (unused by the mock path)
)

// Event is one input to Poll.
type Event struct {
	Kind  EventKind
	Frame []byte
	Now   time.Time
}

// ActionKind tags an output the driver must carry out.
type ActionKind uint8

const (
	ActSend     ActionKind = iota // transmit Bytes on the backend
	ActArmTimer                   // schedule an EvTimeout after Delay
	ActLog                        // progress note
	ActDone                       // replay completed
	ActAbort                      // ended early; Reason explains why
)

// Action is one output from Poll.
type Action struct {
	Kind   ActionKind
	Bytes  []byte
	Delay  time.Duration
	Reason string
}

// ConvConfig tunes retransmission behaviour.
type ConvConfig struct {
	// ResendBudget caps retransmits of a stalled segment before aborting. Zero uses DefaultResendBudget.
	ResendBudget int
	// RTO is the base retransmit timeout; it doubles per resend. Zero uses DefaultRTO.
	RTO time.Duration
}

const (
	DefaultResendBudget = 5
	DefaultRTO          = 200 * time.Millisecond
)

// Conversation is the closed-loop, ACK-clocked replay state machine: it learns
// the live server ISN from the SYN-ACK, gates client packets on delivered bytes,
// and retransmits on loss. Poll is pure (no I/O). Byte accounting is by
// cumulative contiguous position in server sequence space, not packet index, so
// a peer that re-segments differently (MSS/TSO/GRO) stays in sync.
type Conversation struct {
	flow *Flow
	sess *Session
	link wire.LinkType
	cfg  ConvConfig

	phase Phase
	ci    int // index of the next captured packet to process

	// serverRcvd is the next contiguous sequence expected from the server;
	// everything below it has been delivered. Gates client packets.
	serverRcvd  units.Seq
	serverKnown bool

	// lastData is the last sequence-consuming client frame sent; a retransmit
	// re-sends exactly this. resends counts consecutive retransmits, rto is its
	// current backed-off timeout.
	lastData []byte
	resends  int
	rto      time.Duration
}

// NewConversation builds a conversation for a captured flow. The flow must
// contain a full handshake; the server ISN is learned from the wire, not supplied.
func NewConversation(f *Flow, opts Options, cfg ConvConfig) (*Conversation, error) {
	if !f.HasSyn || !f.HasSynAck {
		return nil, errNoHandshake(f)
	}
	if len(f.Packets) == 0 {
		return nil, fmt.Errorf("flow %s has no packets", f.Key)
	}
	if cfg.ResendBudget == 0 {
		cfg.ResendBudget = DefaultResendBudget
	}
	if cfg.RTO == 0 {
		cfg.RTO = DefaultRTO
	}
	cISN, _, tsC, tsS := opts.isns()
	return &Conversation{
		flow:  f,
		sess:  NewSession(f, units.Seq(cISN), tsC, tsS), // server ISN learned later
		link:  f.Packets[0].Rec.LinkType,
		cfg:   cfg,
		phase: PhaseInit,
		rto:   cfg.RTO,
	}, nil
}

// Phase reports the current lifecycle phase.
func (c *Conversation) Phase() Phase { return c.phase }

// LearnedServerISN returns the server ISN recovered from the SYN-ACK, or 0 if not yet known.
func (c *Conversation) LearnedServerISN() uint32 {
	if !c.serverKnown {
		return 0
	}
	return c.sess.LiveServerISN.Uint32()
}

// Poll advances the state machine by one event and returns the driver's actions.
func (c *Conversation) Poll(ev Event) []Action {
	switch ev.Kind {
	case EvStart:
		if c.phase != PhaseInit {
			return nil
		}
		return c.pump()
	case EvRecv:
		return c.onRecv(ev.Frame)
	case EvTimeout:
		return c.onTimeout()
	default:
		return nil
	}
}

// pump sends every client packet whose gate is open and skips already-delivered
// server packets, until it blocks on the peer (arming a timer) or reaches the end.
func (c *Conversation) pump() []Action {
	var acts []Action
	for c.ci < len(c.flow.Packets) {
		cp := c.flow.Packets[c.ci]

		if cp.Dir == S2C {
			// Server packet: wait for it rather than send it. Advance only once the
			// server has delivered through its end.
			if c.serverKnown && c.serverRcvd.GreaterEqual(c.serverEnd(cp)) {
				c.ci++
				continue
			}
			return append(acts, c.armWait())
		}

		// Client packet: gate on the server having delivered everything it acks.
		// The byte-count clock, independent of how the server segmented.
		if c.serverKnown && cp.Ack {
			liveAck := cp.AckN.AddDelta(c.sess.ServerDelta)
			if c.serverRcvd.Less(liveAck) {
				return append(acts, c.armWait())
			}
		}

		buf, _, err := c.sess.Rewrite(cp)
		if err != nil {
			c.phase = PhaseAborted
			return append(acts, Action{Kind: ActAbort, Reason: "rewrite: " + err.Error()})
		}
		acts = append(acts, Action{Kind: ActSend, Bytes: buf})
		if cp.SegLen > 0 { // SYN/FIN/data consume sequence space, retransmittable
			c.lastData = buf
			c.resends = 0
			c.rto = c.cfg.RTO
		}
		switch {
		case cp.IsSyn:
			c.phase = PhaseSynSent
		case cp.IsFin:
			c.phase = PhaseClosing
		}
		c.ci++
	}
	c.phase = PhaseClosed
	return append(acts, Action{Kind: ActDone})
}

// onRecv folds a received frame in: learn the server ISN from the SYN-ACK,
// advance serverRcvd for in-order data, abort on RST.
func (c *Conversation) onRecv(frame []byte) []Action {
	p, err := wire.Parse(frame, c.link)
	if err != nil || !p.IsTCP() {
		return nil // ignore non-TCP
	}
	if p.HasFlags(wire.FlagRST) {
		c.phase = PhaseAborted
		return []Action{{Kind: ActAbort, Reason: "peer sent RST"}}
	}

	if !c.serverKnown && p.HasFlags(wire.FlagSYN) && p.HasFlags(wire.FlagACK) {
		// Recover the server's ISN and pin the server-space delta. The SYN
		// consumes one sequence number, so the next byte is ISN+1.
		c.sess.LearnServerISN(p.Seq())
		c.serverKnown = true
		c.serverRcvd = c.sess.LiveServerISN.Add(1)
		c.phase = PhaseEstablished
		return c.pump()
	}

	if c.serverKnown {
		// Advance the contiguous delivery watermark. Accept in-order segments and
		// overlaps that extend it; ignore out-of-order future segments (our peers
		// never produce holes).
		seq := p.Seq()
		end := seq.Add(p.SegmentLen())
		if seq.LessEqual(c.serverRcvd) && end.Greater(c.serverRcvd) {
			c.serverRcvd = end
		}
	}
	return c.pump()
}

// onTimeout retransmits the last sequence-consuming client frame with RTO
// backoff, or aborts once the resend budget is spent.
func (c *Conversation) onTimeout() []Action {
	if c.phase == PhaseClosed || c.phase == PhaseAborted {
		return nil
	}
	if c.lastData == nil {
		return []Action{c.armWait()}
	}
	if c.resends >= c.cfg.ResendBudget {
		c.phase = PhaseAborted
		return []Action{{Kind: ActAbort,
			Reason: fmt.Sprintf("no progress after %d retransmits", c.resends)}}
	}
	c.resends++
	c.rto *= 2
	return []Action{
		{Kind: ActLog, Reason: fmt.Sprintf("retransmit #%d (rto=%s)", c.resends, c.rto)},
		{Kind: ActSend, Bytes: c.lastData},
		c.armWait(),
	}
}

// serverEnd is the live-space end sequence of a captured server packet.
func (c *Conversation) serverEnd(cp CapturedPacket) units.Seq {
	return cp.Seq.AddDelta(c.sess.ServerDelta).Add(cp.SegLen)
}

// armWait schedules the retransmit timer for the current RTO.
func (c *Conversation) armWait() Action {
	return Action{Kind: ActArmTimer, Delay: c.rto}
}
