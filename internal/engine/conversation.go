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
	// At is the captured send time of this frame relative to the flow's first
	// packet. The driver uses it to pace an on-wire replay to the original
	// timing; zero (or pacing off) sends as soon as the gate opens.
	At time.Duration
}

// ConvConfig tunes retransmission behaviour.
type ConvConfig struct {
	// ResendBudget caps retransmits of a stalled segment before aborting. Zero uses DefaultResendBudget.
	ResendBudget int
	// RTO is the base retransmit timeout; it doubles per resend. Zero uses DefaultRTO.
	RTO time.Duration
	// Verify controls whether the live server's replies are checked against the
	// capture. The zero value (VerifyOff) preserves the TCP-only behaviour.
	Verify VerifyMode
	// Adaptive makes the replay re-anchor on what the live server actually sends
	// instead of assuming byte-identical responses: client ACKs acknowledge the
	// live server's real high-water mark, and a turn completes once the server
	// goes quiescent even if it answered with fewer bytes than the capture (e.g.
	// a Modbus exception). Off by default (the exact byte-clock is used).
	Adaptive bool
	// Pace replays each client packet no earlier than its captured time offset,
	// reproducing the original inter-packet timing instead of sending as fast as
	// the peer answers. Off by default.
	Pace bool
	// RawL4 replays the client's frames exactly as captured — every packet in
	// order including retransmissions, unusual flag combinations, and RSTs, with
	// the original acknowledgement numbers (fixed-delta rewrite) — instead of
	// driving a clean, response-gated state machine. Only the SYN-ACK is waited
	// on, to learn the live server ISN. For reproducing bugs triggered by the
	// messy TCP the client originally produced. Off by default.
	RawL4 bool
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
	ci    int       // index of the next captured packet to process
	t0    time.Time // capture time of the flow's first packet, for pacing

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

	// verify checks live replies against the capture; nil when verification off.
	verify *respVerifier

	// Adaptive-clock state (used only when cfg.Adaptive is set).
	adaptive      bool
	rawL4         bool
	waitingServer bool      // pump last blocked waiting for a server reply
	turnDrained   bool      // current server turn accepted as complete despite a byte shortfall
	turnBase      units.Seq // serverRcvd at the start of the current server turn (after the request went out)
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
		flow:     f,
		sess:     NewSession(f, units.Seq(cISN), tsC, tsS), // server ISN learned later
		link:     f.Packets[0].Rec.LinkType,
		cfg:      cfg,
		phase:    PhaseInit,
		rto:      cfg.RTO,
		verify:   newRespVerifier(f, cfg.Verify),
		adaptive: cfg.Adaptive,
		rawL4:    cfg.RawL4,
		t0:       f.Packets[0].Rec.Time,
	}, nil
}

// VerifyMode reports the reply-verification mode this conversation runs in.
func (c *Conversation) VerifyMode() VerifyMode { return c.cfg.Verify }

// Mismatches returns every reply divergence found against the capture so far.
func (c *Conversation) Mismatches() []Mismatch {
	if c.verify == nil {
		return nil
	}
	return c.verify.all
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
	if c.rawL4 {
		return c.pumpRaw()
	}
	var acts []Action
	c.waitingServer = false
	for c.ci < len(c.flow.Packets) {
		cp := c.flow.Packets[c.ci]

		if cp.Dir == S2C {
			// Server packet: wait for it rather than send it. The exact byte-clock
			// advances once the server has delivered through this packet's mapped
			// end; this also consumes the SYN-ACK and pure-ACKs in both modes.
			if c.serverKnown && c.serverRcvd.GreaterEqual(c.serverEnd(cp)) {
				c.ci++
				continue
			}
			// Adaptive mode measures the whole server turn relative to the moment
			// the request went out, so it stays correct even after an earlier
			// length divergence shifted the live stream off the captured layout: a
			// turn completes when the device has delivered the run's byte count, or
			// when it went quiescent having answered short.
			if c.adaptive && c.serverKnown {
				delivered := c.turnBase.Delta(c.serverRcvd)
				if delivered >= c.runBytes(c.ci) || c.turnDrained || c.framedTurnComplete(c.ci) {
					c.ci = c.runEnd(c.ci)
					c.turnDrained = false
					continue
				}
			}
			c.waitingServer = true
			return append(acts, c.armWait())
		}

		// Client packet. The exact byte-clock gates the send on the server having
		// delivered everything this packet acks; adaptive mode instead relies on
		// the S2C waits above for ordering and rewrites the ack to the live
		// high-water mark below, so a shorter/longer reply stays coherent.
		if !c.adaptive && c.serverKnown && cp.Ack {
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
		if c.adaptive && c.serverKnown && cp.Ack {
			if nb, ok := reAck(buf, c.link, c.serverRcvd); ok {
				buf = nb
			}
		}
		acts = append(acts, Action{Kind: ActSend, Bytes: buf, At: cp.Rec.Time.Sub(c.t0)})
		if cp.SegLen > 0 { // SYN/FIN/data consume sequence space, retransmittable
			c.lastData = buf
			c.resends = 0
			c.rto = c.cfg.RTO
			c.turnBase = c.serverRcvd // the next server turn is measured from here
			c.turnDrained = false     // a new client turn must earn a fresh server reply
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

// pumpRaw replays the client side exactly as captured: it fires every
// client-to-server packet in order (retransmissions, odd flags, RSTs included)
// with fixed-delta seq/ack rewriting, waiting only for the SYN-ACK to learn the
// live server ISN. Server packets are not gated on.
func (c *Conversation) pumpRaw() []Action {
	var acts []Action
	c.waitingServer = false
	for c.ci < len(c.flow.Packets) {
		cp := c.flow.Packets[c.ci]

		if cp.Dir == S2C {
			if !c.serverKnown {
				c.waitingServer = true // only the SYN-ACK is worth waiting for
				return append(acts, c.armWait())
			}
			c.ci++
			continue
		}

		// A client packet that acknowledges the server can't go until we've
		// learned the live server ISN to rewrite its ack against.
		if cp.Ack && !c.serverKnown {
			c.waitingServer = true
			return append(acts, c.armWait())
		}

		buf, _, err := c.sess.Rewrite(cp) // preserves flags (incl. RST) and captured acks
		if err != nil {
			c.phase = PhaseAborted
			return append(acts, Action{Kind: ActAbort, Reason: "rewrite: " + err.Error()})
		}
		acts = append(acts, Action{Kind: ActSend, Bytes: buf, At: cp.Rec.Time.Sub(c.t0)})
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

// reAck overwrites a client frame's acknowledgement number with the live
// server's real delivery high-water mark and recomputes checksums. buf is a
// fresh copy owned by the caller, so mutating it in place is safe.
func reAck(buf []byte, link wire.LinkType, ack units.Seq) ([]byte, bool) {
	p, err := wire.Parse(buf, link)
	if err != nil || !p.IsTCP() {
		return nil, false
	}
	p.SetAck(units.Ack(ack))
	p.RecalcChecksums()
	return buf, true
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
		c.turnBase = c.serverRcvd // base for any reply before the first request
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
		if acts := c.verifyReply(p); acts != nil {
			if c.phase == PhaseAborted {
				return acts // strict-mode abort; stop here
			}
			return append(acts, c.pump()...)
		}
	}
	return c.pump()
}

// verifyReply folds a live server frame's payload into the verifier and turns
// any new divergences into log actions. In VerifyStrict a structural divergence
// aborts the flow; VerifyLenient only reports. Returns nil when nothing to say.
func (c *Conversation) verifyReply(p *wire.Packet) []Action {
	if c.verify == nil {
		return nil
	}
	pl := p.PayloadLen()
	if pl <= 0 {
		return nil
	}
	pay := p.Payload()
	if pl > len(pay) {
		return nil
	}
	// Offset of this segment within the server's data stream (first byte is ISN+1).
	off := int(c.sess.LiveServerISN.Add(1).Delta(p.Seq()))
	c.verify.deliver(off, pay[:pl])

	newMism := c.verify.check()
	if len(newMism) == 0 {
		return nil
	}
	var acts []Action
	var structural bool
	for _, m := range newMism {
		acts = append(acts, Action{Kind: ActLog, Reason: "reply-mismatch: " + m.Detail})
		if m.Structural {
			structural = true
		}
	}
	if c.cfg.Verify == VerifyStrict && structural {
		c.phase = PhaseAborted
		acts = append(acts, Action{Kind: ActAbort, Reason: "live reply diverged from capture: " + newMism[0].Detail})
	}
	return acts
}

// onTimeout retransmits the last sequence-consuming client frame with RTO
// backoff, or aborts once the resend budget is spent.
func (c *Conversation) onTimeout() []Action {
	if c.phase == PhaseClosed || c.phase == PhaseAborted {
		return nil
	}
	// Adaptive quiescence: we're blocked waiting on a server reply that has
	// already begun arriving but stopped short of the captured length. Treat the
	// silence as the device having finished its (shorter) reply and move on,
	// rather than retransmitting forever against a server that answered fine.
	if c.adaptive && c.serverKnown && c.waitingServer && c.turnBase.Less(c.serverRcvd) {
		c.turnDrained = true
		return c.pump()
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

// runBytes sums the sequence-space length of the contiguous run of server
// packets starting at index i — the byte count the live device must deliver to
// satisfy this turn.
func (c *Conversation) runBytes(i int) uint32 {
	var n uint32
	for ; i < len(c.flow.Packets) && c.flow.Packets[i].Dir == S2C; i++ {
		n += c.flow.Packets[i].SegLen
	}
	return n
}

// runEnd returns the index just past the contiguous run of server packets
// starting at i.
func (c *Conversation) runEnd(i int) int {
	for ; i < len(c.flow.Packets) && c.flow.Packets[i].Dir == S2C; i++ {
	}
	return i
}

// framedTurnComplete reports whether the live device has already delivered every
// application message the captured server run at index i contains — letting an
// adaptive turn finish the instant a full framed reply arrives (e.g. a complete
// Modbus exception ADU) instead of waiting for the quiescence timer. Returns
// false for unframed protocols or when verification is off.
func (c *Conversation) framedTurnComplete(i int) bool {
	if !c.verify.framed() {
		return false
	}
	var runPayload []byte
	for j := i; j < len(c.flow.Packets) && c.flow.Packets[j].Dir == S2C; j++ {
		runPayload = append(runPayload, payloadOf(c.flow.Packets[j])...)
	}
	expected := countMessages(c.verify.proto, runPayload)
	if expected == 0 {
		return false
	}
	baseOff := int(c.sess.LiveServerISN.Add(1).Delta(c.turnBase))
	return c.verify.liveMessagesSince(baseOff) >= expected
}

// armWait schedules the retransmit timer for the current RTO.
func (c *Conversation) armWait() Action {
	return Action{Kind: ActArmTimer, Delay: c.rto}
}
