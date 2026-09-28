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
	EvTick                     // a captured send time became due
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
	ActArmWake                    // schedule an EvTick after Delay while receiving
)

// Action is one output from Poll.
type Action struct {
	Kind    ActionKind
	Bytes   []byte
	Delay   time.Duration
	Reason  string
	Restart bool // ActArmTimer: restart after actual ACK/receive progress
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
	// RawL4 replays the client's frames exactly as captured Ã¢â‚¬â€ every packet in
	// order including retransmissions, unusual flag combinations, and RSTs, with
	// the original acknowledgement numbers (fixed-delta rewrite) Ã¢â‚¬â€ instead of
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

	phase          Phase
	ci             int       // index of the next captured packet to process
	t0             time.Time // capture time of the flow's first packet, for pacing
	now, startedAt time.Time
	waitingPace    bool
	timerProgress  bool

	// serverRcvd is the next contiguous sequence expected from the server;
	// everything below it has been delivered. Gates client packets.
	serverRcvd    units.Seq
	serverKnown   bool
	serverPending []sequenceRange // received ranges beyond a hole in the live stream
	clientNext    units.Seq       // highest sequence end emitted, for handshake ACK validation
	serverTSKnown bool
	sender        senderState

	// RawL4 retains its handshake SYN verbatim for establishment retries.
	// Normal replay retransmits sender.outstanding's oldest unacknowledged
	// range. resends also bounds zero-window and response-progress waits.
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
	if f == nil {
		return nil, fmt.Errorf("nil captured flow")
	}
	if cfg.RTO < 0 || cfg.ResendBudget < 0 {
		return nil, fmt.Errorf("TCP retransmit timeout and budget must be nonnegative")
	}
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
	verifier := newRespVerifier(f, cfg.Verify)
	if verifier != nil && verifier.captureError != nil {
		return nil, fmt.Errorf("captured response stream cannot be verified: %w", verifier.captureError)
	}
	return &Conversation{
		flow:       f,
		sess:       NewSession(f, units.Seq(cISN), tsC, tsS), // server ISN learned later
		link:       f.Packets[0].Rec.LinkType,
		cfg:        cfg,
		phase:      PhaseInit,
		clientNext: units.Seq(cISN),
		sender:     senderState{una: units.Seq(cISN)},
		rto:        cfg.RTO,
		verify:     verifier,
		adaptive:   cfg.Adaptive,
		rawL4:      cfg.RawL4,
		t0:         f.Packets[0].Rec.Time,
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
	if c.phase == PhaseClosed || c.phase == PhaseAborted {
		return nil
	}
	c.now = ev.Now
	switch ev.Kind {
	case EvStart:
		if c.phase != PhaseInit {
			return nil
		}
		c.startedAt = ev.Now
		return c.pump()
	case EvRecv:
		return c.onRecv(ev.Frame)
	case EvTimeout:
		return c.onTimeout()
	case EvTick:
		return c.pump()
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
	c.waitingPace = false
	for c.ci < len(c.flow.Packets) {
		cp := c.flow.Packets[c.ci]
		if cp.Dir == S2C {
			if c.serverKnown && cp.IsSynAck {
				c.ci++
				continue
			}
			if c.serverKnown && cp.SegLen == 0 && !cp.IsRst {
				if cp.Ack && c.sender.una.Less(cp.AckN.AddDelta(c.sess.ClientDelta)) {
					return append(acts, c.armWait())
				}
				c.ci++
				continue
			}
			if cp.IsFin && c.sender.peerFIN {
				c.ci++
				continue
			}
			if !c.adaptive && c.serverKnown && !cp.IsRst && !cp.IsFin && c.serverRcvd.GreaterEqual(c.serverEnd(cp)) {
				c.ci++
				continue
			}
			if c.adaptive && c.serverKnown && !cp.IsRst {
				delivered := c.turnBase.Delta(c.serverRcvd)
				if (!c.runHasFIN(c.ci) || c.sender.peerFIN) && (delivered >= c.runBytes(c.ci) || c.turnDrained || c.framedTurnComplete(c.ci)) {
					c.ci = c.runEnd(c.ci)
					c.turnDrained = false
					continue
				}
			}
			if c.sender.peerFIN {
				return append(acts, c.abort("peer closed before the expected response completed")...)
			}
			c.waitingServer = true
			return append(acts, c.armWait())
		}
		if !c.adaptive && c.serverKnown && cp.Ack && c.serverRcvd.Less(cp.AckN.AddDelta(c.sess.ServerDelta)) {
			return append(acts, c.armWait())
		}
		if wait, future := c.paceWait(cp); future {
			return append(acts, wait...)
		}
		buf, complete, err := c.nextClientFrame(cp)
		if err != nil {
			return append(acts, c.abort("rewrite: "+err.Error())...)
		}
		if buf == nil {
			if complete {
				c.ci++
				continue
			}
			return append(acts, c.armWait())
		}
		p, _ := wire.Parse(buf, c.link)
		acts = append(acts, Action{Kind: ActSend, Bytes: buf, At: cp.Rec.Time.Sub(c.t0)})
		if p.SegmentLen() > 0 {
			if len(c.sender.outstanding) == 0 {
				c.resends, c.rto = 0, c.cfg.RTO
				c.timerProgress = true
			}
			c.rememberSent(buf)
			c.turnBase, c.turnDrained = c.serverRcvd, false
		}
		if cp.IsSyn && !c.serverKnown {
			c.phase = PhaseSynSent
		}
		if cp.IsRst {
			c.phase = PhaseClosed
			return append(acts, Action{Kind: ActDone})
		}
		if complete {
			c.ci++
		}
	}
	if len(c.sender.outstanding) > 0 || (c.sender.finSent && !c.sender.peerFIN) {
		c.waitingServer = true
		return append(acts, c.armWait())
	}
	c.phase = PhaseClosed
	return append(acts, Action{Kind: ActDone})
}

func (c *Conversation) abort(reason string) []Action {
	c.phase = PhaseAborted
	return []Action{{Kind: ActAbort, Reason: reason}}
}

func (c *Conversation) runHasFIN(i int) bool {
	for ; i < len(c.flow.Packets) && c.flow.Packets[i].Dir == S2C; i++ {
		if c.flow.Packets[i].IsFin {
			return true
		}
	}
	return false
}

// pumpRaw replays the client side exactly as captured: it fires every
// client-to-server packet in order (retransmissions, odd flags, RSTs included)
// with fixed-delta seq/ack rewriting, waiting only for the SYN-ACK to learn the
// live server ISN. Server packets are not gated on.
func (c *Conversation) pumpRaw() []Action {
	var acts []Action
	c.waitingServer = false
	c.waitingPace = false
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
		if wait, future := c.paceWait(cp); future {
			return append(acts, wait...)
		}

		buf, _, err := c.sess.Rewrite(cp) // preserves flags (incl. RST) and captured acks
		if err != nil {
			c.phase = PhaseAborted
			return append(acts, Action{Kind: ActAbort, Reason: "rewrite: " + err.Error()})
		}
		acts = append(acts, Action{Kind: ActSend, Bytes: buf, At: cp.Rec.Time.Sub(c.t0)})
		c.recordClientEnd(cp)
		if cp.IsSyn && !c.serverKnown {
			// Raw replay still needs reliable handshake establishment before the
			// server's sequence space is known.
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
		return nil
	}
	if p.SrcIP() != c.flow.Server.Addr || p.DstIP() != c.flow.Client.Addr || p.SrcPort() != c.flow.Server.Port || p.DstPort() != c.flow.Client.Port {
		return nil
	}
	if p.HasFlags(wire.FlagRST) {
		if !c.serverKnown && (!p.HasFlags(wire.FlagACK) || !c.validHandshakeACK(p.AckNum())) {
			return nil
		}
		if c.serverKnown && p.Seq() != c.serverRcvd {
			if !c.rawL4 && p.Seq().Between(c.serverRcvd, c.serverRcvd.Add(c.receiveWindow())) {
				return []Action{c.ackAction()}
			}
			return nil
		}
		return c.abort("peer sent RST")
	}
	if !c.serverKnown && p.HasFlags(wire.FlagSYN) && p.HasFlags(wire.FlagACK) {
		if c.phase != PhaseSynSent || p.HasFlags(wire.FlagFIN) || !c.validHandshakeACK(p.AckNum()) {
			return nil
		}
		c.sess.LearnServerISN(p.Seq())
		c.serverKnown = true
		c.serverRcvd = c.sess.LiveServerISN.Add(1)
		c.turnBase = c.serverRcvd
		c.phase = PhaseEstablished
		c.observeServerTimestamp(p)
		if !c.rawL4 {
			c.learnPeer(p)
			c.acknowledge(p)
		}
		if err := c.receiveRange(p.Seq().Add(1), p.Seq().Add(p.SegmentLen())); err != nil {
			return c.abort(err.Error())
		}
		acts := c.verifyReply(p)
		if c.phase == PhaseAborted {
			return acts
		}
		if !c.rawL4 {
			acts = append(acts, c.ackAction())
			// If the peer declined part of SYN payload, send its unacknowledged
			// suffix as ordinary data rather than retransmitting a SYN in ESTABLISHED.
			if len(c.sender.outstanding) > 0 {
				if frame := c.retransmitFrame(); frame != nil && c.sender.window > 0 {
					acts = append(acts, Action{Kind: ActSend, Bytes: frame})
				}
			}
		}
		return append(acts, c.pump()...)
	}
	if !c.serverKnown {
		return nil
	}
	if p.HasFlags(wire.FlagSYN) {
		if !c.rawL4 {
			return []Action{c.ackAction()}
		}
		return nil
	}
	if !p.HasFlags(wire.FlagACK) {
		return nil
	}
	if !c.rawL4 && !c.acceptableSequence(p) {
		return []Action{c.ackAction()}
	}
	if !c.rawL4 && c.sender.peerFINQueued && p.PayloadLen() > 0 && p.Seq().GreaterEqual(c.sender.peerFINEnd.Sub(1)) {
		return []Action{c.ackAction()}
	}
	if !c.rawL4 {
		p = c.clipReceiveWindow(p)
	}
	ackProgress := false
	if !c.rawL4 {
		var valid bool
		ackProgress, valid = c.acknowledge(p)
		if !valid {
			return []Action{c.ackAction()}
		}
	}
	before := c.serverRcvd
	if !c.rawL4 && c.sender.peerFIN && p.PayloadLen() > 0 {
		return []Action{c.ackAction()}
	}
	if p.HasFlags(wire.FlagFIN) && !c.rawL4 {
		end := p.Seq().Add(p.SegmentLen())
		if c.sender.peerFINQueued && end != c.sender.peerFINEnd {
			return c.abort("peer sent conflicting FIN sequence positions")
		}
		c.queuePeerFIN(end)
	}
	if err := c.receiveRange(p.Seq(), p.Seq().Add(p.SegmentLen())); err != nil {
		return c.abort(err.Error())
	}
	if c.sender.peerFINQueued && c.serverRcvd.GreaterEqual(c.sender.peerFINEnd) {
		c.sender.peerFIN = true
	}
	if p.Seq().LessEqual(before) {
		c.observeServerTimestamp(p)
	}
	if c.serverRcvd != before {
		c.resends, c.rto = 0, c.cfg.RTO
		c.timerProgress = true
	}
	acts := c.verifyReply(p)
	if c.phase == PhaseAborted {
		return acts
	}
	if !c.rawL4 && p.SegmentLen() > 0 {
		acts = append(acts, c.ackAction())
	}
	if c.serverRcvd != before || ackProgress {
		return append(acts, c.pump()...)
	}
	return acts
}

func (c *Conversation) receiveWindow() uint32 {
	return min(uint32(65535)<<c.sender.clientScale, uint32(maxReorderSpan))
}

func (c *Conversation) acceptableSequence(p *wire.Packet) bool {
	end := p.Seq().Add(p.SegmentLen())
	right := c.serverRcvd.Add(c.receiveWindow())
	if p.SegmentLen() == 0 {
		return p.Seq().Between(c.serverRcvd, right)
	}
	// A duplicate or overlapping prefix may be acknowledged again. Future
	// data wholly beyond the advertised window must not release captured gates.
	return p.Seq().Less(right) && (end.Greater(c.serverRcvd) || end == c.serverRcvd)
}
func (c *Conversation) observeServerTimestamp(p *wire.Packet) {
	if ts, _, ok := p.Timestamps(); ok {
		if !c.serverTSKnown || units.Seq(ts).GreaterEqual(units.Seq(c.sess.lastLiveTS[S2C])) {
			c.sess.lastLiveTS[S2C] = ts
			c.serverTSKnown = true
		}
	}
}

func (c *Conversation) recordClientEnd(cp CapturedPacket) {
	if end := cp.Seq.AddDelta(c.sess.ClientDelta).Add(cp.SegLen); end.Greater(c.clientNext) {
		c.clientNext = end
	}
}

func (c *Conversation) validHandshakeACK(ack units.Ack) bool {
	return ack.Greater(c.sess.LiveClientISN) && ack.LessEqual(c.clientNext)
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
	payloadSeq := p.Seq()
	if p.HasFlags(wire.FlagSYN) {
		payloadSeq = payloadSeq.Add(1)
	}
	off := int(c.sess.LiveServerISN.Add(1).Delta(payloadSeq))
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

// onTimeout retries the oldest unacknowledged range, probes a closed peer
// window, or bounds an otherwise silent application/close wait.
func (c *Conversation) onTimeout() []Action {
	if c.phase == PhaseClosed || c.phase == PhaseAborted {
		return nil
	}
	if c.waitingPace && len(c.sender.outstanding) == 0 && (!c.rawL4 || c.serverKnown) {
		return nil // the separate captured-time wake remains armed
	}
	if c.adaptive && !c.rawL4 && c.serverKnown && c.waitingServer && len(c.sender.outstanding) == 0 && len(c.serverPending) == 0 && c.ci < len(c.flow.Packets) && !c.runHasFIN(c.ci) && c.turnBase.Less(c.serverRcvd) {
		c.turnDrained = true
		return c.pump()
	}
	if c.resends >= c.cfg.ResendBudget {
		reason := fmt.Sprintf("no progress after %d retries", c.resends)
		if c.serverKnown && c.sender.window == 0 && !c.rawL4 {
			reason += ": peer receive window stayed closed"
		}
		return c.abort(reason)
	}
	c.resends++
	if c.rto >= 30*time.Second {
		c.rto = 60 * time.Second
	} else {
		c.rto *= 2
	}
	var frame []byte
	if c.rawL4 {
		frame = append([]byte(nil), c.lastData...)
	} else {
		frame = c.retransmitFrame()
	}
	if len(frame) > 0 {
		return []Action{{Kind: ActLog, Reason: fmt.Sprintf("retransmit #%d (rto=%s)", c.resends, c.rto)}, {Kind: ActSend, Bytes: frame}, c.armWait()}
	}
	if !c.rawL4 && c.serverKnown && c.sender.window == 0 {
		// A sequence just before SND.NXT elicits a window ACK without
		// falsely claiming that new application data has been delivered.
		a := c.ackAction()
		p, _ := wire.Parse(a.Bytes, c.link)
		p.SetSeq(c.clientNext.Sub(1))
		p.RecalcChecksums()
		return []Action{{Kind: ActLog, Reason: fmt.Sprintf("zero-window probe #%d", c.resends)}, a, c.armWait()}
	}
	return []Action{{Kind: ActLog, Reason: fmt.Sprintf("waiting for peer progress #%d (rto=%s)", c.resends, c.rto)}, c.armWait()}
}

// serverEnd is the live-space end sequence of a captured server packet.
func (c *Conversation) serverEnd(cp CapturedPacket) units.Seq {
	return cp.Seq.AddDelta(c.sess.ServerDelta).Add(cp.SegLen)
}

// runBytes sums the sequence-space length of the contiguous run of server
// packets starting at index i Ã¢â‚¬â€ the byte count the live device must deliver to
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
// application message the captured server run at index i contains Ã¢â‚¬â€ letting an
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
	a := Action{Kind: ActArmTimer, Delay: c.rto, Restart: c.timerProgress}
	c.timerProgress = false
	return a
}

func (c *Conversation) paceWait(cp CapturedPacket) ([]Action, bool) {
	if !c.cfg.Pace {
		return nil, false
	}
	delay := c.startedAt.Add(cp.Rec.Time.Sub(c.t0)).Sub(c.now)
	if delay <= 0 {
		return nil, false
	}
	c.waitingPace = true
	acts := []Action{{Kind: ActArmWake, Delay: delay}}
	if len(c.sender.outstanding) > 0 || (c.rawL4 && !c.serverKnown) {
		acts = append(acts, c.armWait())
	}
	return acts, true
}
