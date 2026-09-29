package engine

import (
	"fmt"

	"github.com/kvmukilan/livewire/internal/units"
	"github.com/kvmukilan/livewire/internal/wire"
)

const maxFlightBytes = 64 << 10

type sentSegment struct {
	frame []byte
	end   units.Seq
}

type senderState struct {
	una           units.Seq
	outstanding   []sentSegment
	pending       []byte
	window        uint32
	windowSeq     units.Seq
	windowACK     units.Seq
	scale         uint8
	clientScale   uint8
	mss           uint32
	timestamps    bool
	lastTS        uint32
	haveTS        bool
	finSent       bool
	finEnd        units.Seq
	peerFIN       bool
	peerFINEnd    units.Seq
	peerFINQueued bool
}

func (c *Conversation) learnPeer(p *wire.Packet) {
	c.sender.mss = 536
	if p.IsIPv6() {
		c.sender.mss = 1220
	}
	if mss, ok := p.MSS(); ok && mss > 0 {
		c.sender.mss = uint32(mss)
	}
	var clientScale uint8
	var clientHasScale, clientTS bool
	for _, cp := range c.flow.Packets {
		if cp.Dir == C2S && cp.IsSyn {
			if syn, err := wire.Parse(cp.Rec.Data, c.link); err == nil {
				clientScale, clientHasScale = syn.WindowScale()
				clientTS = syn.HasTimestamps()
			}
			break
		}
	}
	if shift, ok := p.WindowScale(); ok && clientHasScale {
		c.sender.scale = min(shift, 14)
		c.sender.clientScale = min(clientScale, 14)
	}
	c.sender.timestamps = clientTS && p.HasTimestamps()
	// SYN windows are never scaled, even when scaling was negotiated.
	c.sender.window = uint32(p.Window())
	c.sender.windowSeq, c.sender.windowACK = p.Seq(), p.AckNum()
}

// acknowledge validates SND.UNA <= SEG.ACK <= SND.NXT, trims the acknowledged
// prefix, and accepts window updates only in sequence/ACK order (SND.WL1/WL2).
// Old duplicate ACKs may accompany valid data, but cannot shrink a fresh window.
func (c *Conversation) acknowledge(p *wire.Packet) (progress, valid bool) {
	ack := p.AckNum()
	if ack.Greater(c.clientNext) {
		return false, false
	}
	if ack.Less(c.sender.una) {
		return false, true
	}
	if ack.Greater(c.sender.una) {
		c.sender.una = ack
		progress = true
		for len(c.sender.outstanding) > 0 && c.sender.outstanding[0].end.LessEqual(ack) {
			c.sender.outstanding[0] = sentSegment{}
			c.sender.outstanding = c.sender.outstanding[1:]
		}
		if len(c.sender.outstanding) > 0 {
			first := &c.sender.outstanding[0]
			if pk, err := wire.Parse(first.frame, c.link); err == nil && pk.Seq().Less(ack) {
				first.frame = trimTCPPrefix(pk, ack)
			}
		}
		c.resends, c.rto = 0, c.cfg.RTO
		c.timerProgress = true
	}
	if p.Seq().Greater(c.sender.windowSeq) || (p.Seq() == c.sender.windowSeq && ack.GreaterEqual(c.sender.windowACK)) {
		window := uint32(p.Window())
		if !p.HasFlags(wire.FlagSYN) {
			window <<= c.sender.scale
		}
		progress = progress || window != c.sender.window
		c.sender.window = window
		c.sender.windowSeq, c.sender.windowACK = p.Seq(), ack
	}
	return progress, true
}

func trimTCPPrefix(p *wire.Packet, start units.Seq) []byte {
	consumed := p.Seq().Delta(start)
	flags := p.Flags()
	if flags&wire.FlagSYN != 0 && consumed > 0 {
		flags &^= wire.FlagSYN
		consumed--
	}
	pl := uint32(p.PayloadLen())
	consumed = min(consumed, pl)
	payload := append([]byte(nil), p.Payload()[consumed:pl]...)
	p.SetSeq(start)
	p.SetFlags(flags)
	return p.RebuildWithPayload(payload)
}

// normalOptions drops captured SACK blocks and SYN-only options after the
// handshake: they describe the old connection, not this live receive state.
func (c *Conversation) normalOptions(p *wire.Packet) []byte {
	var opts []byte
	if c.sender.timestamps {
		ts := c.sess.lastLiveTS[C2S]
		if c.sender.haveTS && units.Seq(ts).Less(units.Seq(c.sender.lastTS)) {
			ts = c.sender.lastTS
		}
		c.sender.lastTS, c.sender.haveTS = ts, true
		opts = wire.SynTimestamp(ts)
	}
	frame, _ := p.RebuildWithOptions(opts, p.Payload()[:p.PayloadLen()])
	q, _ := wire.Parse(frame, c.link)
	q.SetAck(c.serverRcvd)
	q.SetWindow(uint16(min(uint32(65535), uint32(maxReorderSpan)>>c.sender.clientScale)))
	if c.sender.timestamps {
		q.SetTimestamps(c.sender.lastTS, c.sess.lastLiveTS[S2C])
	}
	q.RecalcChecksums()
	return frame
}

func (c *Conversation) ackAction() Action {
	// Start with a captured client header, then build only the live ACK fields
	// and negotiated timestamps. No captured payload or SACK edge survives.
	for _, cp := range c.flow.Packets {
		if cp.Dir != C2S {
			continue
		}
		p, err := wire.Parse(append([]byte(nil), cp.Rec.Data...), c.link)
		if err != nil {
			continue
		}
		p.SetSeq(c.clientNext)
		p.SetFlags(wire.FlagACK)
		frame := p.RebuildWithPayload(nil)
		p, _ = wire.Parse(frame, c.link)
		return Action{Kind: ActSend, Bytes: c.normalOptions(p)}
	}
	return Action{Kind: ActLog, Reason: "cannot construct TCP acknowledgement"}
}

func (c *Conversation) rememberSent(frame []byte) {
	p, _ := wire.Parse(frame, c.link)
	end := p.Seq().Add(p.SegmentLen())
	if p.SegmentLen() == 0 {
		return
	}
	c.clientNext = end
	c.sender.outstanding = append(c.sender.outstanding, sentSegment{frame: append([]byte(nil), frame...), end: end})
	if p.HasFlags(wire.FlagFIN) {
		c.sender.finSent, c.sender.finEnd = true, end
		c.phase = PhaseClosing
	}
}

// nextClientFrame emits at most the live peer's MSS and remaining receive
// window. The unsent suffix remains attached to the current captured packet.
func (c *Conversation) nextClientFrame(cp CapturedPacket) (frame []byte, complete bool, err error) {
	if c.sender.pending == nil {
		c.sender.pending, _, err = c.sess.Rewrite(cp)
		if err != nil {
			return nil, false, err
		}
	}
	p, err := wire.Parse(c.sender.pending, c.link)
	if err != nil {
		return nil, false, err
	}
	if p.HasFlags(wire.FlagURG) {
		return nil, false, fmt.Errorf("TCP urgent data requires explicit captured transport replay")
	}
	if p.HasFlags(wire.FlagSYN) && !c.serverKnown {
		frame, c.sender.pending = c.sender.pending, nil
		return frame, true, nil
	}
	if p.HasFlags(wire.FlagRST) {
		frame, c.sender.pending = c.normalOptions(p), nil
		return frame, true, nil
	}
	if !c.serverKnown {
		return nil, false, nil
	}
	if p.Seq().Greater(c.clientNext) && p.SegmentLen() > 0 {
		return nil, false, fmt.Errorf("captured client stream has a sequence gap before packet %d", cp.Index)
	}
	if p.SegmentLen() > 0 && p.Seq().Add(p.SegmentLen()).LessEqual(c.clientNext) {
		c.sender.pending = nil // captured retransmission already queued or ACKed
		return nil, true, nil
	}
	if p.Seq().Less(c.clientNext) && p.SegmentLen() > 0 {
		c.sender.pending = trimTCPPrefix(p, c.clientNext)
		p, _ = wire.Parse(c.sender.pending, c.link)
	}
	if p.SegmentLen() == 0 {
		p.SetSeq(c.clientNext)
		frame, c.sender.pending = c.normalOptions(p), nil
		return frame, true, nil
	}
	if c.sender.finSent {
		return nil, false, fmt.Errorf("captured client data follows FIN at packet %d", cp.Index)
	}
	flight := c.sender.una.Delta(c.clientNext)
	limit := min(c.sender.window, uint32(maxFlightBytes))
	if flight >= limit {
		return nil, false, nil
	}
	allow := min(limit-flight, c.sender.mss)
	take := min(uint32(p.PayloadLen()), allow)
	flags := p.Flags() | wire.FlagACK
	includeFIN := flags&wire.FlagFIN != 0 && take == uint32(p.PayloadLen()) && allow > take
	complete = take == uint32(p.PayloadLen()) && (flags&wire.FlagFIN == 0 || includeFIN)
	if !complete {
		flags &^= wire.FlagFIN | wire.FlagPSH
	}
	if take == 0 && !includeFIN {
		return nil, false, nil
	}
	payload := append([]byte(nil), p.Payload()[:take]...)
	seq := p.Seq()
	if complete {
		c.sender.pending = nil
	} else {
		c.sender.pending = trimTCPPrefix(p, p.Seq().Add(take))
	}
	p.SetSeq(seq)
	p.SetFlags(flags)
	frame = p.RebuildWithPayload(payload)
	p, _ = wire.Parse(frame, c.link)
	return c.normalOptions(p), complete, nil
}

func (c *Conversation) retransmitFrame() []byte {
	if len(c.sender.outstanding) == 0 {
		return nil
	}
	p, _ := wire.Parse(append([]byte(nil), c.sender.outstanding[0].frame...), c.link)
	if !c.serverKnown {
		return p.Buf
	}
	// A receiver may shrink its window. Limit retries to its current window;
	// at zero window a one-byte duplicate probe solicits a fresh window ACK.
	limit := min(c.sender.window, c.sender.mss)
	if limit == 0 {
		limit = 1
	}
	if uint32(p.PayloadLen()) > limit {
		p.SetFlags(p.Flags() &^ (wire.FlagFIN | wire.FlagPSH))
		frame := p.RebuildWithPayload(p.Payload()[:limit])
		p, _ = wire.Parse(frame, c.link)
	}
	return c.normalOptions(p)
}
