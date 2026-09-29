package engine

import (
	"fmt"

	"github.com/kvmukilan/livewire/internal/units"
	"github.com/kvmukilan/livewire/internal/wire"
)

// A segment can overlap the advertised receive window while its trailing
// payload or FIN lies outside it. Only admitted bytes may enter the receive
// scoreboard or response verifier; ACKing the suffix would falsely promise
// delivery and prevent the peer from retransmitting it when the window moves.
func (c *Conversation) clipReceiveWindow(p *wire.Packet) *wire.Packet {
	right := c.serverRcvd.Add(c.receiveWindow())
	if c.sender.peerFINQueued && p.PayloadLen() > 0 && c.sender.peerFINEnd.Sub(1).Less(right) {
		right = c.sender.peerFINEnd.Sub(1)
	}
	if !p.Seq().Add(p.SegmentLen()).Greater(right) {
		return p
	}
	q, _ := wire.Parse(append([]byte(nil), p.Buf...), c.link)
	q.SetFlags(q.Flags() &^ wire.FlagFIN)
	take := min(uint32(q.PayloadLen()), q.Seq().Delta(right))
	frame := q.RebuildWithPayload(q.Payload()[:take])
	q, _ = wire.Parse(frame, c.link)
	return q
}

func (c *Conversation) queuePeerFIN(end units.Seq) {
	c.sender.peerFINQueued, c.sender.peerFINEnd = true, end
	kept := c.serverPending[:0]
	for _, r := range c.serverPending {
		if r.start.GreaterEqual(end) {
			continue
		}
		if r.end.Greater(end) {
			r.end = end
		}
		kept = append(kept, r)
	}
	c.serverPending = kept
	if c.verify != nil {
		payloadEnd := int(c.sess.LiveServerISN.Add(1).Delta(end.Sub(1)))
		if payloadEnd < len(c.verify.live) {
			c.verify.live = c.verify.live[:payloadEnd]
			c.verify.filled = c.verify.filled[:payloadEnd]
			c.verify.contig = min(c.verify.contig, payloadEnd)
		}
	}
}

type sequenceRange struct {
	start, end units.Seq
}

// Bound the receive scoreboard independently of payload verification. It stores
// sequence intervals rather than one allocation per byte, including FIN's byte
// of sequence space. Serial-number comparisons remain valid across wraparound.
const (
	maxPendingRanges = 1024
	maxReorderSpan   = 16 << 20
)

func (c *Conversation) receiveRange(start, end units.Seq) error {
	if !end.Greater(c.serverRcvd) || start == end {
		return nil
	}
	if c.serverRcvd.Delta(end) > maxReorderSpan {
		return fmt.Errorf("server sequence exceeds the %d-byte receive reordering limit", maxReorderSpan)
	}
	if start.LessEqual(c.serverRcvd) {
		c.serverRcvd = end
	} else {
		// Keep disjoint ranges ordered by sequence, merging overlaps and
		// adjacent segments so retransmissions cannot grow the scoreboard.
		i := 0
		for i < len(c.serverPending) && c.serverPending[i].end.Less(start) {
			i++
		}
		j := i
		for j < len(c.serverPending) && c.serverPending[j].start.LessEqual(end) {
			if c.serverPending[j].start.Less(start) {
				start = c.serverPending[j].start
			}
			if c.serverPending[j].end.Greater(end) {
				end = c.serverPending[j].end
			}
			j++
		}
		if i == j {
			if len(c.serverPending) >= maxPendingRanges {
				return fmt.Errorf("server receive reordering exceeds %d disjoint ranges", maxPendingRanges)
			}
			c.serverPending = append(c.serverPending, sequenceRange{})
			copy(c.serverPending[i+1:], c.serverPending[i:])
		} else {
			copy(c.serverPending[i+1:], c.serverPending[j:])
			c.serverPending = c.serverPending[:len(c.serverPending)-(j-i)+1]
		}
		c.serverPending[i] = sequenceRange{start: start, end: end}
	}
	for len(c.serverPending) > 0 && c.serverPending[0].start.LessEqual(c.serverRcvd) {
		if c.serverPending[0].end.Greater(c.serverRcvd) {
			c.serverRcvd = c.serverPending[0].end
		}
		c.serverPending = c.serverPending[1:]
	}
	return nil
}
