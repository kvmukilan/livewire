package engine

import (
	"math/rand"
	"time"

	"github.com/kvmukilan/livewire/internal/units"
	"github.com/kvmukilan/livewire/internal/wire"
)

// PeerBehavior scripts how the simulated device deviates from a compliant
// server: re-segmentation, packet loss, resets.
type PeerBehavior uint8

const (
	// BehaviorCompliant replays the captured server side faithfully.
	BehaviorCompliant PeerBehavior = iota
	// BehaviorReSegment splits each server data packet in two (frame boundaries
	// no longer match the capture), exercising byte-count tracking.
	BehaviorReSegment
	// BehaviorDropFirstResponse withholds the first server data packet, then
	// re-delivers it on client retransmit, exercising loss recovery.
	BehaviorDropFirstResponse
	// BehaviorResetOnData answers the first client data with a RST, exercising abort.
	BehaviorResetOnData
)

// MockPeer is a capture-driven Responder impersonating the live server: it picks
// a hidden ISN (the engine must recover it from the SYN-ACK), learns the client
// ISN from the SYN, and emits captured server packets in its own sequence space,
// clocked by client progress. Implements backend.Responder without importing backend.
type MockPeer struct {
	flow     *Flow
	behavior PeerBehavior
	link     wire.LinkType

	sess      *Session
	hiddenISN uint32
	tsBaseC   uint32
	tsBaseS   uint32
	ready     bool

	pi         int       // cursor over flow.Packets for server emission
	cliHigh    units.Seq // highest contiguous client sequence end received (live space)
	cliHighSet bool

	dropUsed     bool
	stash        [][]byte // withheld frames, re-emitted on client retransmit
	lastClientTS uint32
}

// NewMockPeer builds a simulated device for a flow. Timestamp bases come from
// opts; the server ISN is drawn from a stream the engine cannot observe.
func NewMockPeer(f *Flow, b PeerBehavior, opts Options) *MockPeer {
	_, _, tsC, tsS := opts.isns()
	return &MockPeer{
		flow:      f,
		behavior:  b,
		link:      f.Packets[0].Rec.LinkType,
		hiddenISN: peerISNFrom(opts),
		tsBaseC:   tsC,
		tsBaseS:   tsS,
	}
}

// HiddenISN is the server ISN the peer chose; the engine must recover exactly this.
func (p *MockPeer) HiddenISN() uint32 { return p.hiddenISN }

// OnSend consumes a client frame and returns the server's response frames.
func (p *MockPeer) OnSend(frame []byte, _ time.Time) [][]byte {
	pk, err := wire.Parse(frame, p.link)
	if err != nil || !pk.IsTCP() {
		return nil
	}
	if tsv, _, ok := pk.Timestamps(); ok {
		p.lastClientTS = tsv // echoed in every server frame's TSecr
	}

	if !p.ready {
		if pk.HasFlags(wire.FlagSYN) && !pk.HasFlags(wire.FlagACK) {
			p.setup(pk.Seq())
		} else {
			return nil // ignore anything before the handshake opens
		}
	}

	end := pk.Seq().Add(pk.SegmentLen())
	if p.cliHighSet && !end.Greater(p.cliHigh) {
		// No new client bytes: a retransmit or bare ACK. If we're holding a
		// withheld response, deliver it now.
		if len(p.stash) > 0 {
			out := p.stash
			p.stash = nil
			return out
		}
		return nil
	}
	p.cliHigh, p.cliHighSet = end, true
	return p.emitBurst()
}

// setup initialises the peer's sequence space on the SYN: learn the client ISN,
// pin the hidden server ISN.
func (p *MockPeer) setup(clientLiveISN units.Seq) {
	p.sess = NewSession(p.flow, clientLiveISN, p.tsBaseC, p.tsBaseS)
	p.sess.SetServerISN(units.Seq(p.hiddenISN))
	p.ready = true
}

// emitBurst emits every server packet unlocked by client progress, stopping at
// the next client packet not yet fully received.
func (p *MockPeer) emitBurst() [][]byte {
	var out [][]byte
	for p.pi < len(p.flow.Packets) {
		cp := p.flow.Packets[p.pi]
		if cp.Dir == C2S {
			end := cp.Seq.AddDelta(p.sess.ClientDelta).Add(cp.SegLen)
			if end.Greater(p.cliHigh) {
				break // still waiting on this client packet
			}
			p.pi++ // already covered; the peer emits nothing for client packets
			continue
		}
		out = append(out, p.render(cp)...)
		p.pi++
	}
	return out
}

// render turns one captured server packet into the frames the peer puts on the
// wire, applying its scripted behaviour.
func (p *MockPeer) render(cp CapturedPacket) [][]byte {
	buf, _, err := p.sess.Rewrite(cp)
	if err != nil {
		return nil
	}
	p.fixTSecr(buf)
	hasPayload := cp.PayloadLen > 0

	switch p.behavior {
	case BehaviorReSegment:
		if hasPayload {
			if parts, ok := splitTCP(buf, p.link, cp.PayloadLen/2); ok {
				return parts
			}
		}
	case BehaviorDropFirstResponse:
		if hasPayload && !p.dropUsed {
			p.dropUsed = true
			p.stash = append(p.stash, buf) // withhold until the client retransmits
			return nil
		}
	case BehaviorResetOnData:
		if hasPayload {
			if rst, ok := makeRST(buf, p.link); ok {
				return [][]byte{rst}
			}
		}
	}
	return [][]byte{buf}
}

// fixTSecr sets a server frame's timestamp echo to the client's latest TSval so
// a PAWS-checking client accepts it (RFC 7323).
func (p *MockPeer) fixTSecr(buf []byte) {
	pk, err := wire.Parse(buf, p.link)
	if err != nil {
		return
	}
	if tsv, _, ok := pk.Timestamps(); ok {
		pk.SetTimestamps(tsv, p.lastClientTS)
		pk.RecalcChecksums()
	}
}

// peerISNFrom draws the peer's hidden ISN from a stream independent of the
// engine's, so SYN-ACK recovery is a real measurement.
func peerISNFrom(o Options) uint32 {
	return rand.New(rand.NewSource(o.Seed ^ 0x5DEECE66D)).Uint32()
}

// splitTCP splits a TCP frame into two carrying the first n and remaining payload
// bytes, bumping the second segment's seq and fixing lengths/checksums. Link- and
// address-family-agnostic. Returns ok=false if the frame is not TCP or can't split at n.
func splitTCP(frame []byte, link wire.LinkType, n int) ([][]byte, bool) {
	p, err := wire.Parse(frame, link)
	if err != nil || !p.IsTCP() {
		return nil, false
	}
	pl := p.PayloadLen()
	if n <= 0 || n >= pl {
		return nil, false
	}
	payload := append([]byte(nil), p.Payload()[:pl]...)

	first := p.RebuildWithPayload(payload[:n])
	p.SetSeq(p.Seq().AddDelta(uint32(n))) // second segment's seq
	second := p.RebuildWithPayload(payload[n:])
	return [][]byte{first, second}, true
}

// makeRST turns a TCP frame into a payload-free RST|ACK with the same 4-tuple.
func makeRST(frame []byte, link wire.LinkType) ([]byte, bool) {
	p, err := wire.Parse(frame, link)
	if err != nil || !p.IsTCP() {
		return nil, false
	}
	p.SetFlags(wire.FlagRST | wire.FlagACK)
	return p.RebuildWithPayload(nil), true
}
