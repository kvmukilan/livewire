// Package ipreasm reassembles fragmented IPv4 datagrams into whole ones. Only
// the first fragment carries the transport header; the rest are payload at an
// offset. livewire stitches them back together before the engine or a
// dissector sees a segment. Runs offline over a capture.
//
// IPv6 fragmentation is not yet handled; such packets pass through untouched.
package ipreasm

import (
	"encoding/binary"
	"sort"

	"github.com/kvmukilan/livewire/internal/wire"
)

type fragKey struct {
	src, dst [16]byte
	id       uint16
	proto    uint8
}

type piece struct {
	offset int
	data   []byte
	more   bool
}

type buffer struct {
	l2ip   []byte // L2 + IP header from the offset-0 fragment
	l3Off  int
	ihl    int
	link   wire.LinkType
	pieces []piece
	seen   int // arrival order of the last piece, for output ordering
}

// ReassembleAll returns the reassembled and pass-through frames. Non-fragments
// pass through in place; a datagram is emitted when its final fragment arrives.
// Fragment sets still incomplete at the end are dropped and counted in dropped.
func ReassembleAll(frames [][]byte, link wire.LinkType) (out [][]byte, dropped int, err error) {
	bufs := map[fragKey]*buffer{}
	order := 0
	for _, frame := range frames {
		p, perr := wire.Parse(frame, link)
		if perr != nil || !p.IsIPv4() || !p.IsFragment() {
			out = append(out, frame) // pass through untouched
			continue
		}
		key, b := keyAndBuffer(bufs, p, frame, link)
		payload := fragmentPayload(p, frame)
		b.pieces = append(b.pieces, piece{offset: p.FragmentOffset(), data: payload, more: p.MoreFragments()})
		order++
		b.seen = order

		whole, ok := b.tryAssemble()
		if !ok {
			continue
		}
		delete(bufs, key)
		out = append(out, whole)
	}
	dropped = len(bufs)
	return out, dropped, nil
}

func keyAndBuffer(bufs map[fragKey]*buffer, p *wire.Packet, frame []byte, link wire.LinkType) (fragKey, *buffer) {
	var key fragKey
	src := p.SrcIP().As16()
	dst := p.DstIP().As16()
	key.src, key.dst = src, dst
	key.id = p.FragmentID()
	key.proto = p.Proto()

	b := bufs[key]
	if b == nil {
		b = &buffer{link: link, l3Off: p.L3Offset(), ihl: p.L3HeaderLen()}
		bufs[key] = b
	}
	// The offset-0 fragment donates the L2+IP header for the rebuild.
	if p.FragmentOffset() == 0 && b.l2ip == nil {
		hdrEnd := p.L3Offset() + p.L3HeaderLen()
		b.l2ip = append([]byte(nil), frame[:hdrEnd]...)
		b.l3Off = p.L3Offset()
		b.ihl = p.L3HeaderLen()
	}
	return key, b
}

// fragmentPayload returns the IP payload bytes this fragment carries.
func fragmentPayload(p *wire.Packet, frame []byte) []byte {
	start := p.L3PayloadOffset()
	total := int(binary.BigEndian.Uint16(frame[p.L3Offset()+2 : p.L3Offset()+4]))
	end := p.L3Offset() + total
	if end > len(frame) {
		end = len(frame)
	}
	if start > end {
		start = end
	}
	return append([]byte(nil), frame[start:end]...)
}

// tryAssemble returns the reassembled frame once the set is complete: a piece at
// offset 0, contiguous coverage, and a final piece with MF clear.
func (b *buffer) tryAssemble() ([]byte, bool) {
	if b.l2ip == nil {
		return nil, false // never saw the first fragment
	}
	ps := append([]piece(nil), b.pieces...)
	sort.Slice(ps, func(i, j int) bool { return ps[i].offset < ps[j].offset })

	if ps[0].offset != 0 {
		return nil, false
	}
	var payload []byte
	next := 0
	sawLast := false
	for _, pc := range ps {
		if pc.offset > next {
			return nil, false // hole
		}
		if pc.offset < next {
			// overlap: trim to the contiguous boundary
			trim := next - pc.offset
			if trim >= len(pc.data) {
				continue
			}
			pc.data = pc.data[trim:]
			pc.offset = next
		}
		payload = append(payload, pc.data...)
		next += len(pc.data)
		if !pc.more {
			sawLast = true
		}
	}
	if !sawLast {
		return nil, false
	}

	frame := append(append([]byte(nil), b.l2ip...), payload...)
	// Fix IP total length, clear flags/offset, recompute checksums.
	total := b.ihl + len(payload)
	binary.BigEndian.PutUint16(frame[b.l3Off+2:b.l3Off+4], uint16(total))
	frame[b.l3Off+6], frame[b.l3Off+7] = 0, 0
	if p, err := wire.Parse(frame, b.link); err == nil {
		p.RecalcChecksums()
		return p.Buf, true
	}
	return frame, true
}

// CountFragments reports how many frames in a capture are IPv4 fragments, for a
// summary line in `info`.
func CountFragments(frames [][]byte, link wire.LinkType) int {
	n := 0
	for _, frame := range frames {
		if p, err := wire.Parse(frame, link); err == nil && p.IsFragment() {
			n++
		}
	}
	return n
}
