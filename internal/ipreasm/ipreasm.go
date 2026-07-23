// Package ipreasm reassembles fragmented IPv4 and IPv6 datagrams into whole
// ones. Only
// the first fragment carries the transport header; the rest are payload at an
// offset. livewire stitches them back together before the engine or a
// dissector sees a segment. Runs offline over a capture.
package ipreasm

import (
	"bytes"
	"encoding/binary"
	"sort"

	"github.com/kvmukilan/livewire/internal/wire"
)

type fragKey struct {
	src, dst [16]byte
	id       uint16
	proto    uint8
}

type frag6Key struct {
	src, dst [16]byte
	id       uint32
	next     uint8
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

type buffer6 struct {
	prefix          []byte // L2 + IPv6 + unfragmentable extension headers
	l3Off           int
	previousNextOff int
	next            uint8
	link            wire.LinkType
	pieces          []piece
}

// ReassembleAll returns the reassembled and pass-through frames. Non-fragments
// pass through in place; a datagram is emitted when its final fragment arrives.
// Fragment sets still incomplete at the end are dropped and counted in dropped.
func ReassembleAll(frames [][]byte, link wire.LinkType) (out [][]byte, dropped int, err error) {
	bufs := map[fragKey]*buffer{}
	bufs6 := map[frag6Key]*buffer6{}
	order := 0
	for _, frame := range frames {
		p, perr := wire.Parse(frame, link)
		if perr != nil || !p.IsFragment() {
			out = append(out, frame) // pass through untouched
			continue
		}
		if p.IsIPv6() {
			id, offset, more, next, headerOff, previousNextOff, ok := p.IPv6Fragment()
			if !ok {
				out = append(out, frame)
				continue
			}
			key := frag6Key{src: p.SrcIP().As16(), dst: p.DstIP().As16(), id: id, next: next}
			b := bufs6[key]
			if b == nil {
				b = &buffer6{l3Off: p.L3Offset(), previousNextOff: previousNextOff, next: next, link: link}
				bufs6[key] = b
			}
			if offset == 0 && b.prefix == nil {
				b.prefix = append([]byte(nil), frame[:headerOff]...)
				b.previousNextOff = previousNextOff
			}
			start := headerOff + 8
			end := p.L3Offset() + 40 + int(binary.BigEndian.Uint16(frame[p.L3Offset()+4:p.L3Offset()+6]))
			if end > len(frame) {
				end = len(frame)
			}
			if start > end {
				start = end
			}
			b.pieces = append(b.pieces, piece{offset: offset, data: append([]byte(nil), frame[start:end]...), more: more})
			whole, complete := b.tryAssemble()
			if complete {
				delete(bufs6, key)
				out = append(out, whole)
			}
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
	dropped = len(bufs) + len(bufs6)
	return out, dropped, nil
}

func (b *buffer6) tryAssemble() ([]byte, bool) {
	payload, ok := assemblePieces(b.pieces)
	if !ok || b.prefix == nil {
		return nil, false
	}
	frame := append(append([]byte(nil), b.prefix...), payload...)
	frame[b.previousNextOff] = b.next
	// IPv6 payload length includes unfragmentable extension headers after the
	// fixed 40-byte header plus the reassembled fragmentable payload.
	ext := len(b.prefix) - (b.l3Off + 40)
	binary.BigEndian.PutUint16(frame[b.l3Off+4:b.l3Off+6], uint16(ext+len(payload)))
	if p, err := wire.Parse(frame, b.link); err == nil {
		p.RecalcChecksums()
		return p.Buf, true
	}
	return frame, true
}

func assemblePieces(pieces []piece) ([]byte, bool) {
	if len(pieces) == 0 {
		return nil, false
	}
	ps := append([]piece(nil), pieces...)
	sort.Slice(ps, func(i, j int) bool { return ps[i].offset < ps[j].offset })
	if ps[0].offset != 0 {
		return nil, false
	}
	var payload []byte
	next := 0
	sawLast := false
	for _, pc := range ps {
		if pc.offset > next {
			return nil, false
		}
		if pc.offset < next {
			trim := next - pc.offset
			overlap := trim
			if overlap > len(pc.data) {
				overlap = len(pc.data)
			}
			if pc.offset+overlap > len(payload) || !bytes.Equal(payload[pc.offset:pc.offset+overlap], pc.data[:overlap]) {
				return nil, false // ambiguous/conflicting overlap is unsafe to replay semantically
			}
			if trim >= len(pc.data) {
				if !pc.more {
					sawLast = true
				}
				continue
			}
			pc.data = pc.data[trim:]
		}
		payload = append(payload, pc.data...)
		next += len(pc.data)
		if !pc.more {
			sawLast = true
		}
	}
	return payload, sawLast
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
	payload, ok := assemblePieces(b.pieces)
	if !ok {
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

// CountFragments reports how many frames in a capture are IP fragments, for a
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
