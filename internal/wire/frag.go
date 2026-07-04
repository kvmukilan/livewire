package wire

import "encoding/binary"

// IPv4 fragmentation accessors. Only the first fragment holds the transport
// header, so fragments must be reassembled (see internal/ipreasm) before L4.

// FragmentID returns the IPv4 identification field (meaningless for non-IPv4).
func (p *Packet) FragmentID() uint16 {
	if !p.isV4 {
		return 0
	}
	return binary.BigEndian.Uint16(p.Buf[p.l3Off+4 : p.l3Off+6])
}

// fragWord returns the IPv4 flags+offset 16-bit word.
func (p *Packet) fragWord() uint16 {
	return binary.BigEndian.Uint16(p.Buf[p.l3Off+6 : p.l3Off+8])
}

// MoreFragments reports whether the IPv4 MF bit is set (more fragments follow).
func (p *Packet) MoreFragments() bool {
	if !p.isV4 {
		return false
	}
	return p.fragWord()&0x2000 != 0
}

// DontFragment reports whether the IPv4 DF bit is set.
func (p *Packet) DontFragment() bool {
	if !p.isV4 {
		return false
	}
	return p.fragWord()&0x4000 != 0
}

// FragmentOffset returns the fragment's payload offset in bytes (0 for the
// first fragment or an unfragmented datagram).
func (p *Packet) FragmentOffset() int {
	if !p.isV4 {
		return 0
	}
	return int(p.fragWord()&0x1fff) * 8
}

// IsFragment reports whether the packet is a piece of a fragmented IPv4
// datagram (MF set or non-zero offset).
func (p *Packet) IsFragment() bool {
	if !p.isV4 {
		return false
	}
	return p.MoreFragments() || p.FragmentOffset() > 0
}

// L3PayloadOffset returns the offset where the IP payload begins.
func (p *Packet) L3PayloadOffset() int { return p.l3Off + p.l3HdrLn }

// L3HeaderLen returns the IP header length in bytes.
func (p *Packet) L3HeaderLen() int { return p.l3HdrLn }

// L3Offset returns where the IP header begins (after any L2 header).
func (p *Packet) L3Offset() int { return p.l3Off }
