package wire

import (
	"encoding/binary"
	"net/netip"

	"github.com/kvmukilan/livewire/internal/units"
)

// In-place field mutators. Call RecalcChecksums after changing any field.

// SetSrcMAC sets the Ethernet source MAC. No-op on non-Ethernet frames.
func (p *Packet) SetSrcMAC(mac [6]byte) {
	if p.hasEth {
		copy(p.Buf[6:12], mac[:])
	}
}

// SetDstMAC sets the Ethernet destination MAC. No-op on non-Ethernet frames.
func (p *Packet) SetDstMAC(mac [6]byte) {
	if p.hasEth {
		copy(p.Buf[0:6], mac[:])
	}
}

// SrcMAC returns the Ethernet source MAC (zero if not Ethernet).
func (p *Packet) SrcMAC() (mac [6]byte) {
	if p.hasEth {
		copy(mac[:], p.Buf[6:12])
	}
	return
}

// DstMAC returns the Ethernet destination MAC (zero if not Ethernet).
func (p *Packet) DstMAC() (mac [6]byte) {
	if p.hasEth {
		copy(mac[:], p.Buf[0:6])
	}
	return
}

// SetSrcIP writes a new source IP. The address family must match the packet.
func (p *Packet) SetSrcIP(a netip.Addr) bool { return p.setIP(p.srcIPOff(), a) }

// SetDstIP writes a new destination IP. The address family must match.
func (p *Packet) SetDstIP(a netip.Addr) bool { return p.setIP(p.dstIPOff(), a) }

func (p *Packet) setIP(off int, a netip.Addr) bool {
	if p.isV4 && a.Is4() {
		v := a.As4()
		copy(p.Buf[off:off+4], v[:])
		return true
	}
	if p.isV6 && a.Is6() && !a.Is4In6() {
		v := a.As16()
		copy(p.Buf[off:off+16], v[:])
		return true
	}
	return false
}

// SetSrcPort sets the transport source port.
func (p *Packet) SetSrcPort(port uint16) {
	if p.isTCP || p.isUDP {
		binary.BigEndian.PutUint16(p.Buf[p.l4Off:p.l4Off+2], port)
	}
}

// SetDstPort sets the transport destination port.
func (p *Packet) SetDstPort(port uint16) {
	if p.isTCP || p.isUDP {
		binary.BigEndian.PutUint16(p.Buf[p.l4Off+2:p.l4Off+4], port)
	}
}

// SetSeq sets the TCP sequence number.
func (p *Packet) SetSeq(s units.Seq) {
	if p.isTCP {
		binary.BigEndian.PutUint32(p.Buf[p.l4Off+4:p.l4Off+8], s.Uint32())
	}
}

// SetAck sets the TCP acknowledgement number.
func (p *Packet) SetAck(a units.Ack) {
	if p.isTCP {
		binary.BigEndian.PutUint32(p.Buf[p.l4Off+8:p.l4Off+12], a.Uint32())
	}
}

// SetFlags sets the TCP flags byte.
func (p *Packet) SetFlags(f uint8) {
	if p.isTCP {
		p.Buf[p.l4Off+13] = f
	}
}

// SetWindow sets the raw TCP window field.
func (p *Packet) SetWindow(w uint16) {
	if p.isTCP {
		binary.BigEndian.PutUint16(p.Buf[p.l4Off+14:p.l4Off+16], w)
	}
}

// SetTTL sets the IPv4 TTL or IPv6 hop limit.
func (p *Packet) SetTTL(ttl uint8) {
	switch {
	case p.isV4:
		p.Buf[p.l3Off+8] = ttl
	case p.isV6:
		p.Buf[p.l3Off+7] = ttl
	}
}

// l4Segment returns the transport header+payload slice bounded by the IP length.
func (p *Packet) l4Segment() []byte {
	end := p.l4Off + p.l4TotalLen
	if end > len(p.Buf) {
		end = len(p.Buf)
	}
	return p.Buf[p.l4Off:end]
}

func (p *Packet) srcIPBytes() []byte {
	if p.isV4 {
		return p.Buf[p.l3Off+12 : p.l3Off+16]
	}
	return p.Buf[p.l3Off+8 : p.l3Off+24]
}

func (p *Packet) dstIPBytes() []byte {
	if p.isV4 {
		return p.Buf[p.l3Off+16 : p.l3Off+20]
	}
	return p.Buf[p.l3Off+24 : p.l3Off+40]
}

// RecalcChecksums recomputes the IPv4 header checksum (if any) and the TCP/UDP/ICMP
// checksum. Computed over IP-indicated lengths so trailing padding is excluded.
func (p *Packet) RecalcChecksums() {
	p.recalcIPv4Header()
	if !p.isTCP && !p.isUDP && !p.isICMP {
		return
	}
	seg := p.l4Segment()
	if len(seg) < 8 {
		return
	}
	// Zero the checksum field: TCP at offset 16, UDP at offset 6, ICMP at offset 2.
	var csumOff int
	if p.isTCP {
		csumOff = 16
	} else if p.isUDP {
		csumOff = 6
	} else {
		csumOff = 2
	}
	if csumOff+2 > len(seg) {
		return
	}
	seg[csumOff], seg[csumOff+1] = 0, 0

	var pseudo uint32
	if p.isICMP && p.isV4 {
		// ICMPv4 has no pseudo-header.
		pseudo = 0
	} else if p.isV4 {
		pseudo = pseudoSumV4(p.srcIPBytes(), p.dstIPBytes(), p.proto, len(seg))
	} else {
		pseudo = pseudoSumV6(p.srcIPBytes(), p.dstIPBytes(), p.proto, len(seg))
	}
	sum := l4Checksum(pseudo, seg)
	if p.isUDP && sum == 0 {
		sum = 0xffff // a computed 0 is transmitted as 0xFFFF
	}
	binary.BigEndian.PutUint16(seg[csumOff:csumOff+2], sum)
}

func (p *Packet) recalcIPv4Header() {
	if !p.isV4 {
		return
	}
	hdr := p.Buf[p.l3Off : p.l3Off+p.l3HdrLn]
	hdr[10], hdr[11] = 0, 0
	binary.BigEndian.PutUint16(hdr[10:12], ipv4HeaderChecksum(hdr))
}

// VerifyChecksums reports whether the IPv4 header and transport checksums are
// already correct.
func (p *Packet) VerifyChecksums() (ipOK, l4OK bool) {
	ipOK = true
	if p.isV4 {
		hdr := p.Buf[p.l3Off : p.l3Off+p.l3HdrLn]
		ipOK = fold(sumBytes(hdr, 0)) == 0
	}
	l4OK = true
	if p.isTCP || p.isUDP || p.isICMP {
		seg := p.l4Segment()
		if len(seg) >= 8 {
			var pseudo uint32
			if p.isICMP && p.isV4 {
				pseudo = 0
			} else if p.isV4 {
				pseudo = pseudoSumV4(p.srcIPBytes(), p.dstIPBytes(), p.proto, len(seg))
			} else {
				pseudo = pseudoSumV6(p.srcIPBytes(), p.dstIPBytes(), p.proto, len(seg))
			}
			// A correct segment sums (with its stored checksum) to zero, except
			// UDP-over-IPv4 with a transmitted checksum of 0 (disabled).
			if p.isUDP && seg[6] == 0 && seg[7] == 0 && p.isV4 {
				l4OK = true
			} else {
				l4OK = fold(sumBytes(seg, pseudo)) == 0
			}
		}
	}
	return
}
