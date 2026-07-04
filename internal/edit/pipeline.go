// Package edit applies static offline packet rewrites (tcprewrite-style): MAC,
// IP pseudo-NAT, port maps, TTL, and a uniform TCP sequence shift. Fields are
// mutated first, checksums recomputed last.
package edit

import (
	"net/netip"

	"github.com/kvmukilan/livewire/internal/wire"
)

// IPMap is a pseudo-NAT rule: Match's network bits become Rewrite's, host bits
// preserved.
type IPMap struct {
	Match   netip.Prefix
	Rewrite netip.Prefix
}

// Rules is a declarative set of static rewrites. Zero-value fields are no-ops.
type Rules struct {
	SrcMAC   *[6]byte
	DstMAC   *[6]byte
	SrcIPMap []IPMap
	DstIPMap []IPMap
	PortMap  map[uint16]uint16
	TTL      *uint8
	SeqShift uint32 // uniform offset added to every TCP seq and ack (tcprewrite --tcp-sequence)

	// Structural (applied before field rewrites, at the buffer level).
	StripVLAN bool
	PushVLAN  *VLANTag
}

// VLANTag describes a tag to insert.
type VLANTag struct {
	VID uint16
	PCP uint8
}

// PreTransform applies length-changing edits to a raw frame; call before Parse.
func (r *Rules) PreTransform(buf []byte) []byte {
	if r.StripVLAN {
		buf = wire.StripVLANs(buf)
	}
	if r.PushVLAN != nil {
		buf = wire.PushVLAN(buf, r.PushVLAN.VID, r.PushVLAN.PCP)
	}
	return buf
}

// Apply rewrites fields in place and recomputes checksums; reports whether
// anything changed.
func (r *Rules) Apply(p *wire.Packet) bool {
	changed := false

	if r.SrcMAC != nil {
		p.SetSrcMAC(*r.SrcMAC)
		changed = true
	}
	if r.DstMAC != nil {
		p.SetDstMAC(*r.DstMAC)
		changed = true
	}

	if len(r.SrcIPMap) > 0 {
		if na, ok := mapIP(p.SrcIP(), r.SrcIPMap); ok {
			p.SetSrcIP(na)
			changed = true
		}
	}
	if len(r.DstIPMap) > 0 {
		if na, ok := mapIP(p.DstIP(), r.DstIPMap); ok {
			p.SetDstIP(na)
			changed = true
		}
	}

	if len(r.PortMap) > 0 && (p.IsTCP() || p.IsUDP()) {
		if np, ok := r.PortMap[p.SrcPort()]; ok {
			p.SetSrcPort(np)
			changed = true
		}
		if np, ok := r.PortMap[p.DstPort()]; ok {
			p.SetDstPort(np)
			changed = true
		}
	}

	if r.TTL != nil {
		p.SetTTL(*r.TTL)
		changed = true
	}

	if r.SeqShift != 0 && p.IsTCP() {
		p.SetSeq(p.Seq().Add(r.SeqShift))
		p.SetAck(p.AckNum().Add(r.SeqShift))
		changed = true
	}

	if changed {
		p.RecalcChecksums()
	}
	return changed
}

// mapIP applies the first matching rule, preserving host bits below the prefix.
func mapIP(a netip.Addr, maps []IPMap) (netip.Addr, bool) {
	for _, m := range maps {
		if !m.Match.Contains(a) {
			continue
		}
		if a.Is4() != m.Rewrite.Addr().Is4() {
			continue // family mismatch
		}
		if a.Is4() {
			return remapBits4(a, m.Rewrite), true
		}
		return remapBits16(a, m.Rewrite), true
	}
	return a, false
}

func remapBits4(a netip.Addr, to netip.Prefix) netip.Addr {
	host := a.As4()
	netw := to.Addr().As4()
	bits := to.Bits()
	var out [4]byte
	for i := 0; i < 4; i++ {
		mask := prefixByteMask(bits, i)
		out[i] = (netw[i] & mask) | (host[i] &^ mask)
	}
	return netip.AddrFrom4(out)
}

func remapBits16(a netip.Addr, to netip.Prefix) netip.Addr {
	host := a.As16()
	netw := to.Addr().As16()
	bits := to.Bits()
	var out [16]byte
	for i := 0; i < 16; i++ {
		mask := prefixByteMask(bits, i)
		out[i] = (netw[i] & mask) | (host[i] &^ mask)
	}
	return netip.AddrFrom16(out)
}

// prefixByteMask returns the mask byte for octet i given a prefix length in bits.
func prefixByteMask(bits, i int) byte {
	high := (i + 1) * 8
	switch {
	case bits >= high:
		return 0xff
	case bits <= i*8:
		return 0x00
	default:
		return byte(0xff << uint(high-bits))
	}
}
