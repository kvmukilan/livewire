package wire

import (
	"encoding/binary"
	"net/netip"
)

// RewriteFragmentTuple retargets one IP fragment without recomputing a
// transport checksum over incomplete bytes. On the first fragment it updates
// the stored TCP/UDP/ICMPv6 checksum incrementally (RFC 1624) for pseudo-header
// and port changes; later fragments only need their IP addresses/header checksum
// rewritten. It returns false when the protocol has an unknown address-bound
// checksum and therefore cannot be adapted safely.
func (p *Packet) RewriteFragmentTuple(src, dst netip.Addr, srcPort, dstPort uint16) bool {
	if !p.IsFragment() || p.isV4 != src.Is4() || p.isV4 != dst.Is4() || p.isV6 && (src.Is4In6() || dst.Is4In6()) {
		return false
	}
	oldSrc := append([]byte(nil), p.srcIPBytes()...)
	oldDst := append([]byte(nil), p.dstIPBytes()...)
	newSrc, newDst := addressBytes(src), addressBytes(dst)
	if newSrc == nil || newDst == nil {
		return false
	}

	first := p.FragmentOffset() == 0
	var checksumOffset int
	checksumBoundToAddress := false
	oldSrcPort, oldDstPort := uint16(0), uint16(0)
	if first {
		switch {
		case p.isTCP:
			checksumOffset, checksumBoundToAddress = p.l4Off+16, true
			oldSrcPort, oldDstPort = p.SrcPort(), p.DstPort()
		case p.isUDP:
			checksumOffset, checksumBoundToAddress = p.l4Off+6, true
			oldSrcPort, oldDstPort = p.SrcPort(), p.DstPort()
		case p.isICMP && p.isV6:
			checksumOffset, checksumBoundToAddress = p.l4Off+2, true
		case p.isICMP && p.isV4:
			// ICMPv4 has no pseudo-header; only the IPv4 header changes.
		default:
			if !equalBytes(oldSrc, newSrc) || !equalBytes(oldDst, newDst) {
				return false
			}
		}
	}

	if checksumBoundToAddress {
		if checksumOffset+2 > len(p.Buf) {
			return false
		}
		stored := binary.BigEndian.Uint16(p.Buf[checksumOffset : checksumOffset+2])
		udpV4Disabled := p.isUDP && p.isV4 && stored == 0
		if !udpV4Disabled {
			updated := stored
			for i := 0; i < len(oldSrc); i += 2 {
				updated = checksumReplaceWord(updated, binary.BigEndian.Uint16(oldSrc[i:i+2]), binary.BigEndian.Uint16(newSrc[i:i+2]))
				updated = checksumReplaceWord(updated, binary.BigEndian.Uint16(oldDst[i:i+2]), binary.BigEndian.Uint16(newDst[i:i+2]))
			}
			if p.isTCP || p.isUDP {
				updated = checksumReplaceWord(updated, oldSrcPort, srcPort)
				updated = checksumReplaceWord(updated, oldDstPort, dstPort)
			}
			if p.isUDP && updated == 0 {
				updated = 0xffff
			}
			binary.BigEndian.PutUint16(p.Buf[checksumOffset:checksumOffset+2], updated)
		}
	}
	if !p.SetSrcIP(src) || !p.SetDstIP(dst) {
		return false
	}
	if first && (p.isTCP || p.isUDP) {
		p.SetSrcPort(srcPort)
		p.SetDstPort(dstPort)
	}
	p.recalcIPv4Header()
	return true
}

func addressBytes(address netip.Addr) []byte {
	if address.Is4() {
		value := address.As4()
		return value[:]
	}
	if address.Is6() && !address.Is4In6() {
		value := address.As16()
		return value[:]
	}
	return nil
}

func checksumReplaceWord(checksum, oldWord, newWord uint16) uint16 {
	sum := uint32(^checksum) + uint32(^oldWord) + uint32(newWord)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
