package backend

import (
	"encoding/binary"
	"net"
	"net/netip"
)

const ethIPv6 = 0x86DD

// buildNS assembles an Ethernet/IPv6/ICMPv6 Neighbor Solicitation with the
// source-link-layer-address option and a correct ICMPv6 checksum.
func buildNS(srcMAC, dstMAC net.HardwareAddr, src, dst, target netip.Addr) []byte {
	icmp := make([]byte, 32)
	icmp[0] = 135
	t := target.As16()
	copy(icmp[8:24], t[:])
	icmp[24], icmp[25] = 1, 1
	copy(icmp[26:32], srcMAC)

	sa, da := src.As16(), dst.As16()
	binary.BigEndian.PutUint16(icmp[2:4], icmpv6Checksum(sa[:], da[:], icmp))
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(icmp)))
	ip[6], ip[7] = 58, 255
	copy(ip[8:24], sa[:])
	copy(ip[24:40], da[:])
	eth := make([]byte, 14)
	copy(eth[0:6], dstMAC)
	copy(eth[6:12], srcMAC)
	binary.BigEndian.PutUint16(eth[12:14], ethIPv6)
	return append(append(eth, ip...), icmp...)
}

func parseNA(frame []byte, wantIP netip.Addr) (net.HardwareAddr, bool) {
	const eth = 14
	if len(frame) < eth+40+24 || binary.BigEndian.Uint16(frame[12:14]) != ethIPv6 || frame[eth]>>4 != 6 || frame[eth+6] != 58 {
		return nil, false
	}
	icmp := frame[eth+40:]
	if icmp[0] != 136 {
		return nil, false
	}
	var tgt [16]byte
	copy(tgt[:], icmp[8:24])
	if netip.AddrFrom16(tgt) != wantIP.WithZone("") {
		return nil, false
	}
	for opts := icmp[24:]; len(opts) >= 8; {
		olen := int(opts[1]) * 8
		if olen == 0 || olen > len(opts) {
			break
		}
		if opts[0] == 2 {
			return append(net.HardwareAddr(nil), opts[2:8]...), true
		}
		opts = opts[olen:]
	}
	return append(net.HardwareAddr(nil), frame[6:12]...), true
}

func icmpv6Checksum(src, dst, msg []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(src)
	add(dst)
	var plen [4]byte
	binary.BigEndian.PutUint32(plen[:], uint32(len(msg)))
	add(plen[:])
	add([]byte{0, 0, 0, 58})
	add(msg)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
