//go:build linux

package backend

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"
)

// IPv6 next-hop resolution uses NDP (Neighbor Discovery, RFC 4861): send an
// ICMPv6 Neighbor Solicitation to the target's solicited-node multicast group
// and read the Neighbor Advertisement for the link-layer address. Builds the
// whole L2 frame over an AF_PACKET raw socket, like the ARP path. Linux-only.

const ethIPv6 = 0x86DD

// resolveMAC6 resolves an IPv6 target's MAC via a Neighbor Solicitation.
func resolveMAC6(ifname string, target netip.Addr, timeout time.Duration) (net.HardwareAddr, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	src, err := linkLocalV6(ifi)
	if err != nil {
		return nil, err
	}
	tgt := target.As16()

	// Solicited-node multicast: ff02::1:ffXX:XXXX from the low 24 bits of target.
	sol := netip.AddrFrom16([16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, tgt[13], tgt[14], tgt[15]})
	// The matching multicast MAC is 33:33:ff:XX:XX:XX.
	dstMAC := net.HardwareAddr{0x33, 0x33, 0xff, tgt[13], tgt[14], tgt[15]}

	frame := buildNS(ifi.HardwareAddr, dstMAC, src, sol, target)

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethIPv6)))
	if err != nil {
		return nil, fmt.Errorf("backend: ndp socket: %w", err)
	}
	defer syscall.Close(fd)
	sll := syscall.SockaddrLinklayer{Protocol: htons(ethIPv6), Ifindex: ifi.Index, Halen: 6}
	copy(sll.Addr[:6], dstMAC)
	if err := syscall.Sendto(fd, frame, 0, &sll); err != nil {
		return nil, fmt.Errorf("backend: ndp sendto: %w", err)
	}

	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	buf := make([]byte, 256)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n, _, rerr := syscall.Recvfrom(fd, buf, 0)
		if rerr != nil {
			return nil, fmt.Errorf("backend: ndp recv: %w", rerr)
		}
		if mac, ok := parseNA(buf[:n], target); ok {
			return mac, nil
		}
	}
	return nil, fmt.Errorf("backend: NDP timed out resolving %s on %s", target, ifname)
}

// linkLocalV6 returns the interface's fe80:: address, the required NS source.
func linkLocalV6(ifi *net.Interface) (netip.Addr, error) {
	addrs, _ := ifi.Addrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if addr, ok := netip.AddrFromSlice(ipn.IP); ok && addr.Is6() && addr.IsLinkLocalUnicast() {
				return addr, nil
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("backend: interface %s has no IPv6 link-local address for NDP", ifi.Name)
}

// buildNS assembles an Ethernet/IPv6/ICMPv6 Neighbor Solicitation with the
// source-link-layer-address option and a correct ICMPv6 checksum.
func buildNS(srcMAC, dstMAC net.HardwareAddr, src, dst, target netip.Addr) []byte {
	icmp := make([]byte, 32)
	icmp[0] = 135 // Neighbor Solicitation
	// [1] code 0, [2:4] checksum (filled below), [4:8] reserved.
	t := target.As16()
	copy(icmp[8:24], t[:])
	icmp[24] = 1 // option: source link-layer address
	icmp[25] = 1 // length in 8-octet units
	copy(icmp[26:32], srcMAC)

	sa := src.As16()
	da := dst.As16()
	binary.BigEndian.PutUint16(icmp[2:4], icmpv6Checksum(sa[:], da[:], icmp))

	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(icmp)))
	ip[6] = 58 // ICMPv6
	ip[7] = 255
	copy(ip[8:24], sa[:])
	copy(ip[24:40], da[:])

	eth := make([]byte, 14)
	copy(eth[0:6], dstMAC)
	copy(eth[6:12], srcMAC)
	binary.BigEndian.PutUint16(eth[12:14], ethIPv6)
	return append(append(eth, ip...), icmp...)
}

// parseNA extracts the target link-layer address from a Neighbor Advertisement
// for wantIP.
func parseNA(frame []byte, wantIP netip.Addr) (net.HardwareAddr, bool) {
	const eth = 14
	if len(frame) < eth+40+24 {
		return nil, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethIPv6 {
		return nil, false
	}
	if frame[eth]>>4 != 6 || frame[eth+6] != 58 {
		return nil, false
	}
	icmp := frame[eth+40:]
	if icmp[0] != 136 { // Neighbor Advertisement
		return nil, false
	}
	var tgt [16]byte
	copy(tgt[:], icmp[8:24])
	if netip.AddrFrom16(tgt) != wantIP {
		return nil, false
	}
	// Options follow at icmp[24:]; find the target-link-layer-address option (2).
	opts := icmp[24:]
	for len(opts) >= 8 {
		otype, olen := opts[0], int(opts[1])*8
		if olen == 0 || olen > len(opts) {
			break
		}
		if otype == 2 { // target link-layer address
			mac := make(net.HardwareAddr, 6)
			copy(mac, opts[2:8])
			return mac, true
		}
		opts = opts[olen:]
	}
	// Some hosts answer without the option; fall back to the NA source MAC.
	mac := make(net.HardwareAddr, 6)
	copy(mac, frame[6:12])
	return mac, true
}

// icmpv6Checksum computes the ICMPv6 checksum over the IPv6 pseudo-header
// (src, dst, upper-layer length, next header = 58) plus the ICMPv6 message.
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
	add([]byte{0, 0, 0, 58}) // 3 zero bytes + next header
	add(msg)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// defaultGateway6 parses /proc/net/ipv6_route for the default route on ifname.
func defaultGateway6(ifname string) (netip.Addr, error) {
	data, err := os.ReadFile("/proc/net/ipv6_route")
	if err != nil {
		return netip.Addr{}, err
	}
	for _, ln := range strings.Split(string(data), "\n") {
		f := strings.Fields(ln)
		// dest(0) destprefix(1) src(2) srcprefix(3) nexthop(4) ... iface(last)
		if len(f) < 10 {
			continue
		}
		if f[len(f)-1] != ifname {
			continue
		}
		if f[0] != strings.Repeat("0", 32) || f[1] != "00" {
			continue // not the default route (::/0)
		}
		nh, err := hexToAddr16(f[4])
		if err != nil {
			continue
		}
		if nh.IsUnspecified() {
			continue
		}
		return nh, nil
	}
	return netip.Addr{}, fmt.Errorf("backend: no IPv6 default gateway on %s", ifname)
}

// hexToAddr16 parses 32 hex chars into an IPv6 address.
func hexToAddr16(s string) (netip.Addr, error) {
	if len(s) != 32 {
		return netip.Addr{}, fmt.Errorf("backend: bad ipv6 hex %q", s)
	}
	var b [16]byte
	for i := 0; i < 16; i++ {
		var v int
		if _, err := fmt.Sscanf(s[i*2:i*2+2], "%02x", &v); err != nil {
			return netip.Addr{}, err
		}
		b[i] = byte(v)
	}
	return netip.AddrFrom16(b), nil
}
