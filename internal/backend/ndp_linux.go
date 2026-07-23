//go:build linux

package backend

import (
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
