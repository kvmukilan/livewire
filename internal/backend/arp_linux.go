//go:build linux

package backend

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Since we build the whole L2 frame, we need the destination MAC — the next hop
// toward the target. These helpers resolve it with only the standard library:
// the kernel routing/neighbour tables via /proc, plus an active ARP request when
// the neighbour entry is cold. Linux-only.

// NextHop returns the IP of the next hop toward target for the given interface:
// target itself if it shares a subnet with one of the interface's addresses,
// otherwise the default gateway from the routing table.
func NextHop(ifname string, target netip.Addr) (netip.Addr, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return netip.Addr{}, err
	}
	addrs, _ := ifi.Addrs()
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		pfx, ok := netipPrefix(ipn)
		if ok && pfx.Contains(target) {
			return target, nil // on-link
		}
	}
	gw, err := defaultGateway(ifname, target.Is6())
	if err != nil {
		return netip.Addr{}, fmt.Errorf("no on-link route and %w", err)
	}
	return gw, nil
}

// ResolveMAC returns the MAC for ip on ifname, consulting the kernel neighbour
// table first and issuing an ARP request if the entry is missing (IPv4 only;
// IPv6 uses NDP, deferred).
func ResolveMAC(ifname string, ip netip.Addr) (net.HardwareAddr, error) {
	if mac, ok := neighLookup(ip); ok {
		return mac, nil
	}
	if ip.Is6() {
		return resolveMAC6(ifname, ip, 2*time.Second)
	}
	return arpRequest(ifname, ip, 2*time.Second)
}

// LocalMAC returns the interface's own hardware address.
func LocalMAC(ifname string) (net.HardwareAddr, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	return ifi.HardwareAddr, nil
}

func netipPrefix(ipn *net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(ipn.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := ipn.Mask.Size()
	return netip.PrefixFrom(addr.Unmap(), ones), true
}

// neighLookup reads /proc/net/arp for a cached MAC. Returns ok=false if the
// address is absent or the entry is incomplete (00:00:00:00:00:00).
func neighLookup(ip netip.Addr) (net.HardwareAddr, bool) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, false
	}
	lines := strings.Split(string(data), "\n")
	for _, ln := range lines[1:] { // skip header
		f := strings.Fields(ln)
		if len(f) < 4 {
			continue
		}
		if f[0] == ip.String() && f[3] != "00:00:00:00:00:00" {
			mac, err := net.ParseMAC(f[3])
			if err == nil {
				return mac, true
			}
		}
	}
	return nil, false
}

// defaultGateway parses /proc/net/route (IPv4) or /proc/net/ipv6_route (IPv6)
// for the default route on ifname.
func defaultGateway(ifname string, v6 bool) (netip.Addr, error) {
	if v6 {
		return defaultGateway6(ifname)
	}
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return netip.Addr{}, err
	}
	for _, ln := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(ln)
		if len(f) < 4 || f[0] != ifname {
			continue
		}
		if f[1] != "00000000" { // destination 0.0.0.0 = default route
			continue
		}
		gwLE, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil {
			continue
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(gwLE)) // /proc stores it little-endian
		return netip.AddrFrom4(b), nil
	}
	return netip.Addr{}, fmt.Errorf("backend: no default gateway on %s", ifname)
}

// arpRequest broadcasts an ARP who-has for target on ifname and waits for the
// reply, returning the resolved MAC. It sends and receives on a dedicated raw
// ARP socket so it does not disturb the replay backend.
func arpRequest(ifname string, target netip.Addr, timeout time.Duration) (net.HardwareAddr, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	srcIP, err := firstIPv4(ifi)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(etherARP)))
	if err != nil {
		return nil, fmt.Errorf("backend: arp socket: %w", err)
	}
	defer syscall.Close(fd)
	sll := syscall.SockaddrLinklayer{Protocol: htons(etherARP), Ifindex: ifi.Index, Halen: 6}
	copy(sll.Addr[:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	frame := buildARPRequest(ifi.HardwareAddr, srcIP, target.As4())
	if err := syscall.Sendto(fd, frame, 0, &sll); err != nil {
		return nil, fmt.Errorf("backend: arp sendto: %w", err)
	}

	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	buf := make([]byte, 128)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, fmt.Errorf("backend: arp recv: %w", err)
		}
		if mac, ok := parseARPReply(buf[:n], target.As4()); ok {
			return mac, nil
		}
	}
	return nil, fmt.Errorf("backend: ARP timed out resolving %s on %s", target, ifname)
}

// etherARP is the ARP ethertype; declared here to avoid depending on wire's
// unexported constant.
const etherARP = 0x0806

func firstIPv4(ifi *net.Interface) ([4]byte, error) {
	addrs, _ := ifi.Addrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if v4 := ipn.IP.To4(); v4 != nil {
				return [4]byte{v4[0], v4[1], v4[2], v4[3]}, nil
			}
		}
	}
	return [4]byte{}, fmt.Errorf("backend: interface %s has no IPv4 address for ARP", ifi.Name)
}

// buildARPRequest assembles an Ethernet-framed ARP who-has.
func buildARPRequest(srcMAC net.HardwareAddr, srcIP, targetIP [4]byte) []byte {
	f := make([]byte, 42)
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // dst broadcast
	copy(f[6:12], srcMAC)
	binary.BigEndian.PutUint16(f[12:14], etherARP)
	binary.BigEndian.PutUint16(f[14:16], 1)      // HTYPE Ethernet
	binary.BigEndian.PutUint16(f[16:18], 0x0800) // PTYPE IPv4
	f[18], f[19] = 6, 4                          // HLEN, PLEN
	binary.BigEndian.PutUint16(f[20:22], 1)      // OPER request
	copy(f[22:28], srcMAC)
	copy(f[28:32], srcIP[:])
	// target MAC left zero
	copy(f[38:42], targetIP[:])
	return f
}

// parseARPReply extracts the sender MAC from an ARP reply for wantIP.
func parseARPReply(frame []byte, wantIP [4]byte) (net.HardwareAddr, bool) {
	if len(frame) < 42 {
		return nil, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != etherARP {
		return nil, false
	}
	if binary.BigEndian.Uint16(frame[20:22]) != 2 { // OPER reply
		return nil, false
	}
	var sIP [4]byte
	copy(sIP[:], frame[28:32])
	if sIP != wantIP {
		return nil, false
	}
	mac := make(net.HardwareAddr, 6)
	copy(mac, frame[22:28])
	return mac, true
}
