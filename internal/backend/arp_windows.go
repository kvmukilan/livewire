//go:build windows

package backend

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
	"unsafe"
)

// On Windows the next-hop MAC comes from the IP Helper API's SendARP
// (iphlpapi.dll, loaded lazily so no cgo or SDK is needed). The local interface
// MAC comes from Go's net package by subnet match.

var (
	iphlpapi    = syscall.NewLazyDLL("iphlpapi.dll")
	procSendARP = iphlpapi.NewProc("SendARP")
)

// NextHopWindows returns the next hop toward target: target itself if it is
// on-link with one of this host's interfaces, else an error. Off-link routing
// (GetBestRoute) isn't implemented; on-link covers the common lab/SCADA case.
func NextHopWindows(target netip.Addr) (netip.Addr, error) {
	ifis, err := net.Interfaces()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, ifi := range ifis {
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if pfx, ok := netipPrefixWin(ipn); ok && pfx.Contains(target) {
					return target, nil
				}
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("backend: target %s is not on-link on any interface; "+
		"off-link routing on Windows is not yet supported (place the tool on the target's subnet)", target)
}

// ResolveMACWindows resolves ip's MAC via SendARP (IPv4 only; IPv6 uses NDP).
func ResolveMACWindows(ip netip.Addr) (net.HardwareAddr, error) {
	if !ip.Is4() {
		return nil, fmt.Errorf("backend: IPv6 NDP needs the selected open Npcap handle; use OpenLive or ResolveLink")
	}
	if err := iphlpapi.Load(); err != nil {
		return nil, fmt.Errorf("backend: iphlpapi.dll not loadable: %w", err)
	}
	dst := ip.As4()
	destInet := *(*uint32)(unsafe.Pointer(&dst[0])) // network-order bytes as the API expects
	var mac [8]byte
	macLen := uint32(len(mac))
	r, _, _ := procSendARP.Call(
		uintptr(destInet),
		0, // SrcIP 0 => let the stack choose
		uintptr(unsafe.Pointer(&mac[0])),
		uintptr(unsafe.Pointer(&macLen)),
	)
	if r != 0 { // NO_ERROR == 0
		return nil, fmt.Errorf("backend: SendARP(%s) failed (error %d); is the target reachable?", ip, r)
	}
	if macLen < 6 {
		return nil, fmt.Errorf("backend: SendARP returned %d MAC bytes", macLen)
	}
	return net.HardwareAddr(mac[:6]), nil
}

// resolveMAC6Npcap performs active NDP on the already-open Npcap handle. This
// avoids depending on a pre-populated Windows neighbor cache and works for
// both global and link-local on-link targets.
func resolveMAC6Npcap(np *Npcap, target, localIP netip.Addr, localMAC net.HardwareAddr, timeout time.Duration) (net.HardwareAddr, error) {
	tgt := target.WithZone("").As16()
	solicited := netip.AddrFrom16([16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, tgt[13], tgt[14], tgt[15]})
	dstMAC := net.HardwareAddr{0x33, 0x33, 0xff, tgt[13], tgt[14], tgt[15]}
	frame := buildNS(localMAC, dstMAC, localIP.WithZone(""), solicited, target.WithZone(""))
	oldFilter := np.Filter
	np.Filter = func(frame []byte) bool {
		_, ok := parseNA(frame, target)
		return ok
	}
	defer func() { np.Filter = oldFilter }()
	if err := np.Send(frame); err != nil {
		return nil, fmt.Errorf("backend: NDP solicitation: %w", err)
	}
	buf := make([]byte, 2048)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n, ok, err := np.Recv(buf, minDuration(100*time.Millisecond, time.Until(deadline)))
		if err != nil {
			return nil, fmt.Errorf("backend: NDP receive: %w", err)
		}
		if ok {
			if mac, matched := parseNA(buf[:n], target); matched {
				return mac, nil
			}
		}
	}
	return nil, fmt.Errorf("backend: NDP timed out resolving %s", target)
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// LocalMACForTarget returns the MAC of the interface on target's subnet.
func LocalMACForTarget(target netip.Addr) (net.HardwareAddr, error) {
	ifis, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, ifi := range ifis {
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if pfx, ok := netipPrefixWin(ipn); ok && pfx.Contains(target) && len(ifi.HardwareAddr) == 6 {
					return ifi.HardwareAddr, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("backend: no interface with a MAC on target %s's subnet", target)
}

// LocalIPForTarget returns the address the host would use on the target's
// directly connected subnet. The v0.5 live path intentionally requires an
// on-link Windows target because route-table selection is not yet exposed.
func LocalIPForTarget(target netip.Addr) (netip.Addr, error) {
	ifis, err := net.Interfaces()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, ifi := range ifis {
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			pfx, ok := netipPrefixWin(ipn)
			if !ok || !pfx.Contains(target) {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if ok {
				return ip.Unmap(), nil
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("backend: target %s is not on-link on any interface", target)
}

func netipPrefixWin(ipn *net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(ipn.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := ipn.Mask.Size()
	return netip.PrefixFrom(addr.Unmap(), ones), true
}
