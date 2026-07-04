//go:build windows

package backend

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
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
		return nil, fmt.Errorf("backend: SendARP is IPv4-only; IPv6 NDP resolution on Windows is not implemented")
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

func netipPrefixWin(ipn *net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(ipn.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := ipn.Mask.Size()
	return netip.PrefixFrom(addr.Unmap(), ones), true
}
