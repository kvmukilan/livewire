//go:build linux

package backend

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/kvmukilan/livewire/internal/wire"
)

// openLive wires an AF_PACKET backend to a resolved next hop and a 4-tuple recv
// filter. Promiscuous mode is forced on because server replies are unicast to
// the spoofed client MAC, which the interface doesn't own.
func openLive(cfg LiveConfig) (*LiveBackend, error) {
	af, err := OpenAFPacket(cfg.Iface, true)
	if err != nil {
		return nil, err
	}
	nextHop, err := NextHop(cfg.Iface, cfg.Target)
	if err != nil {
		af.Close()
		return nil, err
	}
	nhMAC, err := ResolveMAC(cfg.Iface, nextHop)
	if err != nil {
		af.Close()
		return nil, err
	}
	localMAC, err := LocalMAC(cfg.Iface)
	if err != nil {
		af.Close()
		return nil, err
	}

	proto := cfg.Protocol
	if proto == 0 {
		proto = wire.ProtoTCP
	}
	// Only pass the server→client half of the flow to the engine.
	af.Filter = func(frame []byte) bool {
		p, err := wire.Parse(frame, wire.LinkEthernet)
		if err != nil || p.Proto() != proto {
			return false
		}
		if p.SrcIP() != cfg.Target {
			return false
		}
		if proto == wire.ProtoTCP || proto == wire.ProtoUDP {
			if p.SrcPort() != cfg.TargetPort {
				return false
			}
			return cfg.LocalPort == 0 || p.DstPort() == cfg.LocalPort
		}
		if proto == wire.ProtoICMPv4 || proto == wire.ProtoICMPv6 {
			_, id, _, ok := p.ICMPEcho()
			return ok && (cfg.ICMPID == 0 || id == cfg.ICMPID)
		}
		return true
	}

	localIP, err := localIPForTarget(cfg.Iface, cfg.Target)
	if err != nil {
		af.Close()
		return nil, err
	}
	lb := &LiveBackend{Backend: af, LocalIP: localIP}
	if len(localMAC) == 6 {
		copy(lb.LocalMAC[:], localMAC)
	}
	if len(nhMAC) == 6 {
		copy(lb.NextHopMAC[:], nhMAC)
	} else {
		af.Close()
		return nil, fmt.Errorf("backend: resolved next-hop MAC has unexpected length %d", len(nhMAC))
	}
	return lb, nil
}

func localIPForTarget(ifname string, target netip.Addr) (netip.Addr, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return netip.Addr{}, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if (target.Is4() && ip.Is4()) || (target.Is6() && !target.Is4In6() && ip.Is6() && !ip.Is4In6()) {
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("backend: interface %s has no address matching target family %s", ifname, target)
}

// openSender opens a plain AF_PACKET socket for stateless blasting: no promisc,
// no filter, no next-hop resolution.
func openSender(iface string) (PacketBackend, error) {
	return OpenAFPacket(iface, false)
}

// openCapture opens an AF_PACKET socket for recording frames.
func openCapture(iface string, promisc bool) (PacketBackend, error) {
	return OpenAFPacket(iface, promisc)
}

func resolveLink(iface string, target netip.Addr, _ PacketBackend) ([6]byte, [6]byte, error) {
	var source, next [6]byte
	nextHop, err := NextHop(iface, target)
	if err != nil {
		return source, next, err
	}
	sourceMAC, err := LocalMAC(iface)
	if err != nil {
		return source, next, err
	}
	nextMAC, err := ResolveMAC(iface, nextHop)
	if err != nil {
		return source, next, err
	}
	if len(sourceMAC) != 6 || len(nextMAC) != 6 {
		return source, next, fmt.Errorf("backend: link resolution returned source=%d next-hop=%d MAC bytes", len(sourceMAC), len(nextMAC))
	}
	copy(source[:], sourceMAC)
	copy(next[:], nextMAC)
	return source, next, nil
}
