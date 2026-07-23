//go:build windows

package backend

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/kvmukilan/livewire/internal/wire"
)

// openLive wires an Npcap backend to the resolved next hop and a 4-tuple recv
// filter, the Windows counterpart of the AF_PACKET path. The device is an Npcap
// name from `livewire ifaces`.
func openLive(cfg LiveConfig) (*LiveBackend, error) {
	np, err := OpenNpcap(cfg.Iface, true)
	if err != nil {
		return nil, err
	}

	proto := cfg.Protocol
	if proto == 0 {
		proto = wire.ProtoTCP
	}
	np.Filter = func(frame []byte) bool {
		p, err := wire.Parse(frame, np.LinkType())
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

	localIP, err := LocalIPForTarget(cfg.Target)
	if err != nil {
		np.Close()
		return nil, err
	}
	lb := &LiveBackend{Backend: np, LocalIP: localIP}

	// The Npcap loopback adapter is Null-framed and a loopback target has no
	// ARP/next-hop, so skip MAC resolution: the rewriter is a no-op for
	// non-Ethernet links and zero MACs are correct. Enables single-box loopback
	// tests.
	if cfg.Target.IsLoopback() || np.LinkType() != wire.LinkEthernet {
		return lb, nil
	}

	nextHop, err := NextHopWindows(cfg.Target)
	if err != nil {
		np.Close()
		return nil, err
	}
	localMAC, err := LocalMACForTarget(cfg.Target)
	if err != nil {
		np.Close()
		return nil, err
	}
	var nhMAC []byte
	if nextHop.Is6() {
		nhMAC, err = resolveMAC6Npcap(np, nextHop, localIP, localMAC, 2*time.Second)
	} else {
		nhMAC, err = ResolveMACWindows(nextHop)
	}
	if err != nil {
		np.Close()
		return nil, err
	}
	copy(lb.LocalMAC[:], localMAC)
	if len(nhMAC) != 6 {
		np.Close()
		return nil, fmt.Errorf("backend: resolved next-hop MAC has unexpected length %d", len(nhMAC))
	}
	copy(lb.NextHopMAC[:], nhMAC)
	return lb, nil
}

// openSender opens an Npcap handle for stateless blasting (no filter, no
// next-hop resolution).
func openSender(device string) (PacketBackend, error) {
	return OpenNpcap(device, false)
}

// openCapture opens an Npcap handle for recording frames.
func openCapture(device string, promisc bool) (PacketBackend, error) {
	return OpenNpcap(device, promisc)
}

func resolveLink(_ string, target netip.Addr, b PacketBackend) ([6]byte, [6]byte, error) {
	var source, next [6]byte
	localIP, err := LocalIPForTarget(target)
	if err != nil {
		return source, next, err
	}
	sourceMAC, err := LocalMACForTarget(target)
	if err != nil {
		return source, next, err
	}
	var nextMAC net.HardwareAddr
	if target.Is6() {
		npcap, ok := b.(*Npcap)
		if !ok {
			return source, next, fmt.Errorf("backend: Windows IPv6 link resolution requires the selected Npcap sender")
		}
		nextMAC, err = resolveMAC6Npcap(npcap, target, localIP, sourceMAC, 2*time.Second)
	} else {
		nextMAC, err = ResolveMACWindows(target)
	}
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
