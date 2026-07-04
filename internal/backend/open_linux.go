//go:build linux

package backend

import (
	"fmt"

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

	// Only pass the server→client half of the flow to the engine.
	af.Filter = func(frame []byte) bool {
		p, err := wire.Parse(frame, wire.LinkEthernet)
		if err != nil || !p.IsTCP() {
			return false
		}
		if p.SrcIP() != cfg.Target || p.SrcPort() != cfg.TargetPort {
			return false
		}
		return cfg.LocalPort == 0 || p.DstPort() == cfg.LocalPort
	}

	lb := &LiveBackend{Backend: af}
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

// openSender opens a plain AF_PACKET socket for stateless blasting: no promisc,
// no filter, no next-hop resolution.
func openSender(iface string) (PacketBackend, error) {
	return OpenAFPacket(iface, false)
}

// openCapture opens an AF_PACKET socket for recording frames.
func openCapture(iface string, promisc bool) (PacketBackend, error) {
	return OpenAFPacket(iface, promisc)
}
