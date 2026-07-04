//go:build windows

package backend

import (
	"fmt"

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

	np.Filter = func(frame []byte) bool {
		p, err := wire.Parse(frame, np.LinkType())
		if err != nil || !p.IsTCP() {
			return false
		}
		if p.SrcIP() != cfg.Target || p.SrcPort() != cfg.TargetPort {
			return false
		}
		return cfg.LocalPort == 0 || p.DstPort() == cfg.LocalPort
	}

	lb := &LiveBackend{Backend: np}

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
	nhMAC, err := ResolveMACWindows(nextHop)
	if err != nil {
		np.Close()
		return nil, err
	}
	localMAC, err := LocalMACForTarget(cfg.Target)
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
