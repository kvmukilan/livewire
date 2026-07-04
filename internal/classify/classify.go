package classify

import (
	"net/netip"

	"github.com/kvmukilan/livewire/internal/flow"
	"github.com/kvmukilan/livewire/internal/wire"
)

// Mode selects the classification strategy (mirrors tcpprep's modes).
type Mode int

const (
	// ModeAuto uses handshake direction, falling back to lower-port-is-server.
	ModeAuto Mode = iota
	// ModePort classifies purely by port: the lower port is the server.
	ModePort
	// ModeClientCIDR marks packets sourced from ClientNets as client-side.
	ModeClientCIDR
)

// Classifier holds the configured strategy and its parameters.
type Classifier struct {
	Mode       Mode
	ClientNets []netip.Prefix // used by ModeClientCIDR
}

// Classify assigns a Send decision to each packet in file order. Nil/unparseable
// frames go to the primary interface so they're still replayed.
func (c *Classifier) Classify(pkts []*wire.Packet) *Cache {
	orient := map[flow.Key]flow.Orient{}
	if c.Mode == ModeAuto {
		for _, p := range pkts {
			if p == nil || !p.IsTCP() {
				continue
			}
			key, dir, ok := flow.KeyFromPacket(p)
			if !ok {
				continue
			}
			if _, seen := orient[key]; seen {
				continue
			}
			syn, ack := p.HasFlags(wire.FlagSYN), p.HasFlags(wire.FlagACK)
			switch {
			case syn && !ack: // sender initiated: sender is client
				orient[key] = clientFromDir(dir)
			case syn && ack: // sender is server: client is the other side
				orient[key] = clientFromDir(opposite(dir))
			}
		}
	}

	cache := &Cache{entries: make([]Send, len(pkts))}
	for i, p := range pkts {
		cache.entries[i] = c.classifyOne(p, orient)
	}
	return cache
}

func (c *Classifier) classifyOne(p *wire.Packet, orient map[flow.Key]flow.Orient) Send {
	if p == nil || (!p.IsTCP() && !p.IsUDP()) {
		return SendPrimary
	}
	key, dir, ok := flow.KeyFromPacket(p)
	if !ok {
		return SendPrimary
	}

	switch c.Mode {
	case ModeClientCIDR:
		if c.matchesClient(p.SrcIP()) {
			return SendPrimary
		}
		if c.matchesClient(p.DstIP()) {
			return SendSecondary
		}
		return SendPrimary
	case ModePort:
		return portDecision(p)
	default: // ModeAuto
		if o, known := orient[key]; known {
			if cd, ok := o.ClientDir(); ok {
				if cd == dir {
					return SendPrimary
				}
				return SendSecondary
			}
		}
		return portDecision(p) // fallback
	}
}

// portDecision routes packets bound for the lower (server) port to primary.
func portDecision(p *wire.Packet) Send {
	if p.DstPort() <= p.SrcPort() {
		return SendPrimary // destined for the lower (server) port
	}
	return SendSecondary
}

func (c *Classifier) matchesClient(a netip.Addr) bool {
	for _, n := range c.ClientNets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

func clientFromDir(d flow.Dir) flow.Orient {
	if d == flow.DirLoToHi {
		return flow.OrientLoIsClient
	}
	return flow.OrientHiIsClient
}

func opposite(d flow.Dir) flow.Dir {
	if d == flow.DirLoToHi {
		return flow.DirHiToLo
	}
	return flow.DirLoToHi
}
