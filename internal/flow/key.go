// Package flow defines the canonical connection identity used to demux packets.
// A Key is direction-agnostic (both directions share one Key); a Dir records
// which way a given packet went.
package flow

import (
	"fmt"
	"net/netip"

	"github.com/kvmukilan/livewire/internal/wire"
)

// Endpoint is one side of a connection; comparable, usable as a map key.
type Endpoint struct {
	Addr netip.Addr
	Port uint16
}

func (e Endpoint) String() string { return netip.AddrPortFrom(e.Addr, e.Port).String() }

func (e Endpoint) less(o Endpoint) bool {
	if c := e.Addr.Compare(o.Addr); c != 0 {
		return c < 0
	}
	return e.Port < o.Port
}

// Key is a canonical 4-tuple with Lo the smaller endpoint; usable as a map key.
type Key struct {
	Lo, Hi Endpoint
	Proto  uint8
}

func (k Key) String() string {
	return fmt.Sprintf("%s<->%s/%d", k.Lo, k.Hi, k.Proto)
}

// Dir is the travel direction of a packet relative to the canonical Key.
type Dir uint8

const (
	// DirLoToHi means the packet went from Lo to Hi.
	DirLoToHi Dir = iota
	// DirHiToLo means the packet went from Hi to Lo.
	DirHiToLo
)

// KeyFromPacket derives the canonical Key and travel direction from a parsed
// TCP/UDP packet. ok is false for non-TCP/UDP frames.
func KeyFromPacket(p *wire.Packet) (key Key, dir Dir, ok bool) {
	if !p.IsTCP() && !p.IsUDP() {
		return Key{}, 0, false
	}
	src := Endpoint{p.SrcIP(), p.SrcPort()}
	dst := Endpoint{p.DstIP(), p.DstPort()}
	if src.less(dst) {
		return Key{Lo: src, Hi: dst, Proto: p.Proto()}, DirLoToHi, true
	}
	return Key{Lo: dst, Hi: src, Proto: p.Proto()}, DirHiToLo, true
}

// Orient records which endpoint is the TCP client (sent the initial SYN).
type Orient uint8

const (
	// OrientUnknown means the client side has not been determined yet.
	OrientUnknown Orient = iota
	// OrientLoIsClient means Lo initiated the connection.
	OrientLoIsClient
	// OrientHiIsClient means Hi initiated the connection.
	OrientHiIsClient
)

// ClientDir returns the direction of client->server traffic, and whether known.
func (o Orient) ClientDir() (Dir, bool) {
	switch o {
	case OrientLoIsClient:
		return DirLoToHi, true
	case OrientHiIsClient:
		return DirHiToLo, true
	default:
		return 0, false
	}
}
