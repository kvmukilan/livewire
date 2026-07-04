package backend

import (
	"time"

	"github.com/kvmukilan/livewire/internal/wire"
)

// macRewriter wraps a PacketBackend and retargets each outgoing frame's L2
// addresses: source to the sending interface's MAC, destination to the resolved
// next-hop MAC. The captured MACs mean nothing on the replay segment, so we fix
// them here and keep the engine's seq/ack logic MAC-unaware.
type macRewriter struct {
	inner   PacketBackend
	local   [6]byte
	nextHop [6]byte
	link    wire.LinkType
}

// NewMACRewriter returns a backend that retargets L2 addresses on Send. Recv,
// clock, capabilities, and Close pass through to inner unchanged.
func NewMACRewriter(inner PacketBackend, local, nextHop [6]byte) PacketBackend {
	return &macRewriter{inner: inner, local: local, nextHop: nextHop, link: inner.LinkType()}
}

func (m *macRewriter) Send(frame []byte) error {
	if m.link != wire.LinkEthernet {
		return m.inner.Send(frame) // no L2 addresses to rewrite
	}
	p, err := wire.Parse(frame, m.link)
	if err != nil {
		return m.inner.Send(frame) // unparseable: pass through rather than drop
	}
	p.SetSrcMAC(m.local)
	p.SetDstMAC(m.nextHop)
	p.RecalcChecksums()
	return m.inner.Send(p.Buf)
}

func (m *macRewriter) Recv(buf []byte, timeout time.Duration) (int, bool, error) {
	return m.inner.Recv(buf, timeout)
}
func (m *macRewriter) Now() time.Time          { return m.inner.Now() }
func (m *macRewriter) LinkType() wire.LinkType { return m.link }
func (m *macRewriter) Caps() Capabilities      { return m.inner.Caps() }
func (m *macRewriter) Close() error            { return m.inner.Close() }
