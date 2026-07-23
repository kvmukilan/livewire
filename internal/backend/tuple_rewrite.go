package backend

import (
	"net/netip"
	"time"

	"github.com/kvmukilan/livewire/internal/wire"
)

type TupleEndpoint struct {
	IP   netip.Addr
	Port uint16
}

type TupleRewrite struct {
	CapturedClient TupleEndpoint
	CapturedServer TupleEndpoint
	LiveClient     TupleEndpoint
	LiveServer     TupleEndpoint
}

// NewTupleRewriter translates captured tuples to live tuples on Send and back
// to captured tuples on Recv. This keeps the state machines capture-relative
// while the evidence/backend observe the real on-wire addresses.
func NewTupleRewriter(inner PacketBackend, m TupleRewrite) PacketBackend {
	return &tupleRewriter{inner: inner, mapping: m}
}

type tupleRewriter struct {
	inner   PacketBackend
	mapping TupleRewrite
}

func (t *tupleRewriter) Send(frame []byte) error {
	t.rewrite(frame, true)
	return t.inner.Send(frame)
}

func (t *tupleRewriter) Recv(buf []byte, timeout time.Duration) (int, bool, error) {
	n, ok, err := t.inner.Recv(buf, timeout)
	if err == nil && ok {
		t.rewrite(buf[:n], false)
	}
	return n, ok, err
}

func (t *tupleRewriter) rewrite(frame []byte, outbound bool) {
	p, err := wire.Parse(frame, t.inner.LinkType())
	if err != nil {
		return
	}
	fromClient, fromServer := t.mapping.CapturedClient, t.mapping.CapturedServer
	toClient, toServer := t.mapping.LiveClient, t.mapping.LiveServer
	if !outbound {
		fromClient, fromServer, toClient, toServer = t.mapping.LiveClient, t.mapping.LiveServer, t.mapping.CapturedClient, t.mapping.CapturedServer
	}
	if p.SrcIP() == fromClient.IP {
		p.SetSrcIP(toClient.IP)
		if fromClient.Port == 0 || p.SrcPort() == fromClient.Port {
			p.SetSrcPort(toClient.Port)
		}
	} else if p.SrcIP() == fromServer.IP {
		p.SetSrcIP(toServer.IP)
		if fromServer.Port == 0 || p.SrcPort() == fromServer.Port {
			p.SetSrcPort(toServer.Port)
		}
	}
	if p.DstIP() == fromServer.IP {
		p.SetDstIP(toServer.IP)
		if fromServer.Port == 0 || p.DstPort() == fromServer.Port {
			p.SetDstPort(toServer.Port)
		}
	} else if p.DstIP() == fromClient.IP {
		p.SetDstIP(toClient.IP)
		if fromClient.Port == 0 || p.DstPort() == fromClient.Port {
			p.SetDstPort(toClient.Port)
		}
	}
	p.RecalcChecksums()
}

func (t *tupleRewriter) Now() time.Time          { return t.inner.Now() }
func (t *tupleRewriter) LinkType() wire.LinkType { return t.inner.LinkType() }
func (t *tupleRewriter) Caps() Capabilities      { return t.inner.Caps() }
func (t *tupleRewriter) Close() error            { return t.inner.Close() }
