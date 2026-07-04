// Package engine is the stateful TCP replay core: it realigns a captured flow's
// seq/ack numbers onto a live peer's chosen ISN so the session completes against
// a real server. I/O-free (operates on parsed packets, emits bytes) and
// protocol-agnostic (rewrites TCP headers only, never the payload).
package engine

import (
	"github.com/kvmukilan/livewire/internal/flow"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/units"
	"github.com/kvmukilan/livewire/internal/wire"
)

// Dir is a packet's direction relative to the connection's client.
type Dir uint8

const (
	C2S Dir = iota // client-to-server
	S2C            // server-to-client
)

func (d Dir) String() string {
	if d == C2S {
		return "C2S"
	}
	return "S2C"
}

// CapturedPacket is one packet of a flow with its parsed view and role.
type CapturedPacket struct {
	Index      int // position in the source file
	Rec        *pcapio.Record
	Dir        Dir
	IsSyn      bool
	IsSynAck   bool
	Ack        bool
	IsFin      bool
	IsRst      bool
	Seq        units.Seq
	AckN       units.Ack
	SegLen     uint32 // sequence-space length (payload + SYN + FIN)
	PayloadLen int
	HasTS      bool
	TSVal      uint32
}

// Flow is a single TCP connection extracted from a capture, in timeline order.
type Flow struct {
	Key          flow.Key
	Orient       flow.Orient
	Client       flow.Endpoint
	Server       flow.Endpoint
	Packets      []CapturedPacket
	CapClientISN units.Seq
	CapServerISN units.Seq
	HasSyn       bool
	HasSynAck    bool
	TSClient     bool // client advertised the TCP timestamp option
	TSServer     bool // server advertised the TCP timestamp option
}

// ExtractFlows groups records into TCP flows, resolves each flow's orientation,
// tags packet directions, and records the handshake ISNs. Non-TCP records are ignored.
func ExtractFlows(recs []*pcapio.Record) []*Flow {
	type acc struct {
		flow *Flow
	}
	order := []flow.Key{}
	byKey := map[flow.Key]*acc{}

	// Pass 1: group by key and resolve orientation from the handshake.
	parsed := make([]*wire.Packet, len(recs))
	keys := make([]flow.Key, len(recs))
	dirs := make([]flow.Dir, len(recs))
	valid := make([]bool, len(recs))

	for i, rec := range recs {
		p, err := wire.Parse(rec.Data, rec.LinkType)
		if err != nil || !p.IsTCP() {
			continue
		}
		key, dir, ok := flow.KeyFromPacket(p)
		if !ok {
			continue
		}
		parsed[i], keys[i], dirs[i], valid[i] = p, key, dir, true

		a := byKey[key]
		if a == nil {
			a = &acc{flow: &Flow{Key: key, Orient: flow.OrientUnknown}}
			byKey[key] = a
			order = append(order, key)
		}
		f := a.flow
		syn, ack := p.HasFlags(wire.FlagSYN), p.HasFlags(wire.FlagACK)
		if f.Orient == flow.OrientUnknown {
			switch {
			case syn && !ack:
				f.Orient = orientFromClientDir(dir)
			case syn && ack:
				f.Orient = orientFromClientDir(oppositeDir(dir))
			}
		}
	}

	// Pass 2: assign per-packet direction and roles; fall back to first-seen for
	// flows with no observed handshake.
	for i, rec := range recs {
		if !valid[i] {
			continue
		}
		f := byKey[keys[i]].flow
		if f.Orient == flow.OrientUnknown {
			f.Orient = orientFromClientDir(dirs[i]) // first packet's sender = client
		}
		p := parsed[i]
		dir := engineDir(f.Orient, dirs[i])
		syn, ack := p.HasFlags(wire.FlagSYN), p.HasFlags(wire.FlagACK)
		tsv, _, hasTS := p.Timestamps()
		cp := CapturedPacket{
			Index:      i,
			Rec:        rec,
			Dir:        dir,
			IsSyn:      syn && !ack,
			IsSynAck:   syn && ack,
			Ack:        ack,
			IsFin:      p.HasFlags(wire.FlagFIN),
			IsRst:      p.HasFlags(wire.FlagRST),
			Seq:        p.Seq(),
			AckN:       p.AckNum(),
			SegLen:     p.SegmentLen(),
			PayloadLen: p.PayloadLen(),
			HasTS:      hasTS,
			TSVal:      tsv,
		}
		if syn && !ack {
			f.CapClientISN = p.Seq()
			f.HasSyn = true
			if hasTS {
				f.TSClient = true
			}
		}
		if syn && ack {
			f.CapServerISN = p.Seq()
			f.HasSynAck = true
			if hasTS {
				f.TSServer = true
			}
		}
		f.Packets = append(f.Packets, cp)
	}

	out := make([]*Flow, 0, len(order))
	for _, k := range order {
		f := byKey[k].flow
		f.Client, f.Server = endpoints(f.Key, f.Orient)
		out = append(out, f)
	}
	return out
}

func endpoints(k flow.Key, o flow.Orient) (client, server flow.Endpoint) {
	if o == flow.OrientHiIsClient {
		return k.Hi, k.Lo
	}
	return k.Lo, k.Hi // default LoIsClient
}

// engineDir maps a canonical travel direction to a client-relative direction.
func engineDir(o flow.Orient, d flow.Dir) Dir {
	cd, ok := o.ClientDir()
	if !ok {
		cd = flow.DirLoToHi
	}
	if d == cd {
		return C2S
	}
	return S2C
}

func orientFromClientDir(d flow.Dir) flow.Orient {
	if d == flow.DirLoToHi {
		return flow.OrientLoIsClient
	}
	return flow.OrientHiIsClient
}

func oppositeDir(d flow.Dir) flow.Dir {
	if d == flow.DirLoToHi {
		return flow.DirHiToLo
	}
	return flow.DirLoToHi
}
