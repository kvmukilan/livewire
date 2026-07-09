package engine

import (
	"fmt"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/units"
	"github.com/kvmukilan/livewire/internal/wire"
)

// SynthesizeHandshake makes a mid-stream capture (one with no SYN/SYN-ACK)
// replayable by fabricating a three-way handshake in front of it. It anchors the
// synthetic client/server ISNs one below the first sequence number seen in each
// direction, so the captured mid-stream data lines up as ISN+1 onwards; the real
// server ISN is still learned live from the fabricated SYN's SYN-ACK. Returns the
// flow unchanged if it already has a handshake.
//
// Experimental: the synthetic SYN is cloned from a captured data frame, so it
// carries that frame's TCP options (timestamps if present) but not SYN-only
// options like MSS or window scale. Most stacks still accept it.
func SynthesizeHandshake(f *Flow) (*Flow, error) {
	if f.HasSyn && f.HasSynAck {
		return f, nil
	}
	var firstC, firstS *CapturedPacket
	for i := range f.Packets {
		cp := &f.Packets[i]
		if cp.IsRst {
			continue
		}
		if cp.Dir == C2S && firstC == nil {
			firstC = cp
		}
		if cp.Dir == S2C && firstS == nil {
			firstS = cp
		}
	}
	if firstC == nil || firstS == nil {
		return nil, fmt.Errorf("cannot synthesize a handshake for flow %s: need at least one packet "+
			"in each direction to anchor the sequence spaces", f.Key)
	}

	clientISN := firstC.Seq.Sub(1) // SYN consumes 1; the first data byte is ISN+1
	serverISN := firstS.Seq.Sub(1)

	syn, err := synthPacket(firstC, clientISN, 0, false)
	if err != nil {
		return nil, err
	}
	// The SYN-ACK acknowledges the client SYN (clientISN+1 == firstC.Seq).
	synack, err := synthPacket(firstS, serverISN, units.Ack(firstC.Seq), true)
	if err != nil {
		return nil, err
	}

	g := *f
	g.Packets = append([]CapturedPacket{syn, synack}, f.Packets...)
	g.CapClientISN = clientISN
	g.CapServerISN = serverISN
	g.HasSyn = true
	g.HasSynAck = true
	g.TSClient = firstC.HasTS
	g.TSServer = firstS.HasTS
	return &g, nil
}

// synthPacket builds a synthetic SYN (or SYN-ACK) by cloning a captured frame's
// headers, stripping the payload, and overwriting the flags and seq/ack.
func synthPacket(tmpl *CapturedPacket, seq units.Seq, ack units.Ack, synack bool) (CapturedPacket, error) {
	buf := append([]byte(nil), tmpl.Rec.Data...)
	p, err := wire.Parse(buf, tmpl.Rec.LinkType)
	if err != nil || !p.IsTCP() {
		return CapturedPacket{}, fmt.Errorf("synth: template packet is not TCP")
	}
	flags := uint8(wire.FlagSYN)
	if synack {
		flags |= wire.FlagACK
	}
	p.SetFlags(flags)
	p.SetSeq(seq)
	p.SetAck(ack)

	// Give the synthesized SYN realistic options the template data frame lacks
	// (MSS, SACK-permitted, and a timestamp if the flow used them), so a device
	// that branches on negotiated options behaves closer to the capture.
	opts := append(wire.SynMSS(1460), wire.SynSACKPerm()...)
	if tsv, _, ok := p.Timestamps(); ok {
		opts = append(opts, wire.SynTimestamp(tsv)...)
	}
	frame, ok := p.RebuildWithOptions(opts, nil)
	if !ok {
		frame = p.RebuildWithPayload(nil) // fall back to the template's own options
	}

	rec := &pcapio.Record{Time: tmpl.Rec.Time, Data: frame, CapLen: len(frame), OrigLen: len(frame), LinkType: tmpl.Rec.LinkType}
	return CapturedPacket{
		Rec:        rec,
		Dir:        tmpl.Dir,
		IsSyn:      !synack,
		IsSynAck:   synack,
		Ack:        synack,
		Seq:        seq,
		AckN:       ack,
		SegLen:     1, // a SYN consumes one sequence number
		PayloadLen: 0,
		HasTS:      tmpl.HasTS,
		TSVal:      tmpl.TSVal,
	}, nil
}
