package engine

import (
	"github.com/kvmukilan/livewire/internal/units"
	"github.com/kvmukilan/livewire/internal/wire"
)

// Session holds the per-flow rewrite state that realigns captured seq numbers
// onto a live session: one delta per direction, plus timestamp-rewrite state to
// satisfy a peer's PAWS check (RFC 7323).
type Session struct {
	Flow          *Flow
	LiveClientISN units.Seq
	LiveServerISN units.Seq
	ClientDelta   uint32 // live - captured, client sequence space
	ServerDelta   uint32 // live - captured, server sequence space
	serverKnown   bool

	// Timestamp rewriting: fresh monotonic TSval per side, TSecr echoes the
	// other side's most recent live TSval.
	tsBase     [2]uint32
	tsFirstCap [2]uint32
	haveFirst  [2]bool
	lastLiveTS [2]uint32
	rewriteTS  bool
}

// NewSession builds a session for a captured flow. The server ISN is learned
// later via LearnServerISN (or set up front for full-rewrite mode).
func NewSession(f *Flow, liveClientISN units.Seq, tsClientBase, tsServerBase uint32) *Session {
	return &Session{
		Flow:          f,
		LiveClientISN: liveClientISN,
		ClientDelta:   f.CapClientISN.Delta(liveClientISN),
		tsBase:        [2]uint32{tsClientBase, tsServerBase},
		rewriteTS:     f.TSClient || f.TSServer,
	}
}

// LearnServerISN records the server's ISN (from its SYN-ACK) and computes the
// server-space delta. The server's ISN is random (RFC 6528), so every captured
// server sequence and client ack derived from it must shift by this delta.
func (s *Session) LearnServerISN(live units.Seq) {
	s.LiveServerISN = live
	s.ServerDelta = s.Flow.CapServerISN.Delta(live)
	s.serverKnown = true
}

// SetServerISN sets the server ISN directly (full-rewrite dry-run, both ISNs chosen).
func (s *Session) SetServerISN(live units.Seq) { s.LearnServerISN(live) }

// RewriteInfo reports the before/after sequence numbers for one packet.
type RewriteInfo struct {
	Dir      Dir
	CapSeq   units.Seq
	LiveSeq  units.Seq
	CapAck   units.Ack
	LiveAck  units.Ack
	AckSet   bool
	SegLen   uint32
	IsSyn    bool
	IsSynAck bool
	IsFin    bool
	IsRst    bool
}

// Rewrite realigns one captured packet into live sequence space, returning a
// fresh buffer plus a summary; the record is not modified. Call in timeline
// order so timestamp echoes stay consistent.
func (s *Session) Rewrite(cp CapturedPacket) ([]byte, RewriteInfo, error) {
	buf := append([]byte(nil), cp.Rec.Data...)
	p, err := wire.Parse(buf, cp.Rec.LinkType)
	if err != nil {
		return nil, RewriteInfo{}, err
	}
	info := RewriteInfo{
		Dir: cp.Dir, CapSeq: cp.Seq, CapAck: cp.AckN, AckSet: cp.Ack,
		SegLen: cp.SegLen, IsSyn: cp.IsSyn, IsSynAck: cp.IsSynAck, IsFin: cp.IsFin, IsRst: cp.IsRst,
	}
	if !p.IsTCP() {
		p.RecalcChecksums()
		return buf, info, nil
	}

	var seqDelta, ackDelta, sackDelta uint32
	if cp.Dir == C2S {
		seqDelta, ackDelta, sackDelta = s.ClientDelta, s.ServerDelta, s.ServerDelta
	} else {
		seqDelta, ackDelta, sackDelta = s.ServerDelta, s.ClientDelta, s.ClientDelta
	}

	newSeq := p.Seq().AddDelta(seqDelta)
	p.SetSeq(newSeq)
	info.LiveSeq = newSeq
	if p.HasFlags(wire.FlagACK) {
		newAck := p.AckNum().AddDelta(ackDelta)
		p.SetAck(newAck)
		info.LiveAck = newAck
	}

	// SACK edges are absolute sequence numbers in the other side's space.
	p.RewriteSACKEdges(func(e uint32) uint32 { return e + sackDelta })

	if s.rewriteTS {
		s.rewriteTimestamps(p, cp.Dir)
	}

	p.RecalcChecksums()
	return buf, info, nil
}

// rewriteTimestamps emits a fresh TSval for this direction and echoes the other
// direction's most recent live TSval in TSecr.
func (s *Session) rewriteTimestamps(p *wire.Packet, dir Dir) {
	tsv, _, ok := p.Timestamps()
	if !ok {
		return
	}
	side := int(dir)
	other := 1 - side
	if !s.haveFirst[side] {
		s.tsFirstCap[side] = tsv
		s.haveFirst[side] = true
	}
	newTSval := s.tsBase[side] + (tsv - s.tsFirstCap[side]) // wrapping preserves relative timing
	newTSecr := uint32(0)
	if p.HasFlags(wire.FlagACK) {
		newTSecr = s.lastLiveTS[other]
	}
	p.SetTimestamps(newTSval, newTSecr)
	s.lastLiveTS[side] = newTSval
}
