package engine

import (
	"fmt"
	"math/rand"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/units"
)

// Options controls a dry run. Seed makes ISN/timestamp selection reproducible;
// the ISN overrides pin specific values for testing.
type Options struct {
	Seed         int64
	ClientISN    *uint32
	ServerISN    *uint32
	TSClientBase uint32
	TSServerBase uint32
}

func (o Options) isns() (client, server, tsC, tsS uint32) {
	r := rand.New(rand.NewSource(o.Seed))
	client, server, tsC, tsS = r.Uint32(), r.Uint32(), r.Uint32(), r.Uint32()
	if o.ClientISN != nil {
		client = *o.ClientISN
	}
	if o.ServerISN != nil {
		server = *o.ServerISN
	}
	if o.TSClientBase != 0 {
		tsC = o.TSClientBase
	}
	if o.TSServerBase != 0 {
		tsS = o.TSServerBase
	}
	return
}

// Row is a per-packet line of a rewrite report.
type Row struct {
	Index      int
	Dir        Dir
	Flags      string
	CapSeq     uint32
	LiveSeq    uint32
	CapAck     uint32
	LiveAck    uint32
	AckSet     bool
	AckAligned bool
	Note       string
}

// RewriteReport is the outcome of realigning a whole flow into a fresh session.
type RewriteReport struct {
	Flow          *Flow
	LiveClientISN uint32
	LiveServerISN uint32
	ClientDelta   uint32
	ServerDelta   uint32
	Rows          []Row
	Anomalies     int
	Frames        []pcapio.Record // rewritten frames, ready to write to a pcap
}

// Consistent reports whether every ack lined up with the other side's live sequence space.
func (r *RewriteReport) Consistent() bool { return r.Anomalies == 0 }

// SimulateRewrite realigns every packet of a flow onto a fresh session and
// checks each ack references a valid position in the other side's live space.
// A pure, device-free dry run of the seq/ack rewrite math.
func SimulateRewrite(f *Flow, opts Options) (*RewriteReport, error) {
	if !f.HasSyn || !f.HasSynAck {
		return nil, errNoHandshake(f)
	}
	cISN, sISN, tsC, tsS := opts.isns()
	sess := NewSession(f, units.Seq(cISN), tsC, tsS)
	sess.SetServerISN(units.Seq(sISN))

	rep := &RewriteReport{
		Flow: f, LiveClientISN: cISN, LiveServerISN: sISN,
		ClientDelta: sess.ClientDelta, ServerDelta: sess.ServerDelta,
	}

	// Live next-expected sequence per side, for ack-alignment checking.
	var cliNext, srvNext units.Seq
	cliSet, srvSet := false, false

	for _, cp := range f.Packets {
		buf, info, err := sess.Rewrite(cp)
		if err != nil {
			return nil, err
		}
		rep.Frames = append(rep.Frames, pcapio.Record{
			Time: cp.Rec.Time, Data: buf, CapLen: len(buf), OrigLen: len(buf), LinkType: cp.Rec.LinkType,
		})

		row := Row{
			Index: cp.Index, Dir: cp.Dir, Flags: flagString(cp),
			CapSeq: info.CapSeq.Uint32(), LiveSeq: info.LiveSeq.Uint32(),
			CapAck: info.CapAck.Uint32(), LiveAck: info.LiveAck.Uint32(), AckSet: info.AckSet,
		}

		// Advance this side's next-expected sequence.
		switch cp.Dir {
		case C2S:
			if cp.IsSyn {
				cliNext, cliSet = sess.LiveClientISN.Add(1), true
			} else if cliSet {
				cliNext = info.LiveSeq.Add(cp.SegLen)
			}
		case S2C:
			if cp.IsSynAck {
				srvNext, srvSet = sess.LiveServerISN.Add(1), true
			} else if srvSet {
				srvNext = info.LiveSeq.Add(cp.SegLen)
			}
		}

		// Check the ack references a valid spot in the other side's live space.
		if info.AckSet && !cp.IsSyn {
			var otherISN, otherNext units.Seq
			var otherSet bool
			if cp.Dir == C2S {
				otherISN, otherNext, otherSet = sess.LiveServerISN, srvNext, srvSet
			} else {
				otherISN, otherNext, otherSet = sess.LiveClientISN, cliNext, cliSet
			}
			if otherSet {
				row.AckAligned = info.LiveAck.GreaterEqual(otherISN) && info.LiveAck.LessEqual(otherNext)
			} else {
				row.AckAligned = info.LiveAck == otherISN.Add(1)
			}
			if !row.AckAligned {
				rep.Anomalies++
				row.Note = "ack outside peer live sequence space"
			}
		} else {
			row.AckAligned = true
		}
		rep.Rows = append(rep.Rows, row)
	}
	return rep, nil
}

func errNoHandshake(f *Flow) error {
	return fmt.Errorf("flow %s lacks a full handshake in the capture (SYN=%v SYN-ACK=%v); "+
		"stateful replay needs the SYN and SYN-ACK to anchor the sequence spaces",
		f.Key, f.HasSyn, f.HasSynAck)
}

func flagString(cp CapturedPacket) string {
	s := ""
	add := func(b bool, c string) {
		if b {
			s += c
		}
	}
	add(cp.IsSyn || cp.IsSynAck, "S")
	add(cp.Ack, "A")
	add(cp.PayloadLen > 0, "P")
	add(cp.IsFin, "F")
	add(cp.IsRst, "R")
	if s == "" {
		s = "-"
	}
	return s
}

// WriteRewrittenPcap writes a report's rewritten frames to a classic pcap.
// link is taken from the first frame.
func WriteRewrittenPcap(w interface {
	Write([]byte) (int, error)
}, rep *RewriteReport, nanos bool) error {
	if len(rep.Frames) == 0 {
		return nil
	}
	pw, err := pcapio.NewWriter(w, rep.Frames[0].LinkType, nanos)
	if err != nil {
		return err
	}
	for i := range rep.Frames {
		if err := pw.Write(&rep.Frames[i]); err != nil {
			return err
		}
	}
	return pw.Flush()
}
