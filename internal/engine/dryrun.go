package engine

import (
	"math/rand"

	"github.com/kvmukilan/livewire/internal/units"
	"github.com/kvmukilan/livewire/internal/wire"
)

// DryRunRow records one packet of a live dry run.
type DryRunRow struct {
	Index   int
	Dir     Dir
	Flags   string
	LiveSeq uint32
	LiveAck uint32
	AckSet  bool
	Match   bool
	Note    string
}

// DryRunReport is the outcome of replaying a flow against a simulated compliant
// peer that chooses its own hidden ISN.
type DryRunReport struct {
	Flow             *Flow
	Protocol         string
	LiveClientISN    uint32
	PeerServerISN    uint32 // the ISN the simulated device chose (hidden from the engine)
	LearnedServerISN uint32 // the ISN the engine recovered from the SYN-ACK
	HandshakeOK      bool
	Rows             []DryRunRow
	Mismatches       int
}

// Succeeded reports whether the engine recovered the peer's ISN, completed the
// handshake, and agreed with the peer on every packet's seq/ack.
func (r *DryRunReport) Succeeded() bool {
	return r.HandshakeOK && r.Mismatches == 0 && r.LearnedServerISN == r.PeerServerISN
}

// LiveDryRun simulates replaying a flow against a compliant peer with no NIC.
// The peer picks a hidden ISN; the engine must recover it from the SYN-ACK and
// realign every subsequent packet. Protocol-agnostic (payload never examined).
func LiveDryRun(f *Flow, opts Options) (*DryRunReport, error) {
	if !f.HasSyn || !f.HasSynAck {
		return nil, errNoHandshake(f)
	}
	cISN, _, tsC, tsS := opts.isns()
	// The device's ISN comes from a stream the engine cannot see.
	peerISN := rand.New(rand.NewSource(opts.Seed ^ 0x5DEECE66D)).Uint32()

	engine := NewSession(f, units.Seq(cISN), tsC, tsS) // learns the server ISN at runtime
	peer := NewSession(f, units.Seq(cISN), tsC, tsS)   // the device: knows its own ISN
	peer.SetServerISN(units.Seq(peerISN))

	rep := &DryRunReport{
		Flow: f, Protocol: ProtocolGuess(f.Server.Port, f.Client.Port),
		LiveClientISN: cISN, PeerServerISN: peerISN,
	}
	learned := false

	for _, cp := range f.Packets {
		row := DryRunRow{Index: cp.Index, Dir: cp.Dir, Flags: flagString(cp), AckSet: cp.Ack}

		switch cp.Dir {
		case S2C:
			// The device emits this server packet in its own sequence space.
			peerBytes, _, err := peer.Rewrite(cp)
			if err != nil {
				return nil, err
			}
			pp, err := wire.Parse(peerBytes, cp.Rec.LinkType)
			if err != nil {
				return nil, err
			}
			if cp.IsSynAck && !learned {
				// Engine recovers the server ISN from the SYN-ACK.
				engine.LearnServerISN(pp.Seq())
				learned = true
				rep.LearnedServerISN = pp.Seq().Uint32()
				rep.HandshakeOK = pp.HasFlags(wire.FlagACK) && pp.AckNum() == engine.LiveClientISN.Add(1)
			}
			// What the engine predicts it should receive.
			engBytes, info, err := engine.Rewrite(cp)
			if err != nil {
				return nil, err
			}
			ep, err := wire.Parse(engBytes, cp.Rec.LinkType)
			if err != nil {
				return nil, err
			}
			row.LiveSeq, row.LiveAck = info.LiveSeq.Uint32(), info.LiveAck.Uint32()
			row.Match = ep.Seq() == pp.Seq() && (!pp.HasFlags(wire.FlagACK) || ep.AckNum() == pp.AckNum())

		case C2S:
			// The engine transmits this client packet.
			engBytes, info, err := engine.Rewrite(cp)
			if err != nil {
				return nil, err
			}
			ep, err := wire.Parse(engBytes, cp.Rec.LinkType)
			if err != nil {
				return nil, err
			}
			// What a compliant device would expect.
			peerBytes, _, err := peer.Rewrite(cp)
			if err != nil {
				return nil, err
			}
			pp, err := wire.Parse(peerBytes, cp.Rec.LinkType)
			if err != nil {
				return nil, err
			}
			row.LiveSeq, row.LiveAck = info.LiveSeq.Uint32(), info.LiveAck.Uint32()
			row.Match = ep.Seq() == pp.Seq() && (!ep.HasFlags(wire.FlagACK) || ep.AckNum() == pp.AckNum())
		}

		if !row.Match {
			rep.Mismatches++
			row.Note = "seq/ack disagree with peer"
		}
		rep.Rows = append(rep.Rows, row)
	}
	return rep, nil
}

// ProtocolGuess names a well-known protocol from the port pair, for display only.
func ProtocolGuess(serverPort, clientPort uint16) string {
	for _, port := range []uint16{serverPort, clientPort} {
		switch port {
		case 502:
			return "Modbus/TCP"
		case 20000:
			return "DNP3"
		case 102:
			return "IEC 61850 / S7 (COTP)"
		case 44818:
			return "EtherNet/IP"
		case 2404:
			return "IEC 60870-5-104"
		case 80, 8080:
			return "HTTP"
		case 443, 8443:
			return "HTTPS/TLS"
		case 22:
			return "SSH"
		case 53:
			return "DNS"
		case 25, 587:
			return "SMTP"
		}
	}
	return "generic TCP"
}
