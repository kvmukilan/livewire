package protofuzz

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/kvmukilan/livewire/internal/dissect"
)

// modbusProtocol drives Modbus/TCP. The request/reply contract is about as simple
// as a protocol gets -- one ADU out, one ADU back, echoing the transaction id --
// so nearly all of the interesting behaviour is in framing and bounds checking
// rather than in sequencing. DNP3 is the opposite case, which is why both are
// worth having.
type modbusProtocol struct{}

func (modbusProtocol) Name() string { return "modbus" }

func (modbusProtocol) Seeds(unit uint16) []SeedCase {
	built := BuiltinSeeds(uint8(unit))
	out := make([]SeedCase, 0, len(built))
	for _, s := range built {
		out = append(out, s)
	}
	return out
}

func (modbusProtocol) Mutators() []Mutator { return DefaultMutators() }

// Stamp writes the transaction id, which a server is required to echo. A frame
// the truncate mutator cut below two bytes has nowhere to put one.
func (modbusProtocol) Stamp(frame []byte, n uint16) []byte {
	if len(frame) >= 2 {
		binary.BigEndian.PutUint16(frame[0:2], n)
	}
	return frame
}

func (modbusProtocol) Classify(sent []byte, outcome ReadOutcome, reply []byte) (State, []Finding) {
	// Recover the request as the device should have read it, so the echo and
	// function checks have something to compare against. Reading it back out of
	// the sent bytes rather than carrying it alongside means a mutator that
	// rewrote the unit id or function is accounted for automatically.
	var req dissect.MBAP
	if len(sent) >= 8 {
		req.TransactionID = binary.BigEndian.Uint16(sent[0:2])
		req.UnitID = sent[6]
		req.Function = sent[7]
	}
	return Classify(req, sent, outcome, reply)
}

func (modbusProtocol) Probe(unit uint16, n uint16) []byte {
	m := dissect.MBAP{TransactionID: n, UnitID: uint8(unit), Function: 0x03}
	m.Data = append(be16(0), be16(1)...)
	return encodeConsistent(m)
}

func (modbusProtocol) ProbeAnswered(outcome ReadOutcome, reply []byte) error {
	switch outcome {
	case ReadTimeout:
		return errors.New("no reply within the read deadline")
	case ReadClosed:
		return errors.New("peer closed the connection")
	}
	// An exception is a perfectly good answer here: the point is that something
	// on the other end is still parsing Modbus and choosing a reply.
	if _, _, err := dissect.ParseMBAP(reply); err != nil {
		return fmt.Errorf("reply was not a Modbus ADU: %w", err)
	}
	return nil
}

// WantMore completes a reply from the MBAP length field, which counts the unit id
// onward and so spans 6 + Length bytes in total.
func (modbusProtocol) WantMore(buf []byte) int {
	if len(buf) < mbapHeaderLen {
		return mbapHeaderLen - len(buf)
	}
	total := 6 + int(binary.BigEndian.Uint16(buf[4:6]))
	if total > len(buf) && total <= maxADU {
		return total - len(buf)
	}
	return 0
}
