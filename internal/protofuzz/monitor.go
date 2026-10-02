package protofuzz

import (
	"encoding/binary"
	"fmt"

	"github.com/kvmukilan/livewire/internal/dissect"
)

// ReadOutcome is what happened when the engine tried to read a reply.
type ReadOutcome int

const (
	// ReadOK means bytes arrived.
	ReadOK ReadOutcome = iota
	// ReadTimeout means the deadline passed with nothing to read.
	ReadTimeout
	// ReadClosed means the peer closed or reset the connection.
	ReadClosed
)

// Severity ranks a finding for the end-of-run report.
type Severity int

const (
	// SevLow is a spec deviation with no obvious consequence: an echo field the
	// device did not echo, for instance.
	SevLow Severity = iota
	// SevMedium is a device acting on a frame it was required to reject, or
	// answering in a way that breaks the request/reply contract.
	SevMedium
	// SevHigh is the device no longer serving traffic.
	SevHigh
)

func (s Severity) String() string {
	switch s {
	case SevLow:
		return "low"
	case SevMedium:
		return "medium"
	case SevHigh:
		return "high"
	}
	return "unknown"
}

// Finding is one deviation from the Modbus spec worth a human look. Correct
// behaviour never produces a finding -- notably, a device that answers a bad
// request with the right exception is behaving, and a device that silently drops a
// malformed frame is also behaving. See Classify.
type Finding struct {
	Severity Severity
	Kind     string
	Detail   string
}

// conformance reports whether a frame about to be sent is one a conforming device
// is permitted to reject outright, and why. The engine uses this to decide
// whether a normal reply is suspicious: answering a frame that breaks framing
// rules means the device parsed something it should have thrown away.
func conformance(frame []byte) (conforming bool, why string) {
	if len(frame) < mbapHeaderLen+1 {
		return false, "shorter than an MBAP header plus function code"
	}
	if len(frame) > maxADU {
		return false, fmt.Sprintf("ADU is %d bytes, over the %d-byte cap", len(frame), maxADU)
	}
	if pid := binary.BigEndian.Uint16(frame[2:4]); pid != 0 {
		return false, fmt.Sprintf("protocol id is 0x%04x, not 0", pid)
	}
	declared := binary.BigEndian.Uint16(frame[4:6])
	actual := uint16(len(frame) - 6) // length covers unit id onward
	if declared != actual {
		return false, fmt.Sprintf("length field says %d, frame carries %d", declared, actual)
	}
	return true, ""
}

// Classify turns one exchange into a state plus any spec deviations.
//
// Silence is deliberately not a finding on its own. The Modbus TCP spec lets a
// device discard a frame whose MBAP length disagrees with what arrived, without
// replying, so a dropped malformed frame is correct behaviour and reporting it
// would bury the real findings in noise. Silence matters only if the liveness
// probe that follows also goes unanswered, which the engine checks separately and
// reports as SevHigh.
func Classify(req dissect.MBAP, sent []byte, outcome ReadOutcome, reply []byte) (State, []Finding) {
	switch outcome {
	case ReadTimeout:
		return State{Kind: StateSilent}, nil
	case ReadClosed:
		// A close is more than a drop: the device gave up on a connection it could
		// have kept serving. Worth reporting, but not alarming on its own, since
		// some stacks close rather than discard by design.
		return State{Kind: StateClosed}, []Finding{{
			Severity: SevLow,
			Kind:     "connection-closed",
			Detail:   "peer closed the connection instead of answering or discarding",
		}}
	}

	if len(reply) < mbapHeaderLen+1 {
		return State{Kind: StateMalformed}, []Finding{{
			Severity: SevMedium,
			Kind:     "short-reply",
			Detail:   fmt.Sprintf("reply is %d bytes, too short to be an ADU", len(reply)),
		}}
	}

	var findings []Finding

	// Read the header directly rather than through ParseMBAP, because ParseMBAP
	// rejects a nonzero protocol id and that is itself one of the things worth
	// reporting rather than a reason to stop looking.
	txid := binary.BigEndian.Uint16(reply[0:2])
	pid := binary.BigEndian.Uint16(reply[2:4])
	declared := binary.BigEndian.Uint16(reply[4:6])
	unit := reply[6]
	fn := reply[7]

	if pid != 0 {
		findings = append(findings, Finding{SevMedium, "reply-protocol-id",
			fmt.Sprintf("reply protocol id is 0x%04x, must be 0", pid)})
	}
	if txid != req.TransactionID {
		findings = append(findings, Finding{SevMedium, "transaction-id-not-echoed",
			fmt.Sprintf("sent 0x%04x, reply carries 0x%04x", req.TransactionID, txid)})
	}
	if unit != req.UnitID {
		findings = append(findings, Finding{SevLow, "unit-id-not-echoed",
			fmt.Sprintf("sent 0x%02x, reply carries 0x%02x", req.UnitID, unit)})
	}
	if actual := uint16(len(reply) - 6); declared != actual {
		findings = append(findings, Finding{SevMedium, "reply-length-mismatch",
			fmt.Sprintf("reply length field says %d, reply carries %d", declared, actual)})
	}
	if len(reply) > maxADU {
		findings = append(findings, Finding{SevMedium, "reply-oversize",
			fmt.Sprintf("reply is %d bytes, over the %d-byte cap", len(reply), maxADU)})
	}

	state := State{Function: fn & 0x7f}
	if fn&0x80 != 0 {
		state.Kind = StateException
		if len(reply) > 8 {
			state.Exception = reply[8]
		}
	} else {
		state.Kind = StateNormal
		// The reply must answer the function that was asked. An exception is a
		// legitimate answer to anything; a different function code is not.
		if fn != req.Function {
			findings = append(findings, Finding{SevMedium, "function-mismatch",
				fmt.Sprintf("asked 0x%02x (%s), answered 0x%02x (%s)",
					req.Function, dissect.FunctionName(req.Function), fn, dissect.FunctionName(fn))})
		}
		// The finding that matters most: a normal reply to a frame the device was
		// entitled to discard means it parsed and acted on malformed framing.
		if ok, why := conformance(sent); !ok {
			findings = append(findings, Finding{SevMedium, "served-nonconforming-frame",
				fmt.Sprintf("answered normally though the request %s", why)})
		}
	}

	return state, findings
}
