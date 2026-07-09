// Package dissect parses the industrial protocols livewire replays, exposing
// their app-layer sequence/identity fields and fixing up length/checksum fields
// after a payload is mutated. Several SCADA protocols carry their own counters a
// layer above TCP (Modbus's MBAP transaction id, DNP3's transport/app sequence
// numbers) that a device may validate.
package dissect

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// MBAP header: transaction id, protocol id, length, unit id.
const mbapHeaderLen = 7

// Errors returned by the Modbus dissector.
var (
	ErrShortMBAP    = errors.New("dissect: modbus PDU shorter than MBAP header")
	ErrMBAPLength   = errors.New("dissect: modbus MBAP length field inconsistent with buffer")
	ErrNotModbus    = errors.New("dissect: not a Modbus/TCP protocol id (expected 0)")
	ErrTruncatedPDU = errors.New("dissect: modbus PDU truncated")
)

// MBAP is one Modbus/TCP ADU: the 7-byte header plus the PDU.
type MBAP struct {
	TransactionID uint16 // echoed by the server; the app-layer "seq"
	ProtocolID    uint16 // 0 for Modbus
	Length        uint16 // byte count of UnitID + PDU
	UnitID        uint8
	Function      uint8
	Data          []byte // PDU payload after the function code
	Raw           []byte // full ADU slice (header + PDU)
}

// ParseMBAP parses one ADU from the front of buf and reports how many bytes it
// consumed, for walking a pipelined stream.
func ParseMBAP(buf []byte) (m MBAP, consumed int, err error) {
	if len(buf) < mbapHeaderLen {
		return MBAP{}, 0, ErrShortMBAP
	}
	m.TransactionID = binary.BigEndian.Uint16(buf[0:2])
	m.ProtocolID = binary.BigEndian.Uint16(buf[2:4])
	m.Length = binary.BigEndian.Uint16(buf[4:6])
	m.UnitID = buf[6]
	if m.ProtocolID != 0 {
		return MBAP{}, 0, ErrNotModbus
	}
	// Length covers UnitID + PDU, so the ADU spans 6 + Length bytes.
	if m.Length < 2 {
		return MBAP{}, 0, ErrMBAPLength
	}
	total := int(m.Length) + 6
	if total > len(buf) {
		return MBAP{}, 0, ErrTruncatedPDU
	}
	m.Function = buf[7]
	m.Data = buf[8:total]
	m.Raw = buf[:total]
	return m, total, nil
}

// ParseModbusStream parses every complete ADU in buf (Modbus/TCP may pipeline
// several into one segment). A trailing partial ADU is reported via leftover.
func ParseModbusStream(buf []byte) (adus []MBAP, leftover int, err error) {
	off := 0
	for off < len(buf) {
		m, n, e := ParseMBAP(buf[off:])
		if e != nil {
			if errors.Is(e, ErrShortMBAP) || errors.Is(e, ErrTruncatedPDU) {
				return adus, len(buf) - off, nil // incomplete tail, not an error
			}
			return adus, 0, e
		}
		adus = append(adus, m)
		off += n
	}
	return adus, 0, nil
}

// IsException reports whether this ADU is a Modbus exception response: the
// server sets the high bit of the function code (fn | 0x80) and the single data
// byte carries the exception code.
func (m MBAP) IsException() bool { return m.Function&0x80 != 0 }

// ExceptionCode returns the exception code of an exception response, or 0 if the
// ADU is not an exception (or carries no code byte).
func (m MBAP) ExceptionCode() uint8 {
	if !m.IsException() || len(m.Data) < 1 {
		return 0
	}
	return m.Data[0]
}

// FunctionName maps a Modbus function code to a short human label. The high bit
// is masked off first, so an exception response names its underlying function.
func FunctionName(code uint8) string {
	switch code & 0x7f {
	case 0x01:
		return "read-coils"
	case 0x02:
		return "read-discrete-inputs"
	case 0x03:
		return "read-holding-registers"
	case 0x04:
		return "read-input-registers"
	case 0x05:
		return "write-single-coil"
	case 0x06:
		return "write-single-register"
	case 0x07:
		return "read-exception-status"
	case 0x08:
		return "diagnostics"
	case 0x0b:
		return "get-comm-event-counter"
	case 0x0c:
		return "get-comm-event-log"
	case 0x0f:
		return "write-multiple-coils"
	case 0x10:
		return "write-multiple-registers"
	case 0x11:
		return "report-server-id"
	case 0x16:
		return "mask-write-register"
	case 0x17:
		return "read-write-multiple-registers"
	case 0x18:
		return "read-fifo-queue"
	case 0x2b:
		return "encapsulated-transport"
	}
	return "unknown"
}

// ExceptionName maps a Modbus exception code to its standard label (IEC 61131 /
// the Modbus spec, table of exception codes).
func ExceptionName(code uint8) string {
	switch code {
	case 0x01:
		return "illegal-function"
	case 0x02:
		return "illegal-data-address"
	case 0x03:
		return "illegal-data-value"
	case 0x04:
		return "server-device-failure"
	case 0x05:
		return "acknowledge"
	case 0x06:
		return "server-device-busy"
	case 0x08:
		return "memory-parity-error"
	case 0x0a:
		return "gateway-path-unavailable"
	case 0x0b:
		return "gateway-target-no-response"
	}
	return "unknown"
}

// ADUDiff is one difference between an expected (captured) response ADU and the
// one a live device actually returned. Structural diffs mean the exchange did
// not reproduce (wrong function, an exception, a bad id echo); a non-structural
// diff is a value drift (e.g. register contents changed since capture) that a
// lenient check tolerates.
type ADUDiff struct {
	Structural bool
	Detail     string
}

// CompareADU checks a live response ADU against the captured one it should
// reproduce and returns the differences, most significant first. An empty slice
// means the live response matched the capture byte-for-byte.
func CompareADU(want, got MBAP) []ADUDiff {
	var diffs []ADUDiff

	// An exception where the capture had a normal reply is the headline failure.
	if got.IsException() && !want.IsException() {
		ec := got.ExceptionCode()
		diffs = append(diffs, ADUDiff{true, fmt.Sprintf(
			"expected function 0x%02x (%s), got exception 0x%02x code 0x%02x (%s)",
			want.Function, FunctionName(want.Function), got.Function, ec, ExceptionName(ec))})
		return diffs
	}
	if got.Function != want.Function {
		diffs = append(diffs, ADUDiff{true, fmt.Sprintf(
			"expected function 0x%02x (%s), got 0x%02x (%s)",
			want.Function, FunctionName(want.Function), got.Function, FunctionName(got.Function))})
	}
	if got.TransactionID != want.TransactionID {
		diffs = append(diffs, ADUDiff{true, fmt.Sprintf(
			"transaction id not echoed: capture 0x%04x, live 0x%04x", want.TransactionID, got.TransactionID)})
	}
	if got.UnitID != want.UnitID {
		diffs = append(diffs, ADUDiff{true, fmt.Sprintf(
			"unit id mismatch: capture 0x%02x, live 0x%02x", want.UnitID, got.UnitID)})
	}
	// Same framing, different payload: a value drift, not a protocol failure.
	if got.Function == want.Function && !bytesEqual(want.Data, got.Data) {
		diffs = append(diffs, ADUDiff{false, fmt.Sprintf(
			"response data differs: capture [% x], live [% x]", want.Data, got.Data)})
	}
	return diffs
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// EncodeMBAP serialises an ADU, recomputing Length from the PDU so a mutated
// payload stays self-consistent.
func EncodeMBAP(m MBAP) []byte {
	pdu := len(m.Data) + 1    // function code + data
	length := uint16(pdu + 1) // + unit id
	out := make([]byte, mbapHeaderLen+pdu)
	binary.BigEndian.PutUint16(out[0:2], m.TransactionID)
	binary.BigEndian.PutUint16(out[2:4], m.ProtocolID)
	binary.BigEndian.PutUint16(out[4:6], length)
	out[6] = m.UnitID
	out[7] = m.Function
	copy(out[8:], m.Data)
	return out
}
