// Package dissect parses the industrial protocols livewire replays, exposing
// their app-layer sequence/identity fields and fixing up length/checksum fields
// after a payload is mutated. Several SCADA protocols carry their own counters a
// layer above TCP (Modbus's MBAP transaction id, DNP3's transport/app sequence
// numbers) that a device may validate.
package dissect

import (
	"encoding/binary"
	"errors"
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
