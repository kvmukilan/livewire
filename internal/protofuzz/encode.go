package protofuzz

import (
	"encoding/binary"

	"github.com/kvmukilan/livewire/internal/dissect"
)

// Modbus/TCP size limits, from Modbus Messaging on TCP/IP V1.0b. The PDU cap is
// what a conforming device is allowed to assume; several mutators exist purely
// to find out what a given device does when the cap is exceeded.
const (
	mbapHeaderLen = 7
	maxPDU        = 253
	maxADU        = mbapHeaderLen + maxPDU // 260
)

// encodeRaw serialises an ADU without the self-consistency dissect.EncodeMBAP
// enforces: the caller chooses the length field outright. Emitting a length that
// disagrees with the payload is the entire point of several mutators, so the
// fuzzer needs an encoder that will cheerfully do it.
func encodeRaw(m dissect.MBAP, length uint16) []byte {
	out := make([]byte, mbapHeaderLen+1+len(m.Data))
	binary.BigEndian.PutUint16(out[0:2], m.TransactionID)
	binary.BigEndian.PutUint16(out[2:4], m.ProtocolID)
	binary.BigEndian.PutUint16(out[4:6], length)
	out[6] = m.UnitID
	out[7] = m.Function
	copy(out[8:], m.Data)
	return out
}

// encodeConsistent serialises an ADU with the length field that a conforming
// master would compute: one byte of unit id plus the function code plus data.
func encodeConsistent(m dissect.MBAP) []byte {
	return encodeRaw(m, uint16(len(m.Data)+2))
}

// be16 is a two-byte big-endian field, the width of every address, quantity and
// register value in the Modbus data model.
func be16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}
