package protofuzz

import (
	"encoding/binary"
	"fmt"
	"math/rand"

	"github.com/kvmukilan/livewire/internal/dissect"
)

// Mutator derives one case from a seed. It returns the bytes to put on the wire
// and a short label naming what it changed, so a finding can be read and
// reproduced without anyone having to diff a hex dump.
type Mutator interface {
	Name() string
	Mutate(r *rand.Rand, s Seed) (frame []byte, what string)
}

// clone copies a seed ADU so a mutator can edit fields in place without
// corrupting the corpus. Seeds are reused for the whole run, and a mutator that
// wrote through to the stored Data would quietly poison every later case.
func clone(s Seed) dissect.MBAP {
	m := s.ADU
	m.Data = append([]byte(nil), s.ADU.Data...)
	m.Raw = nil
	return m
}

// interestingU16 are the two-byte values worth trying before random ones: zero,
// the signed and unsigned boundaries, and the values either side of a byte
// carry. Length, quantity and address fields are all 16-bit, and parser bugs
// cluster at exactly these points.
var interestingU16 = []uint16{0, 1, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xfffe, 0xffff}

// pickU16 favours the interesting values but still returns a uniform one often
// enough that the search does not get stuck on the table.
func pickU16(r *rand.Rand) uint16 {
	if r.Intn(4) > 0 {
		return interestingU16[r.Intn(len(interestingU16))]
	}
	return uint16(r.Intn(0x10000))
}

// lengthFieldMutator makes the MBAP length field disagree with the payload that
// follows it. A device that trusts the field over the bytes it actually received
// will read past the frame or block waiting for data that never arrives, so this
// is the first thing worth trying against any Modbus/TCP stack.
type lengthFieldMutator struct{}

func (lengthFieldMutator) Name() string { return "length-field" }

func (lengthFieldMutator) Mutate(r *rand.Rand, s Seed) ([]byte, string) {
	m := clone(s)
	honest := uint16(len(m.Data) + 2)
	length := pickU16(r)
	return encodeRaw(m, length), fmt.Sprintf("length=0x%04x (consistent would be 0x%04x)", length, honest)
}

// quantityMutator pushes the quantity field past the per-function ceiling the
// spec sets. The correct answer is an illegal-data-value exception; a device that
// instead attempts the transfer may have sized something from the request.
type quantityMutator struct{}

func (quantityMutator) Name() string { return "quantity" }

func (quantityMutator) Mutate(r *rand.Rand, s Seed) ([]byte, string) {
	m := clone(s)
	if len(m.Data) < offQuantity+2 {
		return encodeConsistent(m), "quantity: seed has no quantity field, sent unchanged"
	}
	var qty uint16
	if ceil, ok := quantityCeiling[m.Function&0x7f]; ok && r.Intn(2) == 0 {
		// Just over the ceiling is the boundary that matters; a wild value is
		// often rejected by a cheaper check further up the stack.
		qty = ceil + 1
	} else {
		qty = pickU16(r)
	}
	binary.BigEndian.PutUint16(m.Data[offQuantity:], qty)
	return encodeConsistent(m), fmt.Sprintf("quantity=%d", qty)
}

// addressMutator walks the starting address to the edges of the 16-bit data
// model, including values where start+quantity overflows it. The sum is what a
// device must range-check, and checking only the start is a common slip.
type addressMutator struct{}

func (addressMutator) Name() string { return "address" }

func (addressMutator) Mutate(r *rand.Rand, s Seed) ([]byte, string) {
	m := clone(s)
	if len(m.Data) < offStartAddress+2 {
		return encodeConsistent(m), "address: seed has no address field, sent unchanged"
	}
	addr := pickU16(r)
	binary.BigEndian.PutUint16(m.Data[offStartAddress:], addr)
	what := fmt.Sprintf("start-address=0x%04x", addr)
	if len(m.Data) >= offQuantity+2 {
		qty := binary.BigEndian.Uint16(m.Data[offQuantity:])
		if uint32(addr)+uint32(qty) > 0xffff {
			what += fmt.Sprintf(" (start+quantity=%d overflows the address space)", uint32(addr)+uint32(qty))
		}
	}
	return encodeConsistent(m), what
}

// byteCountMutator makes the byte count of a write-multiple request disagree with
// its quantity. The two are redundant by design, and a device that validates one
// while sizing on the other is the bug this finds.
type byteCountMutator struct{}

func (byteCountMutator) Name() string { return "byte-count" }

func (byteCountMutator) Mutate(r *rand.Rand, s Seed) ([]byte, string) {
	m := clone(s)
	fn := m.Function & 0x7f
	if fn != 0x0f && fn != 0x10 {
		return encodeConsistent(m), "byte-count: not a write-multiple, sent unchanged"
	}
	if len(m.Data) < offByteCount+1 {
		return encodeConsistent(m), "byte-count: seed too short, sent unchanged"
	}
	bc := byte(r.Intn(256))
	m.Data[offByteCount] = bc
	return encodeConsistent(m), fmt.Sprintf("byte-count=%d (payload carries %d)", bc, len(m.Data)-offByteCount-1)
}

// functionMutator sends function codes that are reserved, undefined, or carry the
// exception bit a client is never supposed to set. Illegal-function is the only
// correct answer; anything else means the dispatch table is reachable in a way
// the spec does not allow.
type functionMutator struct{}

func (functionMutator) Name() string { return "function-code" }

func (functionMutator) Mutate(r *rand.Rand, s Seed) ([]byte, string) {
	m := clone(s)
	fn := byte(r.Intn(256))
	m.Function = fn
	note := ""
	if fn&0x80 != 0 {
		note = " (exception bit set on a request)"
	}
	return encodeConsistent(m), fmt.Sprintf("function=0x%02x %s%s", fn, dissect.FunctionName(fn), note)
}

// truncateMutator cuts the frame mid-PDU while leaving the length field claiming
// the full size, which is the on-the-wire shape of a short read. A device must
// wait for the rest or drop the frame; it must not act on the fragment.
type truncateMutator struct{}

func (truncateMutator) Name() string { return "truncate" }

func (truncateMutator) Mutate(r *rand.Rand, s Seed) ([]byte, string) {
	full := encodeConsistent(clone(s))
	if len(full) <= mbapHeaderLen+1 {
		return full, "truncate: frame already minimal, sent unchanged"
	}
	cut := mbapHeaderLen + 1 + r.Intn(len(full)-mbapHeaderLen-1)
	return full[:cut], fmt.Sprintf("truncated to %d of %d bytes", cut, len(full))
}

// oversizeMutator grows the PDU past the 253-byte cap the spec guarantees a
// device may assume. Anything that sized a fixed buffer from that guarantee
// without checking the arrival will show it here.
type oversizeMutator struct{}

func (oversizeMutator) Name() string { return "oversize" }

func (oversizeMutator) Mutate(r *rand.Rand, s Seed) ([]byte, string) {
	m := clone(s)
	target := maxPDU + 1 + r.Intn(512)
	pad := make([]byte, target-len(m.Data)-1)
	for i := range pad {
		pad[i] = byte(r.Intn(256))
	}
	m.Data = append(m.Data, pad...)
	return encodeConsistent(m), fmt.Sprintf("pdu=%d bytes (cap is %d)", len(m.Data)+1, maxPDU)
}

// headerMutator edits the two MBAP fields that identify the conversation rather
// than describe its payload: the protocol id, which must be zero for Modbus, and
// the unit id. A device answering a nonzero protocol id is not speaking
// Modbus/TCP any more.
type headerMutator struct{}

func (headerMutator) Name() string { return "mbap-header" }

func (headerMutator) Mutate(r *rand.Rand, s Seed) ([]byte, string) {
	m := clone(s)
	if r.Intn(2) == 0 {
		m.ProtocolID = pickU16(r)
		return encodeConsistent(m), fmt.Sprintf("protocol-id=0x%04x (must be 0)", m.ProtocolID)
	}
	m.UnitID = byte(r.Intn(256))
	return encodeConsistent(m), fmt.Sprintf("unit-id=0x%02x", m.UnitID)
}

// bitflipMutator is the dumb baseline: flip a few bits in the PDU. It is kept
// because structure-aware mutators only look where their author thought to look,
// and the cheap random case occasionally lands somewhere nobody modelled.
type bitflipMutator struct{}

func (bitflipMutator) Name() string { return "bitflip" }

func (bitflipMutator) Mutate(r *rand.Rand, s Seed) ([]byte, string) {
	m := clone(s)
	if len(m.Data) == 0 {
		return encodeConsistent(m), "bitflip: seed has no data, sent unchanged"
	}
	flips := 1 + r.Intn(3)
	for i := 0; i < flips; i++ {
		at := r.Intn(len(m.Data))
		var bit byte = 1
		bit = bit << uint(r.Intn(8))
		m.Data[at] ^= bit
	}
	return encodeConsistent(m), fmt.Sprintf("%d bit(s) flipped in the pdu", flips)
}

// DefaultMutators is the set the fuzz command uses. Order is not significant --
// the engine picks uniformly -- but the structure-aware mutators are listed first
// because they are the ones worth reading about in a report.
func DefaultMutators() []Mutator {
	return []Mutator{
		lengthFieldMutator{},
		quantityMutator{},
		addressMutator{},
		byteCountMutator{},
		functionMutator{},
		truncateMutator{},
		oversizeMutator{},
		headerMutator{},
		bitflipMutator{},
	}
}
