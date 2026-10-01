package protofuzz

import "github.com/kvmukilan/livewire/internal/dissect"

// Seed is one request the engine mutates. Seeds are carried as parsed ADUs
// rather than raw bytes so a mutator can target a named field — the length, a
// quantity, a starting address — instead of blindly flipping bits in a header
// the device would reject before reaching any interesting code.
type Seed struct {
	Name string
	ADU  dissect.MBAP
}

// Request-field layouts, so a mutator knows where a quantity or byte count
// lives in the PDU it is editing rather than hard-coding offsets per call site.
const (
	offStartAddress = 0 // first field of every read and single-write request
	offQuantity     = 2 // read requests, and the count in a multiple-write
	offByteCount    = 4 // multiple-write requests only
)

// Per-function quantity ceilings from the Modbus spec. A request above the
// ceiling must draw an illegal-data-value exception; a device that instead
// tries to serve it is the bug this table exists to find.
var quantityCeiling = map[uint8]uint16{
	0x01: 2000, // read coils
	0x02: 2000, // read discrete inputs
	0x03: 125,  // read holding registers
	0x04: 125,  // read input registers
	0x0f: 1968, // write multiple coils
	0x10: 123,  // write multiple registers
}

// BuiltinSeeds returns one well-formed request per function code worth
// exercising. They are deliberately conservative — small reads, writes to low
// addresses — because the engine's job is to mutate them, and a seed that is
// already out of bounds tells you nothing about which mutation mattered.
func BuiltinSeeds(unitID uint8) []Seed {
	seed := func(name string, fn uint8, data ...byte) Seed {
		return Seed{Name: name, ADU: dissect.MBAP{UnitID: unitID, Function: fn, Data: data}}
	}
	read := func(name string, fn uint8, start, qty uint16) Seed {
		d := append(be16(start), be16(qty)...)
		return seed(name, fn, d...)
	}

	seeds := []Seed{
		read("read-coils", 0x01, 0, 8),
		read("read-discrete-inputs", 0x02, 0, 8),
		read("read-holding-registers", 0x03, 0, 4),
		read("read-input-registers", 0x04, 0, 4),
		seed("write-single-coil", 0x05, 0x00, 0x00, 0xff, 0x00),
		seed("write-single-register", 0x06, 0x00, 0x00, 0x12, 0x34),
		seed("read-exception-status", 0x07),
		seed("report-server-id", 0x11),
	}

	// Write-multiple requests carry a byte count that must agree with the
	// quantity; keeping a correct one here means a later disagreement is
	// unambiguously the mutator's doing.
	coils := append(be16(0), be16(8)...)
	coils = append(coils, 0x01, 0xff)
	seeds = append(seeds, seed("write-multiple-coils", 0x0f, coils...))

	regs := append(be16(0), be16(2)...)
	regs = append(regs, 0x04, 0x11, 0x22, 0x33, 0x44)
	seeds = append(seeds, seed("write-multiple-registers", 0x10, regs...))

	return seeds
}
