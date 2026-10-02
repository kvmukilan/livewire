package protofuzz

import (
	"fmt"
	"math/rand"
)

// SeedCase is one well-formed starting point for mutation. Each protocol defines
// its own concrete type, and the engine only ever hands a protocol's mutators
// seeds that came from the same protocol, so a mutator may assert its own type
// directly. A failed assertion is a wiring mistake rather than bad input, and
// panicking on it is preferable to silently fuzzing the wrong shape.
type SeedCase interface {
	SeedName() string
}

// Protocol is everything the engine needs in order to drive one application
// protocol: how to build cases from seeds, and how to read what came back.
// Keeping it behind an interface is what lets the loop -- pick a seed, mutate,
// send, classify, probe -- stay the same for Modbus and DNP3, which otherwise
// share almost nothing above TCP.
type Protocol interface {
	// Name is the value the -protocol flag takes.
	Name() string

	// Seeds is the starting corpus, addressed to unit (a Modbus unit id, or a
	// DNP3 outstation address).
	Seeds(unit uint16) []SeedCase

	// Mutators is the set of mutations that make sense for this protocol.
	Mutators() []Mutator

	// Stamp writes a per-case identifier into an already-encoded frame so a reply
	// can be tied to its request. A protocol with no usable identifier returns
	// the frame unchanged.
	Stamp(frame []byte, n uint16) []byte

	// Classify turns one exchange into an observable state plus any deviations
	// from the specification. Correct behaviour must produce no findings.
	Classify(sent []byte, outcome ReadOutcome, reply []byte) (State, []Finding)

	// Probe is a well-formed request whose answer shows the device is still
	// speaking the protocol. It is how the engine tells a deliberately discarded
	// frame from a device that has stopped working.
	Probe(unit uint16, n uint16) []byte

	// ProbeAnswered reports whether a reply to Probe came from a live peer. An
	// error means the target is no longer serving traffic it had been serving.
	ProbeAnswered(outcome ReadOutcome, reply []byte) error

	// WantMore reports how many further bytes are needed to complete the frame at
	// the front of buf, or 0 when it looks complete -- or unparseable, since
	// waiting on a frame whose header makes no sense would only stall. It lets the
	// engine tolerate a reply split across segments without itself knowing any
	// framing.
	WantMore(buf []byte) int
}

// Mutator derives one case from a seed. It returns the bytes to put on the wire
// and a short label naming what it changed, so a finding can be read and
// reproduced without anyone having to diff a hex dump.
type Mutator interface {
	Name() string
	Mutate(r *rand.Rand, s SeedCase) (frame []byte, what string)
}

// Protocols are the protocols the fuzz command can drive, keyed by flag value.
func Protocols() []Protocol {
	return []Protocol{modbusProtocol{}, dnp3Protocol{}}
}

// ProtocolByName resolves the -protocol flag.
func ProtocolByName(name string) (Protocol, error) {
	for _, p := range Protocols() {
		if p.Name() == name {
			return p, nil
		}
	}
	var names []string
	for _, p := range Protocols() {
		names = append(names, p.Name())
	}
	return nil, fmt.Errorf("unknown protocol %q (try %v)", name, names)
}
