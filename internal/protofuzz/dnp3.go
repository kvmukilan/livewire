package protofuzz

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"

	"github.com/kvmukilan/livewire/internal/dissect"
)

// DNP3 link-layer and framing constants, from IEEE 1815. The offsets are into a
// frame as dissect.DNP3.Encode lays it out: start(2) len(1) ctrl(1) dest(2)
// src(2) crc(2), then user data in blocks of up to 16 octets each followed by its
// own CRC.
const (
	dnp3HdrLen      = 10
	dnp3BlockOctets = 16
	dnp3LenOverhead = 5 // LEN counts ctrl + dest + src on top of the user data

	offDNP3Len    = 2
	offDNP3HdrCRC = 8

	// Link control for a master sending unconfirmed user data: DIR | PRM | func 4.
	dnp3MasterControl = 0xC4
	// Transport and application control for a single-fragment request:
	// FIR | FIN, sequence zero.
	dnp3SingleFragment = 0xC0
)

// DNP3Seed is one well-formed DNP3 request. It carries the parsed frame so a
// mutator can edit a named field and re-encode, which matters more here than it
// does for Modbus: every edit inside the user data invalidates a block CRC, and
// dissect.DNP3.Encode recomputes them.
type DNP3Seed struct {
	Name  string
	Frame dissect.DNP3
}

// SeedName satisfies SeedCase.
func (s DNP3Seed) SeedName() string { return s.Name }

// cloneDNP3 copies a seed's frame so a mutator cannot write through to the
// corpus, which is reused for the life of the run.
func cloneDNP3(s DNP3Seed) dissect.DNP3 {
	f := s.Frame
	f.UserData = append([]byte(nil), s.Frame.UserData...)
	return f
}

// dnp3Request assembles a single-fragment application request.
func dnp3Request(name string, addr uint16, fn uint8, objects ...byte) DNP3Seed {
	user := append([]byte{dnp3SingleFragment, dnp3SingleFragment, fn}, objects...)
	return DNP3Seed{Name: name, Frame: dissect.DNP3{
		Control:      dnp3MasterControl,
		Dest:         addr,
		Source:       1,
		UserData:     user,
		HasTransport: true,
		TransportFIN: true,
		TransportFIR: true,
		HasApp:       true,
		AppControl:   dnp3SingleFragment,
		AppFIR:       true,
		AppFIN:       true,
		AppFunc:      fn,
	}}
}

// DNP3Seeds is the default corpus: reads and diagnostics only.
//
// This is a deliberate omission rather than an oversight. DNP3 carries functions
// that do physical work -- select (0x03), operate (0x04), direct-operate (0x05)
// actuate outputs, and cold restart (0x0d) and warm restart (0x0e) reboot the
// outstation. Modbus's equivalent writes land in a register map; a DNP3 operate
// lands on a breaker. Seeding a fuzzer with them would mean the tool's default
// behaviour is to throw control requests at plant equipment, and no amount of
// warning text in a README makes that a reasonable default.
//
// Mutators still reach those function codes, because an outstation's handling of
// an unexpected control request is worth knowing about -- but they arrive as a
// mutation of a read, one frame at a time, rather than as a seed the engine
// returns to and amplifies.
func DNP3Seeds(addr uint16) []DNP3Seed {
	return []DNP3Seed{
		// Read class 0 data (static), qualifier 0x06 = all objects, no range.
		dnp3Request("read-class-0", addr, 0x01, 60, 1, 0x06),
		// Read class 1 events.
		dnp3Request("read-class-1", addr, 0x01, 60, 2, 0x06),
		// Read binary inputs 0..7, qualifier 0x00 = 8-bit start/stop range.
		dnp3Request("read-binary-inputs", addr, 0x01, 1, 2, 0x00, 0x00, 0x07),
		// Read 16-bit analogue inputs 0..3.
		dnp3Request("read-analog-inputs", addr, 0x01, 30, 2, 0x00, 0x00, 0x03),
		// Delay measurement: no objects, used for time synchronisation.
		dnp3Request("delay-measure", addr, 0x17),
		// Disable unsolicited responses for class 1/2/3. Non-actuating.
		dnp3Request("disable-unsolicited", addr, 0x15, 60, 2, 0x06),
	}
}

// dnp3BlockCRCOffsets returns the offset of each data-block CRC in an encoded
// frame, so a mutator can corrupt one without recomputing anything.
func dnp3BlockCRCOffsets(frame []byte) []int {
	var out []int
	if len(frame) <= dnp3HdrLen {
		return nil
	}
	body := len(frame) - dnp3HdrLen
	off := dnp3HdrLen
	for body > 0 {
		data := dnp3BlockOctets
		if body-2 < data {
			data = body - 2
		}
		if data <= 0 {
			break
		}
		crcAt := off + data
		if crcAt+2 > len(frame) {
			break
		}
		out = append(out, crcAt)
		consumed := data + 2
		off += consumed
		body -= consumed
	}
	return out
}

// ---- mutators -------------------------------------------------------------

// dnp3HeaderCRCMutator corrupts the link header CRC. Rejecting it is the first
// thing a DNP3 implementation is required to do, and a frame served anyway means
// the CRC is decorative.
type dnp3HeaderCRCMutator struct{}

func (dnp3HeaderCRCMutator) Name() string { return "dnp3-header-crc" }

func (dnp3HeaderCRCMutator) Mutate(r *rand.Rand, sc SeedCase) ([]byte, string) {
	frame := cloneDNP3(sc.(DNP3Seed)).Encode()
	was := binary.LittleEndian.Uint16(frame[offDNP3HdrCRC:])
	binary.LittleEndian.PutUint16(frame[offDNP3HdrCRC:], was^uint16(1+r.Intn(0xfffe)))
	return frame, fmt.Sprintf("link header CRC corrupted (was 0x%04x)", was)
}

// dnp3BlockCRCMutator corrupts one data-block CRC, which a receiver must also
// check. A device that validates the header CRC and then trusts the body is a
// common shortcut and this is what finds it.
type dnp3BlockCRCMutator struct{}

func (dnp3BlockCRCMutator) Name() string { return "dnp3-block-crc" }

func (dnp3BlockCRCMutator) Mutate(r *rand.Rand, sc SeedCase) ([]byte, string) {
	frame := cloneDNP3(sc.(DNP3Seed)).Encode()
	offs := dnp3BlockCRCOffsets(frame)
	if len(offs) == 0 {
		return frame, "dnp3-block-crc: frame carries no data block, sent unchanged"
	}
	at := offs[r.Intn(len(offs))]
	was := binary.LittleEndian.Uint16(frame[at:])
	binary.LittleEndian.PutUint16(frame[at:], was^uint16(1+r.Intn(0xfffe)))
	return frame, fmt.Sprintf("data block CRC at offset %d corrupted (was 0x%04x)", at, was)
}

// There is deliberately no LEN-field mutator, and the reason is a property of the
// protocol worth knowing. In Modbus/TCP the MBAP length sits outside any checksum,
// so a frame can carry a length that lies about its own payload and a device that
// trusts it will read past the end -- the single most productive Modbus mutation.
// DNP3 puts LEN inside the octets covered by the link header CRC, so changing it
// produces a CRC failure and nothing more: the mutation lands on the CRC check,
// not on the length handling. The Modbus-style lying-length bug class is
// structurally unreachable here, which is a point in IEEE 1815's favour. What
// remains testable is a body shorter than LEN claims, and dnp3TruncateMutator
// covers that without disturbing the header.

// dnp3StartMutator breaks the 0x0564 start octets. Nothing downstream should run.
type dnp3StartMutator struct{}

func (dnp3StartMutator) Name() string { return "dnp3-start" }

func (dnp3StartMutator) Mutate(r *rand.Rand, sc SeedCase) ([]byte, string) {
	frame := cloneDNP3(sc.(DNP3Seed)).Encode()
	if r.Intn(2) == 0 {
		frame[0] ^= byte(1 + r.Intn(255))
	} else {
		frame[1] ^= byte(1 + r.Intn(255))
	}
	return frame, fmt.Sprintf("start octets 0x%02x%02x (must be 0x0564)", frame[0], frame[1])
}

// dnp3TransportMutator attacks the fragmentation state machine: the FIR and FIN
// flags and the six-bit sequence number. This is the mutator that makes "stateful"
// mean something here -- unlike Modbus, DNP3 spreads one application message
// across several link frames, so a receiver has to track an assembly in progress
// and reject a sequence gap, a second FIR before a FIN, and a continuation that
// never began.
type dnp3TransportMutator struct{}

func (dnp3TransportMutator) Name() string { return "dnp3-transport" }

func (dnp3TransportMutator) Mutate(r *rand.Rand, sc SeedCase) ([]byte, string) {
	f := cloneDNP3(sc.(DNP3Seed))
	switch r.Intn(4) {
	case 0:
		f.TransportFIR, f.TransportFIN = false, false
		return f.Encode(), "transport continuation with no FIR: a fragment that never began"
	case 1:
		f.TransportFIR, f.TransportFIN = true, false
		return f.Encode(), "transport FIR without FIN: an assembly left open"
	case 2:
		f.TransportFIR, f.TransportFIN = false, true
		return f.Encode(), "transport FIN without FIR"
	default:
		f.TransportSeq = uint8(r.Intn(64))
		return f.Encode(), fmt.Sprintf("transport sequence jumped to %d", f.TransportSeq)
	}
}

// dnp3AppMutator edits the application header: the function code and the control
// octet's FIR/FIN/CON/UNS bits and four-bit sequence. An outstation must refuse a
// function it does not implement, and must never accept a request carrying the
// unsolicited bit.
type dnp3AppMutator struct{}

func (dnp3AppMutator) Name() string { return "dnp3-app-header" }

func (dnp3AppMutator) Mutate(r *rand.Rand, sc SeedCase) ([]byte, string) {
	f := cloneDNP3(sc.(DNP3Seed))
	if len(f.UserData) < 3 {
		return f.Encode(), "dnp3-app-header: no application header, sent unchanged"
	}
	if r.Intn(2) == 0 {
		fn := byte(r.Intn(256))
		f.UserData[2] = fn
		f.AppFunc = fn
		return f.Encode(), fmt.Sprintf("application function 0x%02x %s",
			fn, dissect.DNP3FunctionName(fn))
	}
	ctl := byte(r.Intn(256))
	f.UserData[1] = ctl
	f.AppControl = ctl
	f.AppSeq = ctl & 0x0F
	note := ""
	if ctl&0x10 != 0 {
		note = " (unsolicited bit set on a request)"
	}
	return f.Encode(), fmt.Sprintf("application control 0x%02x%s", ctl, note)
}

// dnp3ObjectMutator edits the object header that follows the function code:
// group, variation, qualifier and range. A qualifier announcing a count or range
// the frame does not contain is the DNP3 equivalent of a lying length field.
type dnp3ObjectMutator struct{}

func (dnp3ObjectMutator) Name() string { return "dnp3-object-header" }

func (dnp3ObjectMutator) Mutate(r *rand.Rand, sc SeedCase) ([]byte, string) {
	f := cloneDNP3(sc.(DNP3Seed))
	// Object data starts after transport, app control and function octets.
	const objStart = 3
	if len(f.UserData) <= objStart {
		return f.Encode(), "dnp3-object-header: seed carries no objects, sent unchanged"
	}
	at := objStart + r.Intn(len(f.UserData)-objStart)
	was := f.UserData[at]
	f.UserData[at] = byte(r.Intn(256))
	field := "object byte"
	switch at - objStart {
	case 0:
		field = "object group"
	case 1:
		field = "variation"
	case 2:
		field = "qualifier"
	}
	return f.Encode(), fmt.Sprintf("%s at offset %d set to 0x%02x (was 0x%02x)",
		field, at, f.UserData[at], was)
}

// dnp3TruncateMutator cuts the frame mid-body while LEN still claims the whole
// thing, which is what a short read looks like on the wire.
type dnp3TruncateMutator struct{}

func (dnp3TruncateMutator) Name() string { return "dnp3-truncate" }

func (dnp3TruncateMutator) Mutate(r *rand.Rand, sc SeedCase) ([]byte, string) {
	frame := cloneDNP3(sc.(DNP3Seed)).Encode()
	if len(frame) <= dnp3HdrLen {
		return frame, "dnp3-truncate: frame already minimal, sent unchanged"
	}
	cut := dnp3HdrLen + r.Intn(len(frame)-dnp3HdrLen)
	return frame[:cut], fmt.Sprintf("truncated to %d of %d octets", cut, len(frame))
}

// dnp3LinkControlMutator edits the link-layer control octet: direction, primary,
// the frame-count bit and its validity flag, and the link function code. A
// request arriving with PRM clear is a secondary frame and an outstation should
// not treat it as user data.
type dnp3LinkControlMutator struct{}

func (dnp3LinkControlMutator) Name() string { return "dnp3-link-control" }

func (dnp3LinkControlMutator) Mutate(r *rand.Rand, sc SeedCase) ([]byte, string) {
	f := cloneDNP3(sc.(DNP3Seed))
	f.Control = byte(r.Intn(256))
	note := ""
	if f.Control&0x40 == 0 {
		note = " (PRM clear: a secondary frame)"
	}
	return f.Encode(), fmt.Sprintf("link control 0x%02x%s", f.Control, note)
}

// DNP3Mutators is the DNP3 mutator set.
func DNP3Mutators() []Mutator {
	return []Mutator{
		dnp3HeaderCRCMutator{},
		dnp3BlockCRCMutator{},
		dnp3StartMutator{},
		dnp3TransportMutator{},
		dnp3AppMutator{},
		dnp3ObjectMutator{},
		dnp3TruncateMutator{},
		dnp3LinkControlMutator{},
	}
}

// ---- protocol -------------------------------------------------------------

// dnp3Protocol drives DNP3 over TCP. Where Modbus is one request and one reply,
// DNP3 stacks a link layer with CRCs over a transport layer that fragments over a
// application layer that sequences, and every one of those has rules a receiver
// must enforce. That is why it is the more interesting target of the two.
type dnp3Protocol struct{}

func (dnp3Protocol) Name() string { return "dnp3" }

func (dnp3Protocol) Seeds(unit uint16) []SeedCase {
	built := DNP3Seeds(unit)
	out := make([]SeedCase, 0, len(built))
	for _, s := range built {
		out = append(out, s)
	}
	return out
}

func (dnp3Protocol) Mutators() []Mutator { return DNP3Mutators() }

// Stamp deliberately does nothing. DNP3's per-request identifier is the
// application sequence number, which lives inside a CRC-protected block -- poking
// it into an encoded frame would invalidate that block's CRC and turn every case
// into a corrupt-frame case. The classifier compares the reply's sequence against
// the one it reads back out of the frame that was actually sent, which needs no
// stamping.
func (dnp3Protocol) Stamp(frame []byte, _ uint16) []byte { return frame }

func (dnp3Protocol) Probe(unit uint16, _ uint16) []byte {
	return dnp3Request("probe", unit, 0x01, 60, 1, 0x06).Frame.Encode()
}

func (dnp3Protocol) ProbeAnswered(outcome ReadOutcome, reply []byte) error {
	switch outcome {
	case ReadTimeout:
		return errors.New("no reply within the read deadline")
	case ReadClosed:
		return errors.New("peer closed the connection")
	}
	if _, _, err := dissect.ParseDNP3(reply); err != nil {
		return fmt.Errorf("reply was not a DNP3 frame: %w", err)
	}
	return nil
}

// WantMore completes a frame from the LEN octet: user data is LEN-5 octets, each
// run of 16 carrying its own two-octet CRC.
func (dnp3Protocol) WantMore(buf []byte) int {
	if len(buf) < dnp3HdrLen {
		return dnp3HdrLen - len(buf)
	}
	length := int(buf[offDNP3Len])
	if length < dnp3LenOverhead {
		return 0 // nonsense LEN; waiting cannot help
	}
	userLen := length - dnp3LenOverhead
	blocks := (userLen + dnp3BlockOctets - 1) / dnp3BlockOctets
	total := dnp3HdrLen + userLen + 2*blocks
	if total > len(buf) {
		return total - len(buf)
	}
	return 0
}

// Classify reads one DNP3 exchange. As with Modbus, silence is not a finding:
// discarding a frame whose CRC or LEN does not hold up is exactly what IEEE 1815
// requires, so the absence of a reply is usually the device being correct.
func (dnp3Protocol) Classify(sent []byte, outcome ReadOutcome, reply []byte) (State, []Finding) {
	switch outcome {
	case ReadTimeout:
		return State{Kind: StateSilent}, nil
	case ReadClosed:
		return State{Kind: StateClosed}, []Finding{{
			Severity: SevLow,
			Kind:     "connection-closed",
			Detail:   "peer closed the connection instead of answering or discarding",
		}}
	}

	got, _, err := dissect.ParseDNP3(reply)
	if err != nil {
		// The device emitted something that is not a valid DNP3 frame. Its own
		// CRCs are its responsibility, so this is a real deviation.
		return State{Kind: StateMalformed}, []Finding{{
			Severity: SevMedium,
			Kind:     "reply-not-dnp3",
			Detail:   fmt.Sprintf("reply did not parse as a DNP3 frame: %v", err),
		}}
	}

	var findings []Finding
	state := State{Kind: StateNormal, Function: got.AppFunc}
	// Internal indications follow the transport, control and function octets.
	if len(got.UserData) >= 5 {
		state.Indications = uint16(got.UserData[3])<<8 | uint16(got.UserData[4])
	}

	// A response must carry function 0x81, or 0x82 if unsolicited.
	if got.HasApp && got.AppFunc != 0x81 && got.AppFunc != 0x82 {
		findings = append(findings, Finding{SevMedium, "dnp3-unexpected-response-function",
			fmt.Sprintf("reply carries application function 0x%02x (%s); a response is 0x81 or 0x82",
				got.AppFunc, dissect.DNP3FunctionName(got.AppFunc))})
	}

	// The application sequence must echo the request's, read back out of the
	// frame that was actually sent so a mutated sequence is accounted for.
	if want, ok := dnp3SentAppSeq(sent); ok && got.HasApp && got.AppFunc == 0x81 && got.AppSeq != want {
		findings = append(findings, Finding{SevMedium, "dnp3-app-seq-not-echoed",
			fmt.Sprintf("sent application sequence %d, reply carries %d", want, got.AppSeq)})
	}

	// The finding that matters most: the device answered a frame it was required
	// to throw away. ParseDNP3 is the same validator a conforming receiver needs,
	// so if it refuses the frame, so should the device have.
	if _, _, err := dissect.ParseDNP3(sent); err != nil {
		findings = append(findings, Finding{SevMedium, "served-nonconforming-frame",
			fmt.Sprintf("answered a request that is not a valid DNP3 frame: %v", err)})
	}

	return state, findings
}

// dnp3SentAppSeq recovers the application sequence from a frame that was sent,
// tolerating one that was deliberately mangled.
func dnp3SentAppSeq(sent []byte) (uint8, bool) {
	d, _, err := dissect.ParseDNP3(sent)
	if err != nil || !d.HasApp {
		return 0, false
	}
	return d.AppSeq, true
}
