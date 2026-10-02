package protofuzz

import (
	"bytes"
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/dissect"
)

func newDNP3Target(t *testing.T, d Defects) *DNP3MockTarget {
	t.Helper()
	m, err := ServeDNP3Mock("127.0.0.1:0", 1, d)
	if err != nil {
		t.Fatalf("ServeDNP3Mock: %v", err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func dnp3Config(addr string, cases int) Config {
	return Config{
		Target:     addr,
		Protocol:   dnp3Protocol{},
		Unit:       1,
		Cases:      cases,
		Timeout:    200 * time.Millisecond,
		Seed:       42,
		ProbeEvery: 0,
	}
}

func TestDNP3SeedsAreWellFormed(t *testing.T) {
	for _, s := range DNP3Seeds(1) {
		frame := s.Frame.Encode()
		got, consumed, err := dissect.ParseDNP3(frame)
		if err != nil {
			t.Fatalf("seed %s does not parse: %v (frame % x)", s.Name, err, frame)
		}
		if consumed != len(frame) {
			t.Fatalf("seed %s: consumed %d of %d octets", s.Name, consumed, len(frame))
		}
		if !got.HasApp {
			t.Fatalf("seed %s has no application header", s.Name)
		}
	}
}

// TestDNP3SeedsExcludeControlFunctions pins the safety decision in DNP3Seeds. A
// seed is returned to and amplified by the scheduler, so a control function in the
// corpus would mean the tool's default behaviour is to repeatedly actuate outputs
// or reboot the outstation. If someone adds one, this test should stop them and
// make them argue for it.
func TestDNP3SeedsExcludeControlFunctions(t *testing.T) {
	forbidden := map[uint8]string{
		0x03: "select",
		0x04: "operate",
		0x05: "direct-operate",
		0x06: "direct-operate-no-ack",
		0x0d: "cold-restart",
		0x0e: "warm-restart",
	}
	for _, s := range DNP3Seeds(1) {
		if name, bad := forbidden[s.Frame.AppFunc]; bad {
			t.Fatalf("seed %q uses function 0x%02x (%s), which actuates or reboots a device "+
				"and must not be in the default corpus", s.Name, s.Frame.AppFunc, name)
		}
	}
}

func TestDNP3BlockCRCOffsetsLandOnRealCRCs(t *testing.T) {
	// A seed with enough user data to span two CRC blocks.
	s := dnp3Request("long", 1, 0x01, bytes.Repeat([]byte{0x3c, 0x01, 0x06}, 9)...)
	frame := s.Frame.Encode()
	if _, _, err := dissect.ParseDNP3(frame); err != nil {
		t.Fatalf("baseline frame invalid: %v", err)
	}
	offs := dnp3BlockCRCOffsets(frame)
	if len(offs) < 2 {
		t.Fatalf("expected at least 2 block CRCs, got %d (frame %d octets)", len(offs), len(frame))
	}
	// Corrupting any reported offset must make the frame fail to parse; that is
	// the only thing the mutator relies on.
	for _, at := range offs {
		bad := append([]byte(nil), frame...)
		bad[at] ^= 0xff
		if _, _, err := dissect.ParseDNP3(bad); err == nil {
			t.Fatalf("corrupting offset %d left the frame valid, so it is not a CRC", at)
		}
	}
}

func TestDNP3MutatorsProduceAFrameAndALabel(t *testing.T) {
	r := rand.New(rand.NewSource(5))
	for _, m := range DNP3Mutators() {
		for _, s := range DNP3Seeds(1) {
			for i := 0; i < 20; i++ {
				frame, what := m.Mutate(r, s)
				if len(frame) == 0 {
					t.Fatalf("%s on %s produced an empty frame", m.Name(), s.Name)
				}
				if what == "" {
					t.Fatalf("%s on %s produced no label", m.Name(), s.Name)
				}
			}
		}
	}
}

func TestDNP3MutatorsLeaveTheCorpusIntact(t *testing.T) {
	seeds := DNP3Seeds(1)
	before := make([][]byte, len(seeds))
	for i, s := range seeds {
		before[i] = append([]byte(nil), s.Frame.UserData...)
	}
	r := rand.New(rand.NewSource(9))
	for _, m := range DNP3Mutators() {
		for i := range seeds {
			for k := 0; k < 25; k++ {
				m.Mutate(r, seeds[i])
			}
		}
	}
	for i, s := range seeds {
		if !bytes.Equal(s.Frame.UserData, before[i]) {
			t.Fatalf("seed %s was modified: now % x, was % x", s.Name, s.Frame.UserData, before[i])
		}
	}
}

func TestDNP3ClassifySilenceIsNotAFinding(t *testing.T) {
	sent := DNP3Seeds(1)[0].Frame.Encode()
	state, findings := dnp3Protocol{}.Classify(sent, ReadTimeout, nil)
	if state.Kind != StateSilent {
		t.Fatalf("state = %v, want silent", state.Kind)
	}
	if len(findings) != 0 {
		t.Fatalf("silence produced findings: %+v", findings)
	}
}

func TestDNP3WantMoreCompletesAFrame(t *testing.T) {
	p := dnp3Protocol{}
	full := DNP3Seeds(1)[2].Frame.Encode()
	if n := p.WantMore(full); n != 0 {
		t.Fatalf("a complete frame wants %d more octets", n)
	}
	// A frame cut short should ask for the remainder -- but until the link header
	// has arrived the total is unknowable, because LEN lives in it, so up to that
	// point it can only ask for the rest of the header.
	for cut := 1; cut < len(full); cut++ {
		want := len(full) - cut
		if cut < dnp3HdrLen {
			want = dnp3HdrLen - cut
		}
		if n := p.WantMore(full[:cut]); n != want {
			t.Fatalf("at %d of %d octets WantMore = %d, want %d", cut, len(full), n, want)
		}
	}
	// A nonsense LEN must not make the engine wait forever.
	bad := append([]byte(nil), full...)
	bad[offDNP3Len] = 0
	if n := p.WantMore(bad); n != 0 {
		t.Fatalf("an out-of-range LEN asked for %d more octets", n)
	}
}

func TestDNP3RunAgainstConformingOutstationFindsNothing(t *testing.T) {
	m := newDNP3Target(t, Defects{})
	res, err := Run(context.Background(), dnp3Config(m.Addr(), 150))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Occurrences) != 0 {
		for _, o := range res.Occurrences {
			t.Errorf("unexpected finding [%s] %s via %s: %s (frame % x)",
				o.Finding.Severity, o.Finding.Kind, o.Mutator, o.Finding.Detail, o.Frame)
		}
		t.Fatal("a conforming outstation produced findings; the classifier is too eager")
	}
	// Internal indications are what give DNP3 usable state feedback, since it has
	// one response function code. If this drops to one state the feedback loop has
	// gone blind and the scheduler is doing nothing.
	if res.Coverage.Distinct() < 3 {
		t.Fatalf("only %d state(s) reached; expected silence plus at least two indication variants",
			res.Coverage.Distinct())
	}
}

func TestDNP3RunDetectsAnOutstationThatTrustsABadCRC(t *testing.T) {
	m := newDNP3Target(t, Defects{TrustBadCRC: true})
	res, err := Run(context.Background(), dnp3Config(m.Addr(), 250))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, o := range res.Occurrences {
		if o.Finding.Kind == "served-nonconforming-frame" {
			return
		}
	}
	t.Fatalf("an outstation answering a bad-CRC frame was not caught; findings: %+v", res.Occurrences)
}

func TestDNP3RunDetectsWedge(t *testing.T) {
	m := newDNP3Target(t, Defects{WedgeAfter: 8})
	cfg := dnp3Config(m.Addr(), 60)
	cfg.ProbeEvery = 5
	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Wedged {
		t.Fatalf("an outstation that stopped answering was not detected after %d cases", res.Sent)
	}
	for _, o := range res.Occurrences {
		if o.Finding.Kind == "target-unresponsive" && o.Finding.Severity == SevHigh {
			return
		}
	}
	t.Fatalf("wedge produced no high-severity finding: %+v", res.Occurrences)
}

func TestProtocolByName(t *testing.T) {
	for _, want := range []string{"modbus", "dnp3"} {
		p, err := ProtocolByName(want)
		if err != nil {
			t.Fatalf("ProtocolByName(%q): %v", want, err)
		}
		if p.Name() != want {
			t.Fatalf("got protocol %q, want %q", p.Name(), want)
		}
	}
	if _, err := ProtocolByName("bacnet"); err == nil {
		t.Fatal("expected an error for an unsupported protocol")
	}
}
