package protofuzz

import (
	"bytes"
	"context"
	"encoding/binary"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/dissect"
)

func testSeed() Seed {
	return Seed{Name: "read-holding-registers", ADU: dissect.MBAP{
		UnitID: 1, Function: 0x03, Data: []byte{0x00, 0x00, 0x00, 0x04},
	}}
}

func TestEncodeConsistentAgreesWithDissect(t *testing.T) {
	m := testSeed().ADU
	m.TransactionID = 0x1234
	got := encodeConsistent(m)
	want := dissect.EncodeMBAP(m)
	if !bytes.Equal(got, want) {
		t.Fatalf("encodeConsistent disagrees with dissect.EncodeMBAP:\n got % x\nwant % x", got, want)
	}
}

func TestEncodeRawAllowsInconsistentLength(t *testing.T) {
	m := testSeed().ADU
	frame := encodeRaw(m, 0xffff)
	if declared := binary.BigEndian.Uint16(frame[4:6]); declared != 0xffff {
		t.Fatalf("length field = 0x%04x, want 0xffff", declared)
	}
	// The whole point: the frame must stay emittable even though the length field
	// is a lie, because dissect.EncodeMBAP would have corrected it.
	if actual := len(frame) - 6; actual == 0xffff {
		t.Fatal("frame length happens to match, test proves nothing")
	}
}

func TestCloneDoesNotAliasSeed(t *testing.T) {
	s := testSeed()
	original := append([]byte(nil), s.ADU.Data...)
	m := clone(s)
	for i := range m.Data {
		m.Data[i] = 0xff
	}
	if !bytes.Equal(s.ADU.Data, original) {
		t.Fatalf("mutating the clone wrote through to the seed: seed now % x, was % x", s.ADU.Data, original)
	}
}

func TestCoverageObserveAndSummary(t *testing.T) {
	cov := NewCoverage()
	normal := State{Kind: StateNormal, Function: 0x03}
	exc := State{Kind: StateException, Exception: 0x02}

	if !cov.Observe(normal) {
		t.Fatal("first observation should report a new state")
	}
	if cov.Observe(normal) {
		t.Fatal("second observation of the same state should not be new")
	}
	cov.Observe(exc)
	cov.Observe(exc)
	cov.Observe(exc)

	if cov.Distinct() != 2 {
		t.Fatalf("Distinct() = %d, want 2", cov.Distinct())
	}
	if n := cov.Count(normal); n != 2 {
		t.Fatalf("Count(normal) = %d, want 2", n)
	}
	sum := cov.Summary()
	if len(sum) != 2 || sum[0].Key != exc.Key() {
		t.Fatalf("Summary() should lead with the most frequent state, got %+v", sum)
	}
}

func TestSchedulerCoversCorpusBeforeFavouring(t *testing.T) {
	seeds := modbusProtocol{}.Seeds(1)
	cov := NewCoverage()
	sched := NewScheduler(seeds, cov)
	r := rand.New(rand.NewSource(7))

	// Untried seeds outrank everything, so the first picks should between
	// them touch every seed rather than hammering one.
	seen := make(map[int]bool)
	for i := 0; i < len(seeds)*20; i++ {
		idx := sched.Pick(r)
		seen[idx] = true
		sched.Record(idx, State{Kind: StateNormal, Function: 0x03})
		cov.Observe(State{Kind: StateNormal, Function: 0x03})
	}
	if len(seen) != len(seeds) {
		t.Fatalf("scheduler reached %d of %d seeds", len(seen), len(seeds))
	}
}

func TestSchedulerPrefersRareState(t *testing.T) {
	seeds := []SeedCase{Seed{Name: "common"}, Seed{Name: "rare"}}
	cov := NewCoverage()
	sched := NewScheduler(seeds, cov)

	common := State{Kind: StateNormal, Function: 0x03}
	rare := State{Kind: StateException, Exception: 0x04}
	for i := 0; i < 200; i++ {
		cov.Observe(common)
	}
	cov.Observe(rare)
	sched.Record(0, common)
	sched.Record(1, rare)

	r := rand.New(rand.NewSource(1))
	rareHits := 0
	for i := 0; i < 1000; i++ {
		if sched.Pick(r) == 1 {
			rareHits++
		}
	}
	if rareHits < 600 {
		t.Fatalf("seed on the rare state picked %d/1000 times, expected a clear majority", rareHits)
	}
}

func TestConformance(t *testing.T) {
	good := encodeConsistent(testSeed().ADU)
	if ok, why := conformance(good); !ok {
		t.Fatalf("well-formed frame reported nonconforming: %s", why)
	}
	bad := encodeRaw(testSeed().ADU, 0x0001)
	if ok, _ := conformance(bad); ok {
		t.Fatal("frame with a lying length field reported conforming")
	}
	if ok, _ := conformance(make([]byte, 4)); ok {
		t.Fatal("4-byte frame reported conforming")
	}
}

func TestClassifySilenceIsNotAFinding(t *testing.T) {
	req := testSeed().ADU
	state, findings := Classify(req, encodeConsistent(req), ReadTimeout, nil)
	if state.Kind != StateSilent {
		t.Fatalf("state = %v, want silent", state.Kind)
	}
	// The spec lets a device discard a frame it does not like without replying, so
	// silence alone must not be reported; only a failed liveness probe counts.
	if len(findings) != 0 {
		t.Fatalf("silence produced findings: %+v", findings)
	}
}

// reply builds a well-formed response to req for the classifier tests.
func reply(txid uint16, pid uint16, unit, fn byte, payload []byte) []byte {
	out := make([]byte, mbapHeaderLen+1+len(payload))
	binary.BigEndian.PutUint16(out[0:2], txid)
	binary.BigEndian.PutUint16(out[2:4], pid)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(payload)+2))
	out[6] = unit
	out[7] = fn
	copy(out[8:], payload)
	return out
}

func TestClassifyAcceptsAGoodReply(t *testing.T) {
	req := testSeed().ADU
	req.TransactionID = 0x0042
	good := reply(0x0042, 0, req.UnitID, 0x03, []byte{0x08, 0, 1, 0, 2, 0, 3, 0, 4})
	state, findings := Classify(req, encodeConsistent(req), ReadOK, good)
	if state.Kind != StateNormal || state.Function != 0x03 {
		t.Fatalf("state = %+v, want normal/0x03", state)
	}
	if len(findings) != 0 {
		t.Fatalf("a conforming reply produced findings: %+v", findings)
	}
}

func TestClassifyDetectsEchoAndHeaderFaults(t *testing.T) {
	req := testSeed().ADU
	req.TransactionID = 0x0042

	cases := []struct {
		name  string
		reply []byte
		kind  string
	}{
		{"txid not echoed", reply(0x9999, 0, req.UnitID, 0x03, []byte{0x02, 0, 1}), "transaction-id-not-echoed"},
		{"unit not echoed", reply(0x0042, 0, 0x7f, 0x03, []byte{0x02, 0, 1}), "unit-id-not-echoed"},
		{"bad protocol id", reply(0x0042, 0x1234, req.UnitID, 0x03, []byte{0x02, 0, 1}), "reply-protocol-id"},
		{"wrong function", reply(0x0042, 0, req.UnitID, 0x04, []byte{0x02, 0, 1}), "function-mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, findings := Classify(req, encodeConsistent(req), ReadOK, tc.reply)
			for _, f := range findings {
				if f.Kind == tc.kind {
					return
				}
			}
			t.Fatalf("expected finding %q, got %+v", tc.kind, findings)
		})
	}
}

func TestClassifyFlagsNonconformingFrameServed(t *testing.T) {
	req := testSeed().ADU
	req.TransactionID = 1
	// The device answered normally even though the request's length field lied.
	sent := encodeRaw(req, 0x0001)
	good := reply(1, 0, req.UnitID, 0x03, []byte{0x02, 0, 1})
	_, findings := Classify(req, sent, ReadOK, good)
	for _, f := range findings {
		if f.Kind == "served-nonconforming-frame" {
			return
		}
	}
	t.Fatalf("expected served-nonconforming-frame, got %+v", findings)
}

func TestClassifyExceptionIsNotAFinding(t *testing.T) {
	req := testSeed().ADU
	req.TransactionID = 5
	exc := reply(5, 0, req.UnitID, 0x03|0x80, []byte{0x03})
	state, findings := Classify(req, encodeConsistent(req), ReadOK, exc)
	if state.Kind != StateException || state.Exception != 0x03 {
		t.Fatalf("state = %+v, want exception/0x03", state)
	}
	// Refusing a bad request with the right exception is the device behaving.
	if len(findings) != 0 {
		t.Fatalf("a correct exception produced findings: %+v", findings)
	}
}

func TestMutatorsProduceAFrameAndALabel(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for _, m := range DefaultMutators() {
		for _, s := range BuiltinSeeds(1) {
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

// TestMutatorsLeaveTheCorpusIntact guards the aliasing bug clone() exists to
// prevent: a mutator that wrote through to its seed would silently change what
// every later case is derived from.
func TestMutatorsLeaveTheCorpusIntact(t *testing.T) {
	seeds := BuiltinSeeds(1)
	before := make([][]byte, len(seeds))
	for i, s := range seeds {
		before[i] = append([]byte(nil), s.ADU.Data...)
	}
	r := rand.New(rand.NewSource(11))
	for _, m := range DefaultMutators() {
		for i := range seeds {
			for k := 0; k < 25; k++ {
				m.Mutate(r, seeds[i])
			}
		}
	}
	for i, s := range seeds {
		if !bytes.Equal(s.ADU.Data, before[i]) {
			t.Fatalf("seed %s was modified: now % x, was % x", s.Name, s.ADU.Data, before[i])
		}
	}
}

func fuzzConfig(addr string, cases int) Config {
	return Config{
		Target:     addr,
		Unit:       1,
		Cases:      cases,
		Timeout:    200 * time.Millisecond,
		Seed:       42,
		ProbeEvery: 0,
	}
}

func TestRunAgainstConformingMockFindsNothing(t *testing.T) {
	m := newMockTarget(t, Defects{})
	res, err := Run(context.Background(), fuzzConfig(m.Addr(), 150))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Occurrences) != 0 {
		for _, o := range res.Occurrences {
			t.Errorf("unexpected finding [%s] %s via %s: %s (frame % x)",
				o.Finding.Severity, o.Finding.Kind, o.Mutator, o.Finding.Detail, o.Frame)
		}
		t.Fatal("a conforming server produced findings; the classifier is too eager")
	}
	// A run that reached only one state has not exercised anything.
	if res.Coverage.Distinct() < 2 {
		t.Fatalf("only %d state(s) reached, expected the mock to answer several ways", res.Coverage.Distinct())
	}
}

func TestRunDetectsTrustedLengthField(t *testing.T) {
	m := newMockTarget(t, Defects{TrustLengthField: true})
	res, err := Run(context.Background(), fuzzConfig(m.Addr(), 400))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, o := range res.Occurrences {
		if o.Finding.Kind == "served-nonconforming-frame" {
			return
		}
	}
	t.Fatalf("a server that trusts the length field was not caught; findings: %+v", res.Occurrences)
}

func TestRunDetectsTransactionIDNotEchoed(t *testing.T) {
	m := newMockTarget(t, Defects{DontEchoTxID: true})
	res, err := Run(context.Background(), fuzzConfig(m.Addr(), 40))
	if err == nil {
		for _, o := range res.Occurrences {
			if o.Finding.Kind == "transaction-id-not-echoed" {
				return
			}
		}
	}
	// The baseline probe parses the reply but does not check the echo, so the run
	// should still start and then report the fault.
	t.Fatalf("echo fault not reported; err=%v findings=%+v", err, res)
}

func TestRunDetectsWedge(t *testing.T) {
	m := newMockTarget(t, Defects{WedgeAfter: 8})
	cfg := fuzzConfig(m.Addr(), 60)
	cfg.ProbeEvery = 5
	res, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Wedged {
		t.Fatalf("a server that stopped answering was not detected as wedged after %d cases", res.Sent)
	}
	if res.Sent >= 60 {
		t.Fatal("run should have stopped early rather than sending every case")
	}
	var high bool
	for _, o := range res.Occurrences {
		if o.Finding.Kind == "target-unresponsive" && o.Finding.Severity == SevHigh {
			high = true
		}
	}
	if !high {
		t.Fatalf("wedge did not produce a high-severity finding: %+v", res.Occurrences)
	}
}

func TestRunRefusesATargetThatNeverAnswered(t *testing.T) {
	// A closed port: the engine must say so rather than report a page of silence
	// as if the device had been tested.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	if _, err := Run(context.Background(), fuzzConfig(addr, 10)); err == nil {
		t.Fatal("expected an error for a target that does not answer a baseline request")
	}
}

func TestRunStopsOnCancelledContext(t *testing.T) {
	m := newMockTarget(t, Defects{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := Run(ctx, fuzzConfig(m.Addr(), 500))
	if err != nil {
		t.Fatalf("a cancelled run should return its result, not an error: %v", err)
	}
	if res.Sent != 0 {
		t.Fatalf("cancelled before the first case, but %d were sent", res.Sent)
	}
}
