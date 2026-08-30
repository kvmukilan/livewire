package iterate

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name                     string
		completed, matched, wire bool
		want                     Verdict
	}{
		{"completed and matched", true, true, false, Same},
		{"completed but different", true, false, false, Different},
		{"did not complete", false, false, false, Incomplete},
		{"incomplete but matched is still incomplete", false, true, false, Incomplete},
		{"wire mode claims nothing", true, true, true, WireOnly},
		{"wire mode wins over failure", false, false, true, WireOnly},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Classify(c.completed, c.matched, c.wire); got != c.want {
				t.Fatalf("Classify(%v,%v,%v) = %v, want %v", c.completed, c.matched, c.wire, got, c.want)
			}
		})
	}
}

func TestClassifyVerifiedDistinguishesNotCompared(t *testing.T) {
	cases := []struct {
		name                                   string
		completed, verified, matched, wireOnly bool
		want                                   Verdict
	}{
		{"verified match", true, true, true, false, Same},
		{"verified difference", true, true, false, false, Different},
		{"completed but not compared", true, false, false, false, Unverified},
		{"incomplete is still incomplete", false, false, false, false, Incomplete},
		{"wire-only wins", true, true, true, true, WireOnly},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifyVerified(c.completed, c.verified, c.matched, c.wireOnly); got != c.want {
				t.Fatalf("ClassifyVerified(%v,%v,%v,%v) = %v, want %v", c.completed, c.verified, c.matched, c.wireOnly, got, c.want)
			}
		})
	}
}

func TestTallyWorst(t *testing.T) {
	cases := []struct {
		name string
		t    Tally
		want Verdict
	}{
		{"all same", Tally{Same: 3}, Same},
		{"one different among matches", Tally{Same: 2, Different: 1}, Different},
		{"one incomplete outranks different", Tally{Same: 1, Different: 1, Incomplete: 1}, Incomplete},
		{"wire only", Tally{WireOnly: 2}, WireOnly},
		{"unverified", Tally{Unverified: 2}, Unverified},
		{"a match outranks wire-only", Tally{Same: 1, WireOnly: 2}, Same},
		{"unverified prevents an all-matched claim", Tally{Same: 1, Unverified: 2}, Unverified},
		{"empty is not a pass", Tally{}, Incomplete},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.t.Worst(); got != c.want {
				t.Fatalf("Worst() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestTallyTotal(t *testing.T) {
	tl := Tally{Same: 1, Different: 2, WireOnly: 3, Unverified: 4, Incomplete: 5}
	if got := tl.Total(); got != 15 {
		t.Fatalf("Total() = %d, want 15", got)
	}
	var empty Tally
	empty.Add(Same)
	empty.Add(Different)
	empty.Add(WireOnly)
	empty.Add(Unverified)
	empty.Add(Incomplete)
	if empty != (Tally{Same: 1, Different: 1, WireOnly: 1, Unverified: 1, Incomplete: 1}) {
		t.Fatalf("Add did not record each verdict once: %+v", empty)
	}
}

func TestPlanNormalizeAndRepeats(t *testing.T) {
	if got := (Plan{Times: 0}).Normalize().Times; got != 1 {
		t.Fatalf("Times 0 normalized to %d, want 1", got)
	}
	if got := (Plan{Times: -5}).Normalize().Times; got != 1 {
		t.Fatalf("Times -5 normalized to %d, want 1", got)
	}
	if got := (Plan{Times: 3, Gap: -time.Second}).Normalize().Gap; got != 0 {
		t.Fatalf("negative gap normalized to %v, want 0", got)
	}
	if (Plan{Times: 1}).Repeats() {
		t.Fatal("Times 1 must not count as repeating")
	}
	if !(Plan{Times: 2}).Repeats() {
		t.Fatal("Times 2 must count as repeating")
	}
}

func TestPlanRunTimesAndIndexes(t *testing.T) {
	var seen []int
	got := Plan{Times: 4}.Run(context.Background(), func(i int) Tally {
		seen = append(seen, i)
		return Tally{Same: 1}
	})
	if len(got) != 4 {
		t.Fatalf("ran %d attempts, want 4", len(got))
	}
	for i, n := range seen {
		if n != i {
			t.Fatalf("attempt indexes = %v, want 0..3 in order", seen)
		}
	}
}

func TestPlanRunZeroTimesStillRunsOnce(t *testing.T) {
	calls := 0
	got := Plan{Times: 0}.Run(context.Background(), func(int) Tally {
		calls++
		return Tally{Same: 1}
	})
	if calls != 1 || len(got) != 1 {
		t.Fatalf("Times 0: calls=%d results=%d, want 1 and 1", calls, len(got))
	}
}

func TestPlanRunStopWhenDifferent(t *testing.T) {
	// Attempt 2 (index 1) diverges, so the run must stop with two results.
	got := Plan{Times: 5, StopWhenDifferent: true}.Run(context.Background(), func(i int) Tally {
		if i == 1 {
			return Tally{Different: 1}
		}
		return Tally{Same: 1}
	})
	if len(got) != 2 {
		t.Fatalf("ran %d attempts, want 2 (stop at the first divergence)", len(got))
	}

	// A wire-only attempt claims nothing, so it must not trigger the early stop.
	got = Plan{Times: 3, StopWhenDifferent: true}.Run(context.Background(), func(int) Tally {
		return Tally{WireOnly: 1}
	})
	if len(got) != 3 {
		t.Fatalf("wire-only ran %d attempts, want 3", len(got))
	}

	// A completed-but-unverified attempt is not evidence of divergence either.
	got = Plan{Times: 3, StopWhenDifferent: true}.Run(context.Background(), func(int) Tally {
		return Tally{Unverified: 1}
	})
	if len(got) != 3 {
		t.Fatalf("unverified ran %d attempts, want 3", len(got))
	}

	// An incomplete attempt is a divergence too.
	got = Plan{Times: 4, StopWhenDifferent: true}.Run(context.Background(), func(int) Tally {
		return Tally{Incomplete: 1}
	})
	if len(got) != 1 {
		t.Fatalf("incomplete ran %d attempts, want 1", len(got))
	}
}

func TestPlanRunHonoursGap(t *testing.T) {
	const gap = 40 * time.Millisecond
	start := time.Now()
	Plan{Times: 3, Gap: gap}.Run(context.Background(), func(int) Tally { return Tally{Same: 1} })
	// Two gaps between three attempts; no gap before the first.
	if elapsed := time.Since(start); elapsed < 2*gap {
		t.Fatalf("three attempts took %v, want at least %v (two gaps)", elapsed, 2*gap)
	}
}

func TestPlanRunCancelledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	got := Plan{Times: 3}.Run(ctx, func(int) Tally {
		calls++
		return Tally{Same: 1}
	})
	if calls != 0 || len(got) != 0 {
		t.Fatalf("cancelled context: calls=%d results=%d, want 0 and 0", calls, len(got))
	}
}

func TestPlanRunCancelDuringGapKeepsFinishedAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	got := Plan{Times: 5, Gap: time.Hour}.Run(ctx, func(i int) Tally {
		cancel() // as if the operator hit Ctrl-C during attempt 1
		return Tally{Same: 1}
	})
	if len(got) != 1 {
		t.Fatalf("kept %d attempts, want the 1 that finished", len(got))
	}
}

func TestPlanRunNilContext(t *testing.T) {
	//lint:ignore SA1012 a nil context is tolerated so callers need no guard.
	got := Plan{Times: 2}.Run(nil, func(int) Tally { return Tally{Same: 1} })
	if len(got) != 2 {
		t.Fatalf("nil context ran %d attempts, want 2", len(got))
	}
}

func TestSummarizeConsistentPass(t *testing.T) {
	per := []Tally{{Same: 1}, {Same: 1}, {Same: 1}, {Same: 1}, {Same: 1}}
	s := Summarize(per, 5)
	if !s.Consistent || s.Intermittent {
		t.Fatalf("5x same: consistent=%v intermittent=%v, want true/false", s.Consistent, s.Intermittent)
	}
	if s.Verdict != Same || s.Same != 5 || s.Attempts != 5 {
		t.Fatalf("got verdict=%v same=%d attempts=%d, want same/5/5", s.Verdict, s.Same, s.Attempts)
	}
	if s.VerdictName != "same" {
		t.Fatalf("VerdictName = %q, want \"same\"", s.VerdictName)
	}
}

func TestSummarizeIntermittent(t *testing.T) {
	per := []Tally{{Same: 1}, {Same: 1}, {Different: 1}, {Different: 1}, {Same: 1}}
	s := Summarize(per, 5)
	if s.Consistent {
		t.Fatal("a mix of same and different is not consistent")
	}
	if !s.Intermittent {
		t.Fatal("a mix of same and different is intermittent")
	}
	if s.Same != 3 || s.Different != 2 {
		t.Fatalf("got same=%d different=%d, want 3 and 2", s.Same, s.Different)
	}
	if s.Verdict != Different {
		t.Fatalf("Verdict = %v, want different (the worst seen)", s.Verdict)
	}
}

func TestSummarizeIncompleteOutranksDifferent(t *testing.T) {
	s := Summarize([]Tally{{Same: 1}, {Different: 1}, {Incomplete: 1}}, 3)
	if s.Verdict != Incomplete {
		t.Fatalf("Verdict = %v, want incomplete", s.Verdict)
	}
}

func TestSummarizeAllWireOnly(t *testing.T) {
	s := Summarize([]Tally{{WireOnly: 2}, {WireOnly: 2}}, 2)
	if s.Verdict != WireOnly {
		t.Fatalf("Verdict = %v, want wireOnly", s.Verdict)
	}
	if !s.Consistent || s.Intermittent {
		t.Fatalf("uniform wire-only: consistent=%v intermittent=%v, want true/false", s.Consistent, s.Intermittent)
	}
}

func TestSummarizeAllUnverified(t *testing.T) {
	s := Summarize([]Tally{{Unverified: 1}, {Unverified: 1}}, 2)
	if s.Verdict != Unverified || s.Unverified != 2 || s.Sessions.Unverified != 2 {
		t.Fatalf("unverified summary = %+v, want unverified/2", s)
	}
	if !s.Consistent || s.Intermittent {
		t.Fatalf("uniform unverified: consistent=%v intermittent=%v, want true/false", s.Consistent, s.Intermittent)
	}
}

func TestSummarizeSingleAttemptIsNeverIntermittent(t *testing.T) {
	s := Summarize([]Tally{{Different: 1}}, 1)
	if s.Intermittent {
		t.Fatal("one attempt cannot be intermittent")
	}
	if !s.Consistent {
		t.Fatal("one attempt is trivially consistent")
	}
}

func TestSummarizeNoAttempts(t *testing.T) {
	s := Summarize(nil, 3)
	if s.Attempts != 0 || s.Consistent || s.Verdict != Incomplete {
		t.Fatalf("no attempts: attempts=%d consistent=%v verdict=%v, want 0/false/incomplete", s.Attempts, s.Consistent, s.Verdict)
	}
}

func TestSummarizeSessionTotals(t *testing.T) {
	s := Summarize([]Tally{{Same: 2, Different: 1}, {Same: 3}}, 2)
	if s.Sessions.Same != 5 || s.Sessions.Different != 1 {
		t.Fatalf("session totals = %+v, want Same 5 / Different 1", s.Sessions)
	}
	// Per-attempt headline counts always add up to the attempts that ran.
	if s.Same+s.Different+s.WireOnly+s.Unverified+s.Incomplete != s.Attempts {
		t.Fatalf("headline counts %+v do not add up to %d attempts", s, s.Attempts)
	}
}

func TestSummaryPlainIntermittent(t *testing.T) {
	s := Summarize([]Tally{{Same: 1}, {Same: 1}, {Different: 1}, {Same: 1}, {Incomplete: 1}}, 5)
	got := s.Plain()
	want := `
================================
OVERALL: INTERMITTENT
  same as the recording   3 of 5
  different               1 of 5
  did not complete        1 of 5

This device did not behave the same way every time, which is itself a
finding. Send us the report file.
================================
`
	if got != want {
		t.Fatalf("Plain() mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestSummaryPlainConsistentPass(t *testing.T) {
	got := Summarize([]Tally{{Same: 1}, {Same: 1}, {Same: 1}}, 3).Plain()
	if !strings.Contains(got, "OVERALL: SAME AS THE RECORDING") {
		t.Fatalf("missing overall verdict:\n%s", got)
	}
	if !strings.Contains(got, "on all 3 attempts") {
		t.Fatalf("missing attempt count:\n%s", got)
	}
	// Zero counts must not be printed as noise.
	if strings.Contains(got, "different") || strings.Contains(got, "did not complete") {
		t.Fatalf("printed a zero count:\n%s", got)
	}
}

func TestSummaryPlainReportsEarlyStop(t *testing.T) {
	got := Summarize([]Tally{{Same: 1}, {Different: 1}}, 5).Plain()
	if !strings.Contains(got, "Stopped after 2 of 5 attempts.") {
		t.Fatalf("early stop not reported:\n%s", got)
	}
}

// Stopping at the first divergence can leave a single attempt. One sample must
// not be described as a pattern ("on all 1 attempts"), and must not read as if
// the rate were measured.
func TestSummaryPlainDoesNotClaimAPatternFromOneAttempt(t *testing.T) {
	for _, only := range []Tally{{Different: 1}, {Incomplete: 1}, {Same: 1}} {
		got := Summarize([]Tally{only}, 5).Plain()
		if !strings.Contains(got, "Only one attempt ran") {
			t.Errorf("a single attempt should say so:\n%s", got)
		}
		for _, claim := range []string{"all 1 attempts", "any of the 1 attempts", "1 attempts"} {
			if strings.Contains(got, claim) {
				t.Errorf("found %q in a one-attempt summary:\n%s", claim, got)
			}
		}
	}
}

func TestSummaryPlainNoEarlyStopNoteWhenComplete(t *testing.T) {
	got := Summarize([]Tally{{Same: 1}, {Same: 1}}, 2).Plain()
	if strings.Contains(got, "Stopped after") {
		t.Fatalf("reported an early stop for a complete run:\n%s", got)
	}
}

func TestShiftPortZeroStrideKeepsCapturedPort(t *testing.T) {
	if got := ShiftPort(40000, 0); got != 0 {
		t.Fatalf("ShiftPort(40000, 0) = %d, want 0 (meaning: use the captured port)", got)
	}
}

// The whole point is that consecutive attempts present different ports; if any
// two collided, the device would reset the later one as a duplicate.
func TestShiftPortGivesEachAttemptADistinctPort(t *testing.T) {
	for _, captured := range []uint16{1, 502, 40000, 60999, 65535} {
		seen := map[uint16]int{}
		for i := 1; i <= 100; i++ {
			p := ShiftPort(captured, i)
			if prev, dup := seen[p]; dup {
				t.Fatalf("captured %d: attempts %d and %d both got port %d", captured, prev, i, p)
			}
			seen[p] = i
		}
	}
}

func TestShiftPortStaysInEphemeralRange(t *testing.T) {
	const lo, hi = 32768, 60999
	// Include strides large enough to wrap the range more than once.
	for _, captured := range []uint16{0, 1, 502, 32767, 40000, 60999, 65535} {
		for _, n := range []int{1, 2, 100, 28231, 28232, 60000, 1 << 20} {
			p := ShiftPort(captured, n)
			if p < lo || p > hi {
				t.Fatalf("ShiftPort(%d, %d) = %d, outside the ephemeral range %d..%d", captured, n, p, lo, hi)
			}
		}
	}
}

// A negative stride should not land outside the range either: Go's % keeps the
// dividend's sign, so an unguarded modulo would underflow the uint16 conversion.
func TestShiftPortHandlesNegativeStride(t *testing.T) {
	const lo, hi = 32768, 60999
	for _, n := range []int{-1, -100, -60000, -(1 << 20)} {
		p := ShiftPort(40000, n)
		if p < lo || p > hi {
			t.Fatalf("ShiftPort(40000, %d) = %d, outside %d..%d", n, p, lo, hi)
		}
	}
}

// A port below the ephemeral range must not be shifted to just above itself,
// where it could still collide with a listening service.
func TestShiftPortLiftsLowCapturedPortsIntoRange(t *testing.T) {
	if got := ShiftPort(502, 1); got < 32768 {
		t.Fatalf("ShiftPort(502, 1) = %d, want it lifted into the ephemeral range", got)
	}
}

func TestVerdictNames(t *testing.T) {
	for _, c := range []struct {
		v           Verdict
		name, plain string
	}{
		{Same, "same", "SAME AS THE RECORDING"},
		{Different, "different", "DIFFERENT FROM THE RECORDING"},
		{WireOnly, "wireOnly", "SENT ON THE WIRE; NOT COMPARED"},
		{Unverified, "unverified", "COMPLETED; NOT COMPARED"},
		{Incomplete, "incomplete", "DID NOT COMPLETE"},
	} {
		if got := c.v.String(); got != c.name {
			t.Errorf("String() = %q, want %q", got, c.name)
		}
		if got := c.v.Plain(); got != c.plain {
			t.Errorf("Plain() = %q, want %q", got, c.plain)
		}
	}
}
