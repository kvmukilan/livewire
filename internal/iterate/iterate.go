// Package iterate runs a replay more than once and reduces the attempts to a
// single plain-language answer.
//
// A device that misbehaves one time in five is the common field case, and a
// single replay cannot express it. Repeating the replay turns "it didn't
// reproduce" into a rate, and a device that answers differently from attempt to
// attempt is itself a finding worth naming.
//
// The loop, the per-attempt classification, and the summary wording live here so
// the CLI and the web dashboard cannot drift apart on any of the three.
package iterate

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Verdict is one session's outcome, in the terms a peer reads.
type Verdict int

const (
	// Same means the exchange completed and the replies matched the recording.
	Same Verdict = iota
	// Different means the exchange completed but the device answered differently.
	Different
	// WireOnly means frames were sent at captured timing without any claim of
	// live adaptation or response equivalence.
	WireOnly
	// Incomplete means the exchange did not finish.
	Incomplete
)

// String is the machine-readable name used in reports.
func (v Verdict) String() string {
	switch v {
	case Same:
		return "same"
	case Different:
		return "different"
	case WireOnly:
		return "wireOnly"
	default:
		return "incomplete"
	}
}

// Plain is the one-line verdict a peer reads, matching the wording of the
// per-session verdict blocks.
func (v Verdict) Plain() string {
	switch v {
	case Same:
		return "SAME AS THE RECORDING"
	case Different:
		return "DIFFERENT FROM THE RECORDING"
	case WireOnly:
		return "SENT ON THE WIRE; NOT COMPARED"
	default:
		return "DID NOT COMPLETE"
	}
}

// severity ranks verdicts by how much they should worry the reader, so the
// overall answer for a run is the worst thing that happened in it. It is
// deliberately not the declaration order: WireOnly claims nothing either way, so
// it ranks below a clean match rather than above a divergence.
func (v Verdict) severity() int {
	switch v {
	case Incomplete:
		return 3
	case Different:
		return 2
	case Same:
		return 1
	default: // WireOnly
		return 0
	}
}

// Classify maps a session's result booleans onto a Verdict. wireOnly wins
// because a wire-mode replay never claims equivalence, so its completed/matched
// flags carry no meaning.
func Classify(completed, matched, wireOnly bool) Verdict {
	switch {
	case wireOnly:
		return WireOnly
	case completed && matched:
		return Same
	case completed:
		return Different
	default:
		return Incomplete
	}
}

// Tally counts session verdicts within one attempt.
type Tally struct {
	Same       int `json:"sameAsRecording"`
	Different  int `json:"different"`
	WireOnly   int `json:"wireOnly"`
	Incomplete int `json:"didNotComplete"`
}

// Add records one session's verdict.
func (t *Tally) Add(v Verdict) {
	switch v {
	case Same:
		t.Same++
	case Different:
		t.Different++
	case WireOnly:
		t.WireOnly++
	default:
		t.Incomplete++
	}
}

// Total is the number of sessions counted.
func (t Tally) Total() int { return t.Same + t.Different + t.WireOnly + t.Incomplete }

// Worst reduces an attempt's sessions to that attempt's headline verdict: the
// most serious thing that happened, since one broken session in an otherwise
// clean attempt is the interesting part.
func (t Tally) Worst() Verdict {
	switch {
	case t.Incomplete > 0:
		return Incomplete
	case t.Different > 0:
		return Different
	case t.Same > 0:
		return Same
	case t.WireOnly > 0:
		return WireOnly
	default:
		return Incomplete // nothing ran, which is not a pass
	}
}

// Plan describes how many times to run and how to space the attempts.
type Plan struct {
	// Times is the number of attempts; anything below 1 means 1.
	Times int
	// Gap is the settle time between attempts.
	Gap time.Duration
	// StopWhenDifferent ends the run at the first attempt that does not match
	// the recording, for callers who want one failing sample rather than a rate.
	StopWhenDifferent bool
}

// Normalize clamps the plan to runnable values.
func (p Plan) Normalize() Plan {
	if p.Times < 1 {
		p.Times = 1
	}
	if p.Gap < 0 {
		p.Gap = 0
	}
	return p
}

// Repeats reports whether this plan runs more than once. Callers use it to keep
// single-attempt output identical to a run with no iteration at all.
func (p Plan) Repeats() bool { return p.Normalize().Times > 1 }

// Run calls attempt for each iteration and collects the tallies. i is 0-based
// and is the caller's cue to vary anything that must differ between attempts
// (seeds, local ports).
//
// It stops early when ctx is cancelled or when StopWhenDifferent is set and an
// attempt did not match, so the returned slice may be shorter than Times. The
// gap is skippable by cancellation, so Ctrl-C does not wait it out.
func (p Plan) Run(ctx context.Context, attempt func(i int) Tally) []Tally {
	p = p.Normalize()
	if ctx == nil {
		ctx = context.Background()
	}
	out := make([]Tally, 0, p.Times)
	for i := 0; i < p.Times; i++ {
		if ctx.Err() != nil {
			break
		}
		if i > 0 && !sleepCtx(ctx, p.Gap) {
			break
		}
		t := attempt(i)
		out = append(out, t)
		if p.StopWhenDifferent && t.Worst() != Same && t.Worst() != WireOnly {
			break
		}
	}
	return out
}

// sleepCtx waits for d, reporting false if ctx was cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// ShiftPort moves a captured client port by n so a repeated attempt does not
// present the device with the same four-tuple twice. TCP identifies a connection
// by that tuple: replaying it back-to-back looks like a stale duplicate, the
// device resets it, and the run reads as a failure to reproduce when nothing was
// actually wrong.
//
// The result stays inside the usual ephemeral range so the substitute never
// collides with a service the host might be listening on. n == 0 returns 0,
// meaning "use the captured port" — the faithful choice for a single replay.
func ShiftPort(captured uint16, n int) uint16 {
	if n == 0 {
		return 0
	}
	const lo, hi = 32768, 60999
	span := hi - lo + 1
	base := int(captured)
	if base < lo {
		base = lo
	}
	// Go's % keeps the sign of the dividend, so normalise before indexing.
	off := ((base-lo+n)%span + span) % span
	return uint16(lo + off)
}

// Summary reduces every attempt to the answer a peer needs: what happened, how
// often, and whether the device was consistent about it.
type Summary struct {
	// Attempts is the number that actually ran, which is fewer than the plan
	// asked for if the run stopped early.
	Attempts int `json:"attempts"`
	// Requested is the number of attempts asked for.
	Requested int `json:"requested,omitempty"`
	// Same and the counts below are per-attempt headline verdicts, not session
	// counts, so they always add up to Attempts.
	Same       int `json:"sameAsRecording"`
	Different  int `json:"different"`
	WireOnly   int `json:"wireOnly"`
	Incomplete int `json:"didNotComplete"`
	// Sessions is the sum of every session verdict across all attempts.
	Sessions Tally `json:"sessions"`
	// Consistent is true when every attempt reached the same headline verdict.
	Consistent bool `json:"consistent"`
	// Verdict is the overall answer: the worst thing seen across the attempts.
	Verdict Verdict `json:"-"`
	// VerdictName is Verdict in machine-readable form.
	VerdictName string `json:"verdict"`
	// Intermittent is true when the device did not behave the same way every
	// time, which is a distinct finding from a clean pass or a clean failure.
	Intermittent bool `json:"intermittent"`
}

// Summarize reduces one tally per attempt to an overall answer. requested is the
// number of attempts the caller asked for, so the summary can say when a run
// stopped early.
func Summarize(per []Tally, requested int) Summary {
	s := Summary{Attempts: len(per), Requested: requested, Consistent: true}
	worst := Incomplete // nothing ran; overridden by the first attempt below
	if len(per) > 0 {
		worst = per[0].Worst()
	}
	for i, t := range per {
		w := t.Worst()
		switch w {
		case Same:
			s.Same++
		case Different:
			s.Different++
		case WireOnly:
			s.WireOnly++
		default:
			s.Incomplete++
		}
		if w.severity() > worst.severity() {
			worst = w
		}
		if i > 0 && w != per[i-1].Worst() {
			s.Consistent = false
		}
		s.Sessions.Same += t.Same
		s.Sessions.Different += t.Different
		s.Sessions.WireOnly += t.WireOnly
		s.Sessions.Incomplete += t.Incomplete
	}
	if len(per) == 0 {
		s.Consistent = false
	}
	s.Verdict = worst
	s.VerdictName = worst.String()
	s.Intermittent = len(per) > 1 && !s.Consistent
	return s
}

// Plain is the closing block for a repeated run: the counts, then a sentence
// saying what they mean. Callers print it only when more than one attempt ran —
// a single attempt already has its own verdict block.
func (s Summary) Plain() string {
	var b strings.Builder
	b.WriteString("\n================================\n")
	if s.Intermittent {
		b.WriteString("OVERALL: INTERMITTENT\n")
	} else {
		b.WriteString("OVERALL: " + s.Verdict.Plain() + "\n")
	}
	line := func(label string, n int) {
		if n > 0 {
			fmt.Fprintf(&b, "  %-22s  %d of %d\n", label, n, s.Attempts)
		}
	}
	line("same as the recording", s.Same)
	line("different", s.Different)
	line("did not complete", s.Incomplete)
	line("sent, not compared", s.WireOnly)
	b.WriteString("\n")
	switch {
	case s.Intermittent:
		b.WriteString("This device did not behave the same way every time, which is itself a\n")
		b.WriteString("finding. Send us the report file.\n")
	// A run that stopped early can end with a single attempt. One sample says
	// what happened once; it cannot support a claim about how often.
	case s.Attempts == 1:
		b.WriteString("Only one attempt ran, so this is what happened that time, not how often\n")
		b.WriteString("it happens. Send us the report file.\n")
	case s.Verdict == Same:
		fmt.Fprintf(&b, "The device behaved as it did in the recording on all %d attempts.\n", s.Attempts)
		b.WriteString("If the recording shows the problem, the problem reproduces on this device.\n")
	case s.Verdict == Different:
		fmt.Fprintf(&b, "The device answered differently on all %d attempts — consistently, not by\n", s.Attempts)
		b.WriteString("chance. Send us the report file.\n")
	case s.Verdict == Incomplete:
		fmt.Fprintf(&b, "The exchange did not complete on any of the %d attempts. Send us the\n", s.Attempts)
		b.WriteString("report file.\n")
	default:
		b.WriteString("Frames were sent at the recorded timing; the replies were not compared.\n")
	}
	if s.Requested > s.Attempts {
		fmt.Fprintf(&b, "\nStopped after %d of %d attempts.\n", s.Attempts, s.Requested)
	}
	b.WriteString("================================\n")
	return b.String()
}
