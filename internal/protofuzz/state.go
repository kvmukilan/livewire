package protofuzz

import (
	"fmt"
	"math/rand"
	"sort"

	"github.com/kvmukilan/livewire/internal/dissect"
)

// StateKind is the coarse shape of what came back, before the function and
// exception codes narrow it further.
type StateKind int

const (
	// StateNormal is a parseable reply that is not an exception.
	StateNormal StateKind = iota
	// StateException is a Modbus exception response: function code with the high
	// bit set, carrying an exception code.
	StateException
	// StateSilent means nothing arrived before the read deadline. On its own this
	// is not a fault -- see Classify.
	StateSilent
	// StateClosed means the peer tore the connection down instead of answering.
	StateClosed
	// StateMalformed means bytes arrived that are not a Modbus/TCP ADU.
	StateMalformed
)

func (k StateKind) String() string {
	switch k {
	case StateNormal:
		return "normal"
	case StateException:
		return "exception"
	case StateSilent:
		return "silent"
	case StateClosed:
		return "closed"
	case StateMalformed:
		return "malformed"
	}
	return "unknown"
}

// State is how the target answered one request. It stands in for the target's
// internal state the way AFLNet uses response codes: a black-box device will not
// hand over code coverage, so the answer it chooses is the only observable proxy
// for the path it took.
type State struct {
	Kind      StateKind
	Function  uint8 // function code of the reply, masked of the exception bit
	Exception uint8 // exception code, when Kind is StateException
}

// Key identifies a state for counting. Normal replies are keyed by function so
// that reaching a new function's handler counts as new state; exceptions are
// keyed by their code, because which refusal a device picks says more about the
// path it took than which function was refused.
func (s State) Key() string {
	switch s.Kind {
	case StateNormal:
		return fmt.Sprintf("normal/0x%02x", s.Function)
	case StateException:
		return fmt.Sprintf("exception/0x%02x", s.Exception)
	default:
		return s.Kind.String()
	}
}

// String renders a state for a human reading the run log.
func (s State) String() string {
	switch s.Kind {
	case StateNormal:
		return fmt.Sprintf("normal %s", dissect.FunctionName(s.Function))
	case StateException:
		return fmt.Sprintf("exception %s", dissect.ExceptionName(s.Exception))
	default:
		return s.Kind.String()
	}
}

// Coverage counts how often each observable state has been reached. It is the
// run's only feedback signal, so it doubles as the headline progress number: a
// run that stops finding new states has stopped learning about the target.
type Coverage struct {
	counts map[string]int
	first  []string // keys in the order first seen, for a stable report
}

// NewCoverage returns an empty coverage map.
func NewCoverage() *Coverage {
	return &Coverage{counts: make(map[string]int)}
}

// Observe records one state and reports whether this run had not seen it before.
func (c *Coverage) Observe(s State) bool {
	k := s.Key()
	_, seen := c.counts[k]
	c.counts[k]++
	if !seen {
		c.first = append(c.first, k)
	}
	return !seen
}

// Count returns how many times a state has been reached.
func (c *Coverage) Count(s State) int { return c.counts[s.Key()] }

// Distinct returns the number of different states reached.
func (c *Coverage) Distinct() int { return len(c.counts) }

// StateCount is one row of a coverage summary.
type StateCount struct {
	Key   string
	Count int
}

// Summary returns the states reached, most frequent first, for the end-of-run
// report. Ties keep first-seen order so repeated runs read the same way.
func (c *Coverage) Summary() []StateCount {
	rank := make(map[string]int, len(c.first))
	for i, k := range c.first {
		rank[k] = i
	}
	out := make([]StateCount, 0, len(c.counts))
	for k, n := range c.counts {
		out = append(out, StateCount{Key: k, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return rank[out[i].Key] < rank[out[j].Key]
	})
	return out
}

// Scheduler picks which seed to mutate next. A seed is worth more when the state
// it last reached is one the run has rarely seen: following AFLNet, the rare
// answer is the one whose code path is least exercised, so the seed that elicited
// it is the one most likely to reach somewhere new on the next mutation.
type Scheduler struct {
	seeds []Seed
	last  []State // last state each seed reached; zero value is StateNormal/0
	known []bool  // whether this seed has been tried at all yet
	cov   *Coverage
}

// NewScheduler builds a scheduler over a seed corpus.
func NewScheduler(seeds []Seed, cov *Coverage) *Scheduler {
	return &Scheduler{
		seeds: seeds,
		last:  make([]State, len(seeds)),
		known: make([]bool, len(seeds)),
		cov:   cov,
	}
}

// Seed returns the seed at an index.
func (s *Scheduler) Seed(i int) Seed { return s.seeds[i] }

// weight scores a seed for selection. An untried seed outranks everything, so a
// run always covers the whole corpus before it starts favouring anything; after
// that the weight is the reciprocal of how often the seed's last state has been
// seen.
func (s *Scheduler) weight(i int) float64 {
	if !s.known[i] {
		return 1000
	}
	return 1 / float64(1+s.cov.Count(s.last[i]))
}

// Pick chooses a seed index by weighted draw.
func (s *Scheduler) Pick(r *rand.Rand) int {
	total := 0.0
	for i := range s.seeds {
		total += s.weight(i)
	}
	// A zero total would mean an empty corpus, which the caller rejects up front;
	// guard anyway so a future change cannot divide by zero here.
	if total <= 0 {
		return r.Intn(len(s.seeds))
	}
	draw := r.Float64() * total
	for i := range s.seeds {
		draw -= s.weight(i)
		if draw <= 0 {
			return i
		}
	}
	return len(s.seeds) - 1
}

// Record notes the state a seed's latest mutation reached.
func (s *Scheduler) Record(i int, st State) {
	s.last[i] = st
	s.known[i] = true
}
