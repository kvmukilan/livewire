package protofuzz

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"
)

// Config describes one run. The defaults the fuzz command fills in are
// deliberately gentle: a device on a plant floor is not a laptop, and a run that
// outpaces it tells you about the pacing rather than the parser.
type Config struct {
	Target     string        // host:port of the endpoint
	Protocol   Protocol      // what to speak; Modbus if nil
	Unit       uint16        // Modbus unit id, or DNP3 outstation address
	Cases      int           // how many mutated frames to send
	Timeout    time.Duration // per-reply read deadline
	Pace       time.Duration // delay between cases
	Seed       int64         // PRNG seed; the same seed replays the same run
	ProbeEvery int           // send a liveness probe every N cases, 0 to disable
	Seeds      []SeedCase    // corpus; the protocol's own seeds if empty
	Mutators   []Mutator     // the protocol's own mutators if empty
	Log        func(string)  // progress sink; nil discards
}

func (c *Config) applyDefaults() {
	if c.Protocol == nil {
		c.Protocol = modbusProtocol{}
	}
	if c.Timeout <= 0 {
		c.Timeout = 2 * time.Second
	}
	if c.Cases <= 0 {
		c.Cases = 500
	}
	if c.ProbeEvery == 0 {
		c.ProbeEvery = 25
	}
	if len(c.Seeds) == 0 {
		c.Seeds = c.Protocol.Seeds(c.Unit)
	}
	if len(c.Mutators) == 0 {
		c.Mutators = c.Protocol.Mutators()
	}
	if c.Log == nil {
		c.Log = func(string) {}
	}
}

// Occurrence is a finding together with the first case that produced it. Repeats
// are counted rather than listed: a mutator that trips the same deviation three
// hundred times has found one bug, and a report that says so is the one somebody
// will actually read.
type Occurrence struct {
	Finding  Finding
	FirstAt  int    // case number
	Mutator  string // mutator that produced the first occurrence
	SeedName string
	What     string // what the mutator changed
	Frame    []byte // the exact bytes sent, so the case can be replayed
	Count    int
}

// Result is the outcome of a run.
type Result struct {
	Cases       int
	Sent        int
	Coverage    *Coverage
	Occurrences []Occurrence
	// Wedged reports that a liveness probe went unanswered: the target stopped
	// serving traffic it had been serving. The run stops at that point rather
	// than continuing against a device that is no longer in a known state.
	Wedged   bool
	WedgedAt int
}

// Run drives the target and returns what it found. It stops early on a wedge or a
// cancelled context, and otherwise after Cases frames. A cancelled run still
// returns its result: the findings so far are the point of having run at all.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	cfg.applyDefaults()
	if cfg.Target == "" {
		return nil, errors.New("protofuzz: no target given")
	}
	if len(cfg.Seeds) == 0 {
		return nil, errors.New("protofuzz: empty seed corpus")
	}
	p := cfg.Protocol

	r := rand.New(rand.NewSource(cfg.Seed))
	cov := NewCoverage()
	sched := NewScheduler(cfg.Seeds, cov)
	res := &Result{Cases: cfg.Cases, Coverage: cov}

	c := &conn{target: cfg.Target, timeout: cfg.Timeout}
	defer c.close()

	// Confirm the target answers a well-formed request before mutating anything.
	// Without this a run against a wrong address or a closed port produces a page
	// of silence that looks like findings.
	if err := probeOnce(c, p, cfg.Unit, 0); err != nil {
		return nil, fmt.Errorf("protofuzz: target did not answer a well-formed %s request: %w", p.Name(), err)
	}
	cfg.Log(fmt.Sprintf("target %s answered a baseline %s request; starting %d cases",
		cfg.Target, p.Name(), cfg.Cases))

	index := make(map[string]int) // finding key -> position in res.Occurrences
	var ident uint16

	for n := 1; n <= cfg.Cases; n++ {
		if err := ctx.Err(); err != nil {
			cfg.Log(fmt.Sprintf("stopping after %d cases: %v", res.Sent, err))
			return res, nil
		}
		si := sched.Pick(r)
		seed := sched.Seed(si)
		mut := cfg.Mutators[r.Intn(len(cfg.Mutators))]

		frame, what := mut.Mutate(r, seed)
		ident++
		frame = p.Stamp(frame, ident)

		outcome, reply, err := c.exchange(p, frame)
		if err != nil {
			return res, fmt.Errorf("protofuzz: case %d: %w", n, err)
		}
		res.Sent++

		state, findings := p.Classify(frame, outcome, reply)
		if cov.Observe(state) {
			cfg.Log(fmt.Sprintf("case %d: new state %s (via %s: %s)", n, state, mut.Name(), what))
		}
		sched.Record(si, state)

		for _, f := range findings {
			key := f.Kind + "|" + mut.Name()
			if at, ok := index[key]; ok {
				res.Occurrences[at].Count++
				continue
			}
			index[key] = len(res.Occurrences)
			res.Occurrences = append(res.Occurrences, Occurrence{
				Finding: f, FirstAt: n, Mutator: mut.Name(),
				SeedName: seed.SeedName(), What: what,
				Frame: append([]byte(nil), frame...), Count: 1,
			})
			cfg.Log(fmt.Sprintf("case %d: [%s] %s -- %s", n, f.Severity, f.Kind, f.Detail))
		}

		if cfg.ProbeEvery > 0 && n%cfg.ProbeEvery == 0 {
			if err := probeOnce(c, p, cfg.Unit, ident+1); err != nil {
				res.Wedged, res.WedgedAt = true, n
				res.Occurrences = append(res.Occurrences, Occurrence{
					Finding: Finding{SevHigh, "target-unresponsive",
						fmt.Sprintf("a well-formed request went unanswered after case %d: %v", n, err)},
					FirstAt: n, Mutator: mut.Name(), SeedName: seed.SeedName(), What: what,
					Frame: append([]byte(nil), frame...), Count: 1,
				})
				cfg.Log(fmt.Sprintf("case %d: [high] target stopped answering a well-formed request; stopping", n))
				return res, nil
			}
		}

		if cfg.Pace > 0 {
			time.Sleep(cfg.Pace)
		}
	}
	return res, nil
}

// probeOnce sends the protocol's well-formed probe and requires a usable answer.
// It is how the engine tells "this device discarded a bad frame" from "this
// device has stopped working", which is the difference between a clean run and a
// finding.
func probeOnce(c *conn, p Protocol, unit, ident uint16) error {
	outcome, reply, err := c.exchange(p, p.Probe(unit, ident))
	if err != nil {
		return err
	}
	return p.ProbeAnswered(outcome, reply)
}

// conn is a lazily dialled connection that reconnects when the peer drops it, so
// one closed connection does not end a run.
type conn struct {
	target  string
	timeout time.Duration
	c       net.Conn
}

func (k *conn) dial() error {
	if k.c != nil {
		return nil
	}
	c, err := net.DialTimeout("tcp", k.target, k.timeout)
	if err != nil {
		return err
	}
	k.c = c
	return nil
}

func (k *conn) close() {
	if k.c != nil {
		k.c.Close()
		k.c = nil
	}
}

// exchange writes one frame and reads whatever comes back. A write failure on a
// connection the peer closed is retried once on a fresh connection; a failure to
// dial at all is returned, because that is the run ending rather than a finding.
func (k *conn) exchange(p Protocol, frame []byte) (ReadOutcome, []byte, error) {
	if err := k.dial(); err != nil {
		return ReadClosed, nil, err
	}
	k.c.SetDeadline(time.Now().Add(k.timeout))
	if _, err := k.c.Write(frame); err != nil {
		k.close()
		if err := k.dial(); err != nil {
			return ReadClosed, nil, err
		}
		k.c.SetDeadline(time.Now().Add(k.timeout))
		if _, err := k.c.Write(frame); err != nil {
			k.close()
			return ReadClosed, nil, nil
		}
	}
	return k.readReply(p)
}

// readReply reads one reply. It takes whatever arrives and then, for a protocol
// whose header declares a length, tops the buffer up to that length so a reply
// split across segments is not mistaken for a short one. A declared length that
// never arrives resolves as a timeout, which is itself the answer to a
// length-field mutation.
func (k *conn) readReply(p Protocol) (ReadOutcome, []byte, error) {
	buf := make([]byte, 0, maxADU)
	tmp := make([]byte, maxADU)

	n, err := k.c.Read(tmp)
	if n > 0 {
		buf = append(buf, tmp[:n]...)
	}
	if n == 0 && err != nil {
		k.classifyReadErr(err)
		if isTimeout(err) {
			return ReadTimeout, nil, nil
		}
		return ReadClosed, nil, nil
	}

	// Top up while the protocol says the frame is incomplete. Each pass must read
	// something or the loop ends, so a peer that declares a length and then stops
	// talking resolves as the short reply it is rather than hanging.
	for need := p.WantMore(buf); need > 0; need = p.WantMore(buf) {
		n, err := k.c.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if n == 0 || err != nil {
			break
		}
	}
	return ReadOK, buf, nil
}

// classifyReadErr drops the connection when the peer is gone, so the next
// exchange dials fresh rather than writing into a dead socket.
func (k *conn) classifyReadErr(err error) {
	if isTimeout(err) {
		return
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		k.close()
		return
	}
	k.close()
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
