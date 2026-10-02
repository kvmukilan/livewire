package protofuzz

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"

	"github.com/kvmukilan/livewire/internal/dissect"
)

// Config describes one run. The defaults the fuzz command fills in are
// deliberately gentle: a device on a plant floor is not a laptop, and a run that
// outpaces it tells you about the pacing rather than the parser.
type Config struct {
	Target     string        // host:port of the Modbus endpoint
	UnitID     uint8         // unit id the seeds address
	Cases      int           // how many mutated frames to send
	Timeout    time.Duration // per-reply read deadline
	Pace       time.Duration // delay between cases
	Seed       int64         // PRNG seed; the same seed replays the same run
	ProbeEvery int           // send a liveness probe every N cases, 0 to disable
	Seeds      []Seed        // corpus; BuiltinSeeds if empty
	Mutators   []Mutator     // DefaultMutators if empty
	Log        func(string)  // progress sink; nil discards
}

func (c *Config) applyDefaults() {
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
		c.Seeds = BuiltinSeeds(c.UnitID)
	}
	if len(c.Mutators) == 0 {
		c.Mutators = DefaultMutators()
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

	r := rand.New(rand.NewSource(cfg.Seed))
	cov := NewCoverage()
	sched := NewScheduler(cfg.Seeds, cov)
	res := &Result{Cases: cfg.Cases, Coverage: cov}

	c := &conn{target: cfg.Target, timeout: cfg.Timeout}
	defer c.close()

	// Confirm the target answers a well-formed request before mutating anything.
	// Without this a run against a wrong address or a closed port produces a page
	// of silence that looks like findings.
	if err := probe(c, cfg.UnitID, 0); err != nil {
		return nil, fmt.Errorf("protofuzz: target did not answer a well-formed request: %w", err)
	}
	cfg.Log(fmt.Sprintf("target %s answered a baseline read; starting %d cases", cfg.Target, cfg.Cases))

	index := make(map[string]int) // finding key -> position in res.Occurrences
	var txid uint16

	for n := 1; n <= cfg.Cases; n++ {
		if err := ctx.Err(); err != nil {
			cfg.Log(fmt.Sprintf("stopping after %d cases: %v", res.Sent, err))
			return res, nil
		}
		si := sched.Pick(r)
		seed := sched.Seed(si)
		mut := cfg.Mutators[r.Intn(len(cfg.Mutators))]

		frame, what := mut.Mutate(r, seed)
		txid++
		// Stamp a fresh transaction id unless the mutation truncated the frame
		// below the header, in which case there is nothing to stamp.
		if len(frame) >= 2 {
			frame[0] = byte(txid >> 8)
			frame[1] = byte(txid)
		}

		// The request as the device should read it, for echo and function checks.
		req := dissect.MBAP{TransactionID: txid, UnitID: seed.ADU.UnitID, Function: seed.ADU.Function}
		if len(frame) >= 8 {
			req.UnitID = frame[6]
			req.Function = frame[7]
		}

		outcome, reply, err := c.exchange(frame)
		if err != nil {
			return res, fmt.Errorf("protofuzz: case %d: %w", n, err)
		}
		res.Sent++

		state, findings := Classify(req, frame, outcome, reply)
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
				SeedName: seed.Name, What: what,
				Frame: append([]byte(nil), frame...), Count: 1,
			})
			cfg.Log(fmt.Sprintf("case %d: [%s] %s -- %s", n, f.Severity, f.Kind, f.Detail))
		}

		if cfg.ProbeEvery > 0 && n%cfg.ProbeEvery == 0 {
			if err := probe(c, cfg.UnitID, txid+1); err != nil {
				res.Wedged, res.WedgedAt = true, n
				res.Occurrences = append(res.Occurrences, Occurrence{
					Finding: Finding{SevHigh, "target-unresponsive",
						fmt.Sprintf("a well-formed request went unanswered after case %d: %v", n, err)},
					FirstAt: n, Mutator: mut.Name(), SeedName: seed.Name, What: what,
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

// probe sends a minimal well-formed read and requires a parseable reply. It is
// how the engine tells "this device discarded a bad frame" from "this device has
// stopped working", which is the difference between a clean run and a finding.
func probe(c *conn, unitID uint8, txid uint16) error {
	m := dissect.MBAP{TransactionID: txid, UnitID: unitID, Function: 0x03}
	m.Data = append(be16(0), be16(1)...)
	outcome, reply, err := c.exchange(encodeConsistent(m))
	if err != nil {
		return err
	}
	switch outcome {
	case ReadTimeout:
		return errors.New("no reply within the read deadline")
	case ReadClosed:
		return errors.New("peer closed the connection")
	}
	// An exception is a perfectly good answer here: the point is that something
	// on the other end is still parsing Modbus and choosing a reply.
	if _, _, err := dissect.ParseMBAP(reply); err != nil {
		return fmt.Errorf("reply was not a Modbus ADU: %w", err)
	}
	return nil
}

// conn is a lazily dialled Modbus/TCP connection that reconnects when the peer
// drops it, so one closed connection does not end a run.
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
func (k *conn) exchange(frame []byte) (ReadOutcome, []byte, error) {
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
	return k.readReply()
}

// readReply reads one reply. It first takes whatever arrives, then tops the
// buffer up to the length the MBAP header declares, so a reply split across
// segments is not mistaken for a short one. A declared length that never arrives
// resolves as a timeout, which is itself the answer to a length-field mutation.
func (k *conn) readReply() (ReadOutcome, []byte, error) {
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

	for len(buf) >= mbapHeaderLen {
		want := 6 + int(uint16(buf[4])<<8|uint16(buf[5]))
		if want <= len(buf) || want > maxADU*2 {
			break
		}
		n, err := k.c.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
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
