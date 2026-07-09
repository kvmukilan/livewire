package main

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/livereplay"
)

// liveOpts bundles the options shared by the on-wire replay paths.
type liveOpts struct {
	target, iface string
	seed          int64
	noGuard       bool
	verbose       bool
	useTUI        bool
	verify        engine.VerifyMode
	adaptive      bool
	pace          bool
	rawL4         bool
	sequential    bool   // replay -all flows one at a time instead of concurrently
	report        string // JSON report path ("" = none)
}

func (o liveOpts) config(f *engine.Flow, ip netip.Addr, port uint16) livereplay.Config {
	return livereplay.Config{
		Flow: f, Iface: o.iface, TargetIP: ip, TargetPort: port,
		Seed: o.seed, NoGuard: o.noGuard, Trace: o.verbose,
		Verify: o.verify, Adaptive: o.adaptive, Pace: o.pace, RawL4: o.rawL4,
	}
}

// liveReal runs a real stateful replay of one flow via the shared livereplay
// core, adding flow/target selection and the optional TUI dashboard.
func liveReal(flows []*engine.Flow, flowSel int, o liveOpts) error {
	f, err := selectFlow(flows, flowSel)
	if err != nil {
		return err
	}
	targetIP, targetPort, err := resolveTarget(o.target, f)
	if err != nil {
		return err
	}

	res, err := livereplay.Run(o.config(f, targetIP, targetPort), func(line string) { fmt.Println(line) })
	if err != nil {
		return err
	}

	if o.useTUI {
		out := res.Outcome
		st := tuiFlowState{
			Index: flowSel, Label: fmt.Sprintf("%s -> %s:%d", f.Client, targetIP, targetPort),
			Phase: out.Phase.String(), Sent: out.Sent, Retransmits: out.Retransmits,
			ServerISN: res.LearnedServerISN, Note: out.Reason,
		}
		fmt.Println()
		renderDashboard(o.iface, fmt.Sprintf("%s:%d", targetIP, targetPort), []tuiFlowState{st})
	}
	if o.report != "" {
		rep := newReplayReport(o)
		rep.add(0, f, fmt.Sprintf("%s:%d", targetIP, targetPort), "stateful", res, nil)
		if werr := rep.write(o.report); werr != nil {
			fmt.Printf("report: %v\n", werr)
		} else {
			fmt.Printf("report written to %s\n", o.report)
		}
	}
	if !res.Outcome.Succeeded() {
		return fmt.Errorf("replay ended in phase %s: %s", res.Outcome.Phase, res.Outcome.Reason)
	}
	return nil
}

// liveAll replays every flow as its own stateful connection, one after another.
// Flows without a handshake are skipped. This is whole-pcap replay that still
// maintains seq/ack — each connection individually.
type flowFail struct {
	idx    int
	phase  string
	reason string
}

// oneFlowResult carries a single flow's replay result back from its goroutine.
type oneFlowResult struct {
	idx    int
	flow   *engine.Flow
	target string
	mode   string // stateful | stateless | failed
	res    livereplay.Result
	err    error
}

// liveAll replays every flow in the capture. By default the flows run
// concurrently, each started at its captured time offset when -pace is set (so
// overlapping connections overlap on the wire as they did in the recording) —
// the fidelity that "only happens under load" bugs need. -sequential forces the
// old one-at-a-time behaviour.
func liveAll(flows []*engine.Flow, o liveOpts) error {
	// Resolve targets up front; skip flows whose target can't be resolved.
	type task struct {
		idx    int
		flow   *engine.Flow
		cfg    livereplay.Config
		target string
		offset time.Duration
	}
	var tasks []task
	skipped := 0
	var earliest time.Time
	for _, f := range flows {
		if len(f.Packets) > 0 {
			t := f.Packets[0].Rec.Time
			if earliest.IsZero() || t.Before(earliest) {
				earliest = t
			}
		}
	}
	for i, f := range flows {
		targetIP, targetPort, err := resolveTarget(o.target, f)
		if err != nil {
			fmt.Printf("flow %d: skip (%v)\n", i, err)
			skipped++
			continue
		}
		var off time.Duration
		if len(f.Packets) > 0 {
			off = f.Packets[0].Rec.Time.Sub(earliest)
		}
		tasks = append(tasks, task{
			idx: i, flow: f, cfg: o.config(f, targetIP, targetPort),
			target: fmt.Sprintf("%s:%d", targetIP, targetPort), offset: off,
		})
	}

	var mu sync.Mutex // serialises stdout across concurrent flows
	logf := func(idx int, line string) {
		mu.Lock()
		fmt.Printf("[flow %d] %s\n", idx, line)
		mu.Unlock()
	}
	runOne := func(t task) oneFlowResult {
		logf(t.idx, fmt.Sprintf("%s -> %s", t.flow.Client, t.target))
		res, err := livereplay.Run(t.cfg, func(l string) { logf(t.idx, l) })
		if err != nil {
			logf(t.idx, fmt.Sprintf("stateful replay unavailable (%v); sending frames raw", err))
			if serr := livereplay.SendStateless(t.cfg, func(l string) { logf(t.idx, l) }); serr != nil {
				return oneFlowResult{t.idx, t.flow, t.target, "failed", livereplay.Result{}, serr}
			}
			return oneFlowResult{t.idx, t.flow, t.target, "stateless", livereplay.Result{}, nil}
		}
		return oneFlowResult{t.idx, t.flow, t.target, "stateful", res, nil}
	}

	results := make([]oneFlowResult, len(tasks))
	if o.sequential || len(tasks) <= 1 {
		for i, t := range tasks {
			results[i] = runOne(t)
		}
	} else {
		fmt.Printf("replaying %d flows concurrently%s\n", len(tasks),
			map[bool]string{true: " on the capture's original clock", false: ""}[o.pace])
		var wg sync.WaitGroup
		start := time.Now()
		for i, t := range tasks {
			wg.Add(1)
			go func(i int, t task) {
				defer wg.Done()
				if o.pace && t.offset > 0 { // stagger to the captured inter-flow timing
					if d := start.Add(t.offset).Sub(time.Now()); d > 0 {
						time.Sleep(d)
					}
				}
				results[i] = runOne(t)
			}(i, t)
		}
		wg.Wait()
	}

	// Tally and report in flow order.
	stateful, ok, stateless := 0, 0, 0
	var fails []flowFail
	rep := newReplayReport(o)
	for _, r := range results {
		rep.add(r.idx, r.flow, r.target, r.mode, r.res, r.err)
		switch r.mode {
		case "stateful":
			stateful++
			if r.res.Outcome.Succeeded() {
				ok++
			} else {
				fails = append(fails, flowFail{r.idx, r.res.Outcome.Phase.String(), r.res.Outcome.Reason})
			}
		case "stateless":
			stateless++
		case "failed":
			fails = append(fails, flowFail{r.idx, "error", r.err.Error()})
		}
	}

	if len(fails) > 0 {
		fmt.Println("\nflows that did not complete:")
		for _, ff := range fails {
			fmt.Printf("  flow %d: %s — %s\n", ff.idx, ff.phase, ff.reason)
		}
	}
	fmt.Printf("\nsummary: %d stateful (%d completed), %d stateless, %d skipped\n", stateful, ok, stateless, skipped)
	if o.report != "" {
		if werr := rep.write(o.report); werr != nil {
			fmt.Printf("report: %v\n", werr)
		} else {
			fmt.Printf("report written to %s\n", o.report)
		}
	}
	return nil
}

func selectFlow(flows []*engine.Flow, sel int) (*engine.Flow, error) {
	if sel < 0 {
		if len(flows) != 1 {
			return nil, fmt.Errorf("capture has %d flows; pass -flow <index> to choose one for live replay", len(flows))
		}
		return flows[0], nil
	}
	if sel >= len(flows) {
		return nil, fmt.Errorf("-flow %d out of range (capture has %d flows)", sel, len(flows))
	}
	return flows[sel], nil
}

// resolveTarget parses an ip[:port] override, falling back to the captured server.
func resolveTarget(target string, f *engine.Flow) (netip.Addr, uint16, error) {
	if target == "" {
		return f.Server.Addr, f.Server.Port, nil
	}
	if !strings.Contains(target, ":") || (strings.Count(target, ":") > 1 && !strings.Contains(target, "]")) {
		// bare IP (v4 or v6 without a port)
		ip, err := netip.ParseAddr(target)
		if err != nil {
			return netip.Addr{}, 0, fmt.Errorf("invalid -target %q: %w", target, err)
		}
		return ip, f.Server.Port, nil
	}
	ap, err := netip.ParseAddrPort(target)
	if err != nil {
		host, portStr, ok := strings.Cut(target, ":")
		if !ok {
			return netip.Addr{}, 0, fmt.Errorf("invalid -target %q: %w", target, err)
		}
		ip, e1 := netip.ParseAddr(host)
		p, e2 := strconv.ParseUint(portStr, 10, 16)
		if e1 != nil || e2 != nil {
			return netip.Addr{}, 0, fmt.Errorf("invalid -target %q", target)
		}
		return ip, uint16(p), nil
	}
	return ap.Addr(), ap.Port(), nil
}
