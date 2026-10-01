package main

import (
	"context"
	"flag"
	"fmt"
	"sort"
	"time"

	"github.com/kvmukilan/livewire/internal/protofuzz"
)

// cmdFuzz drives a Modbus/TCP endpoint with mutated application frames and
// reports how it answered: which states it reached, and where it departed from
// the spec. It is the robustness-testing counterpart to replay -- same protocol
// knowledge, pointed at framing and bounds handling instead of reproduction.
//
// The target must be on loopback unless -allow-remote is given, mirroring how
// 'web' refuses a non-loopback listener. A Modbus device is frequently the thing
// holding a process up, and the cost of pointing this at the wrong address is not
// a failed test.
func cmdFuzz(args []string) error {
	fs := flag.NewFlagSet("fuzz", flag.ContinueOnError)
	target := fs.String("target", "", "host:port of the Modbus/TCP endpoint to test")
	unit := fs.Int("unit", 1, "Modbus unit id the seed requests address")
	cases := fs.Int("cases", 500, "number of mutated frames to send")
	timeout := fs.Duration("timeout", 2*time.Second, "per-reply read deadline")
	pace := fs.Duration("pace", 0, "delay between cases; raise it for a device that cannot keep up")
	seed := fs.Int64("seed", 0, "PRNG seed; the same seed replays the same run")
	probeEvery := fs.Int("probe-every", 25, "send a well-formed liveness probe every N cases (0 disables)")
	allowRemote := fs.Bool("allow-remote", false, "permit a non-loopback target; only with authorisation to test the device")
	quiet := fs.Bool("quiet", false, "report only the summary, not each new state as it is reached")
	failOnFindings := fs.Bool("fail-on-findings", false, "exit non-zero if any finding is reported")
	allFlags := registerAllFlags(fs)
	fs.Usage = func() {
		fmt.Println("usage: livewire fuzz -target host:port [-cases 500] [-unit 1]")
		fmt.Println("\nSend mutated Modbus/TCP frames to an endpoint and report how it answers.")
		fmt.Println("Seeds are well-formed requests; mutators target the length field, quantities,")
		fmt.Println("addresses, byte counts, function codes and frame size. A liveness probe runs")
		fmt.Println("every -probe-every cases and the run stops if the device stops answering it.")
		printFlags(fs, "target", "unit", "cases", "timeout", "pace", "seed", "probe-every",
			"allow-remote", "quiet", "fail-on-findings")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if handleAllFlags(fs, *allFlags, nil) {
		return errAllFlags
	}

	if *target == "" {
		return fmt.Errorf("-target is required (host:port of the Modbus endpoint)")
	}
	if *unit < 0 || *unit > 255 {
		return fmt.Errorf("-unit must be between 0 and 255")
	}
	if *cases < 1 {
		return fmt.Errorf("-cases must be at least 1")
	}
	if !*allowRemote && !isLoopbackListenAddr(*target) {
		return fmt.Errorf("refusing non-loopback target %q without -allow-remote: "+
			"fuzzing a device you are not authorised to test can take it off line", *target)
	}

	ctx, stop := commandSignalContext(context.Background())
	defer stop()

	cfg := protofuzz.Config{
		Target:     *target,
		UnitID:     uint8(*unit),
		Cases:      *cases,
		Timeout:    *timeout,
		Pace:       *pace,
		Seed:       *seed,
		ProbeEvery: *probeEvery,
	}
	if !*quiet {
		cfg.Log = func(line string) { fmt.Println(line) }
	}

	res, err := protofuzz.Run(ctx, cfg)
	if err != nil {
		return err
	}
	printFuzzReport(res, *target, *seed)
	if *failOnFindings && len(res.Occurrences) > 0 {
		return fmt.Errorf("%d finding(s) reported", len(res.Occurrences))
	}
	return nil
}

// printFuzzReport renders the run so the interesting part is readable without a
// hex editor: what the device answered, then every deviation with the exact bytes
// that produced it so the case can be sent again by hand.
func printFuzzReport(res *protofuzz.Result, target string, seed int64) {
	fmt.Printf("\nlivewire fuzz: %d case(s) sent to %s (seed %d)\n", res.Sent, target, seed)

	summary := res.Coverage.Summary()
	fmt.Printf("\nstates reached (%d):\n", len(summary))
	for _, s := range summary {
		fmt.Printf("  %-24s %6d\n", s.Key, s.Count)
	}

	if len(res.Occurrences) == 0 {
		fmt.Println("\nno findings: every reply was well formed and no frame was served that should have been refused")
		return
	}

	// Most serious first, then the most frequently hit, so the top of the list is
	// where to start reading.
	occ := make([]protofuzz.Occurrence, len(res.Occurrences))
	copy(occ, res.Occurrences)
	sort.SliceStable(occ, func(i, j int) bool {
		if occ[i].Finding.Severity != occ[j].Finding.Severity {
			return occ[i].Finding.Severity > occ[j].Finding.Severity
		}
		return occ[i].Count > occ[j].Count
	})

	fmt.Printf("\nfindings (%d distinct):\n", len(occ))
	for _, o := range occ {
		fmt.Printf("\n  [%s] %s", o.Finding.Severity, o.Finding.Kind)
		if o.Count > 1 {
			fmt.Printf("  (hit %d times)", o.Count)
		}
		fmt.Printf("\n      %s\n", o.Finding.Detail)
		fmt.Printf("      first at case %d, mutator %s on seed %s\n", o.FirstAt, o.Mutator, o.SeedName)
		fmt.Printf("      changed: %s\n", o.What)
		fmt.Printf("      frame:  % x\n", o.Frame)
	}

	if res.Wedged {
		fmt.Printf("\nthe target stopped answering a well-formed request at case %d; the run stopped there.\n", res.WedgedAt)
		fmt.Println("re-run with the same -seed to reproduce, and -cases just past that point to narrow it.")
	}
}
