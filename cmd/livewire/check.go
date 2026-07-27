package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/replay"
)

// cmdCheck answers both questions a peer has about a capture before touching the
// network: what is in it, and can it be replayed? Those used to be two commands
// ('info' and 'analyze') with no way to tell which one to run. Neither opens an
// interface or contacts a device.
func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	var inPath string
	fs.StringVar(&inPath, flagIn, "", "the capture file to look at")
	details := fs.Bool(flagDetails, false, "also show the per-session replay plan and checksum validation")
	jsonPath := fs.String("json", "", "also write the machine-readable assessment to this file")
	profileName := fs.String("profile", "functional", "requested replay fidelity: functional | timing | transport | wire")
	udpIdle := fs.Duration("udp-idle", 30*time.Second, "split a UDP tuple into a new session after this idle interval")
	var rulePacks fileFlags
	fs.Var(&rulePacks, "rules", "JSON adapter rule pack (repeatable)")
	allFlags := registerAllFlags(fs)
	fs.Usage = func() {
		fmt.Println("usage: livewire check <capture.pcap>")
		fmt.Println("   or: livewire check -in <capture.pcap> [-details]")
		fmt.Println("\nLook at a capture without touching the network: what traffic it holds, and")
		fmt.Println("whether livewire can replay it faithfully. Run this before 'reproduce' if")
		fmt.Println("you want to know what you were sent.")
		printFlags(fs, flagIn, flagDetails, "json")
	}

	// Accept the capture as a bare argument too: 'check foo.pcap' is what a
	// reader expects, and it is what 'info' always took.
	path, err := parseCaptureArgs(fs, args, &inPath)
	if err != nil {
		return err
	}
	if handleAllFlags(fs, *allFlags, checkAliases) {
		return errAllFlags
	}
	if path == "" {
		fs.Usage()
		return fmt.Errorf("give the capture file to check, e.g. livewire check issue.pcap")
	}
	if *udpIdle <= 0 {
		return fmt.Errorf("-udp-idle must be positive")
	}

	// Pass one: what is in the file.
	in, err := openInput(path)
	if err != nil {
		return err
	}
	stats, err := scanCapture(in, *details)
	in.Close()
	if err != nil {
		return err
	}
	printCaptureStats(stats, *details)

	// Pass two: can it be replayed. Read the records again rather than holding
	// both representations, since assessment needs parsed records and the scan
	// above needs only counts.
	recs, _, err := loadRecords(path)
	if err != nil {
		return err
	}
	assessment := assessCapture(recs, engine.ExtractFlows(recs))
	printPreflight(assessment)

	profile, err := replay.ParseProfile(*profileName)
	if err != nil {
		return err
	}
	registry, err := registryWithRulePacks(rulePacks)
	if err != nil {
		return err
	}
	_, plan, err := compileCoverageWithOptions(recs, profile, registry, replay.ExtractOptions{UDPIdle: *udpIdle})
	if err != nil {
		return fmt.Errorf("compile coverage: %w", err)
	}
	if *details {
		printCoverage(plan)
	} else if n := len(plan.Entries); n > 0 {
		fmt.Printf("\nReplay plan: %d session(s). Run 'livewire check -in %s -details' to see each one.\n", n, path)
	}

	if *jsonPath != "" {
		if err := writeAssessment(*jsonPath, assessment, plan, registry); err != nil {
			return err
		}
		fmt.Printf("Assessment written to %s\n", *jsonPath)
	}
	return nil
}

// checkAliases names the flags on 'check' that exist only for compatibility with
// the commands it replaced.
var checkAliases = aliasSet{}

// writeAssessment persists the machine-readable assessment. Shared by 'check'
// and the 'analyze' compatibility command so both emit the same document.
func writeAssessment(path string, assessment preflightReport, plan replay.ReplayPlan, registry *replay.Registry) error {
	b, err := json.MarshalIndent(analysisDocument{
		Preflight:       assessment,
		Coverage:        plan,
		AdapterVersions: adapters.VersionsForRegistry(registry),
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// parseCaptureArgs accepts the capture either as a bare argument or via -in,
// in any order. The standard flag package stops at the first positional
// argument, so without this normalization 'check foo.pcap -details' would
// silently ignore -details.
func parseCaptureArgs(fs *flag.FlagSet, args []string, inPath *string) (string, error) {
	positional := ""
	if len(args) > 0 && !isFlagArg(args[0]) {
		positional = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	rest := fs.Args()
	if positional == "" && len(rest) > 0 {
		positional = rest[0]
		rest = rest[1:]
	}
	if len(rest) > 0 {
		return "", fmt.Errorf("unexpected extra argument %q; provide exactly one capture", rest[0])
	}
	switch {
	case positional != "" && *inPath != "" && positional != *inPath:
		return "", fmt.Errorf("two captures given (%q and -in %q); provide exactly one", positional, *inPath)
	case positional != "":
		return positional, nil
	default:
		return *inPath, nil
	}
}

// isFlagArg reports whether an argument is a flag rather than a file name. A
// bare "-" is a file name by convention, not a flag.
func isFlagArg(s string) bool { return len(s) > 1 && s[0] == '-' }
