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

// cmdAnalyze performs the same replayability preflight used by reproduce,
// without opening a network interface or contacting a device.
func cmdAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	inPath := fs.String("in", "", "input pcap/pcapng file (required)")
	jsonPath := fs.String("json", "", "also write the machine-readable assessment to this file")
	profileName := fs.String("profile", "functional", "requested replay fidelity: functional | timing | transport | wire")
	udpIdle := fs.Duration("udp-idle", 30*time.Second, "split a UDP tuple into a new session after this idle interval")
	var rulePacks fileFlags
	fs.Var(&rulePacks, "rules", "JSON adapter rule pack (repeatable)")
	fs.Usage = func() {
		fmt.Println("usage: livewire analyze -in <capture.pcap> [-json assessment.json]")
		fmt.Println("\nChecks capture completeness and reports replay fidelity risks without using the network.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inPath == "" {
		fs.Usage()
		return fmt.Errorf("-in is required")
	}
	recs, _, err := loadRecords(*inPath)
	if err != nil {
		return err
	}
	r := assessCapture(recs, engine.ExtractFlows(recs))
	printPreflight(r)
	profile, err := replay.ParseProfile(*profileName)
	if err != nil {
		return err
	}
	registry, err := registryWithRulePacks(rulePacks)
	if err != nil {
		return err
	}
	if *udpIdle <= 0 {
		return fmt.Errorf("-udp-idle must be positive")
	}
	_, plan, err := compileCoverageWithOptions(recs, profile, registry, replay.ExtractOptions{UDPIdle: *udpIdle})
	if err != nil {
		return fmt.Errorf("compile coverage: %w", err)
	}
	printCoverage(plan)
	if *jsonPath != "" {
		b, err := json.MarshalIndent(analysisDocument{Preflight: r, Coverage: plan, AdapterVersions: adapters.VersionsForRegistry(registry)}, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*jsonPath, append(b, '\n'), 0o644); err != nil {
			return err
		}
		fmt.Printf("Assessment written to %s\n", *jsonPath)
	}
	return nil
}
