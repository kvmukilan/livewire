package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/replay"
)

// cmdAnalyze is the compatibility entry point for the merged 'check' command: it
// prints the replayability assessment alone, exactly as it always has, without
// opening a network interface or contacting a device.
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
		fmt.Println("\n'analyze' is now part of 'check', which also summarises what the capture")
		fmt.Println("holds. This spelling keeps working and prints the assessment only.")
		fmt.Println("\nChecks capture completeness and reports replay fidelity risks without using the network.")
		printFlags(fs, "in", "json", "profile")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inPath == "" {
		fs.Usage()
		return fmt.Errorf("-in is required")
	}
	if *udpIdle <= 0 || *udpIdle > time.Hour {
		return fmt.Errorf("-udp-idle must be greater than zero and at most 1h")
	}
	recs, _, err := loadRecords(*inPath)
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
	printCoverage(plan)
	if *jsonPath != "" {
		readiness := assessProtocolReadiness(detectProtocolRoute(recs))
		if err := writeAssessment(*jsonPath, assessment, plan, registry, readiness); err != nil {
			return err
		}
		fmt.Printf("Assessment written to %s\n", *jsonPath)
	}
	return nil
}
