package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/lab"
	"github.com/kvmukilan/livewire/internal/replay"
)

type labReport struct {
	Tool            string            `json:"tool"`
	Version         string            `json:"version"`
	CaptureDigest   string            `json:"captureDigest"`
	ReplayPlan      replay.ReplayPlan `json:"replayPlan"`
	AdapterVersions map[string]string `json:"adapterVersions"`
	Topology        lab.Topology      `json:"topology"`
	Scenario        lab.Scenario      `json:"scenario"`
	Variables       map[string]string `json:"variables"`
	Transformations []string          `json:"transformations"`
	Limitations     []string          `json:"limitations,omitempty"`
	Evidence        string            `json:"evidence"`
	Result          lab.Result        `json:"result"`
}

func cmdLab(args []string) error {
	fs := flag.NewFlagSet("lab", flag.ContinueOnError)
	inPath := fs.String("in", "", "input pcap/pcapng file (required)")
	clientIface := fs.String("client-iface", "", "client-facing interface (overrides topology)")
	serverIface := fs.String("server-iface", "", "server-facing interface (overrides topology)")
	topologyPath := fs.String("topology", "", "topology JSON (required)")
	scenarioPath := fs.String("scenario", "", "optional deterministic fault scenario JSON")
	evidencePath := fs.String("evidence", "", "output dual-interface PCAPNG (default: <capture>.lab.pcapng)")
	reportPath := fs.String("report", "", "output JSON report (default: <capture>.lab.report.json)")
	drain := fs.Duration("drain", 250*time.Millisecond, "time to observe the DUT after the final actor event")
	actorTimeout := fs.Duration("actor-timeout", 2*time.Second, "maximum wait for preceding traffic to cross the DUT")
	udpIdle := fs.Duration("udp-idle", 30*time.Second, "split a UDP tuple into a new session after this idle interval")
	profileName := fs.String("profile", "timing", "requested fidelity label: functional | timing | transport | wire")
	fs.Usage = func() {
		fmt.Println("usage: livewire lab -in trace.pcap -client-iface <iface> -server-iface <iface> -topology topology.json [-scenario faults.json]")
		fmt.Println("\nRuns coordinated client/server actors through a one-host, two-NIC DUT lab and records both sides in one PCAPNG.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inPath == "" || *topologyPath == "" {
		fs.Usage()
		return fmt.Errorf("-in and -topology are required")
	}
	topology, err := lab.LoadTopology(*topologyPath)
	if err != nil {
		return err
	}
	if *clientIface != "" {
		topology.Client.Interface = *clientIface
	}
	if *serverIface != "" {
		topology.Server.Interface = *serverIface
	}
	if err := topology.Validate(); err != nil {
		return err
	}
	scenario, err := lab.LoadScenario(*scenarioPath)
	if err != nil {
		return err
	}
	records, _, err := loadRecords(*inPath)
	if err != nil {
		return err
	}
	if *udpIdle <= 0 {
		return fmt.Errorf("-udp-idle must be positive")
	}
	trace := replay.ExtractTrace(records, replay.ExtractOptions{UDPIdle: *udpIdle})
	if err := topology.ValidateTrace(trace); err != nil {
		return err
	}
	requestedProfile, err := replay.ParseProfile(*profileName)
	if err != nil {
		return err
	}
	plan := lab.BuildReplayPlan(trace, requestedProfile)
	if err := plan.ValidateCoverage(); err != nil {
		return err
	}
	printCoverage(plan)

	base := strings.TrimSuffix(*inPath, filepath.Ext(*inPath))
	if *evidencePath == "" {
		*evidencePath = base + ".lab.pcapng"
	}
	if *reportPath == "" {
		*reportPath = base + ".lab.report.json"
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Printf("\nLab: %s -> DUT -> %s (%d scheduled capture frames, seed %d)\n", topology.Client.Interface, topology.Server.Interface, trace.Packets, scenario.Seed)
	result, runErr := lab.RunContext(ctx, lab.Config{
		Trace: trace, Plan: &plan, Topology: topology, Scenario: scenario, Profile: requestedProfile, Drain: *drain, ActorTimeout: *actorTimeout,
		Progress: func(p lab.Progress) { fmt.Printf("  [%s] %s\n", p.SessionID, p.Message) },
	})
	if err := lab.WriteEvidence(*evidencePath, result, topology); err != nil {
		return fmt.Errorf("write evidence: %w", err)
	}
	digest, _ := sha256File(*inPath)
	report := labReport{
		Tool: "livewire", Version: version, CaptureDigest: digest, ReplayPlan: plan,
		AdapterVersions: adapters.Versions(), Topology: topology, Scenario: scenario,
		Variables: map[string]string{}, Transformations: labTransformations(plan, result), Limitations: result.Limitations,
		Evidence: *evidencePath, Result: result,
	}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*reportPath, append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("\nEvidence: %s\nReport: %s\n", *evidencePath, *reportPath)
	fmt.Printf("Observed: injected=%d crossed=%d lost=%d duplicate=%d reordered=%d resets=%d NAT=%d\n",
		result.Metrics.Injected, result.Metrics.Crossed, result.Metrics.Lost, result.Metrics.Duplicates, result.Metrics.Reordered, result.Metrics.FirewallResets, len(result.NAT))
	if runErr != nil {
		return runErr
	}
	return nil
}

func labTransformations(plan replay.ReplayPlan, result lab.Result) []string {
	var out []string
	add := func(value string) {
		for _, existing := range out {
			if existing == value {
				return
			}
		}
		out = append(out, value)
	}
	for _, entry := range plan.Entries {
		for _, transformation := range entry.Transformations {
			add(transformation)
		}
	}
	for _, transformation := range result.NAT {
		add("NAT/PAT observed: " + transformation.Before + " => " + transformation.After)
	}
	for _, clock := range result.TCPClocks {
		add(fmt.Sprintf("TCP sequence clock observed for %s %s: delta=%d", clock.SessionID, clock.Direction, clock.Delta))
	}
	return out
}
