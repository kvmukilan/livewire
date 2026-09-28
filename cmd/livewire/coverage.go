package main

import (
	"fmt"
	"os"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/replay"
)

type fileFlags []string

func (f *fileFlags) String() string { return fmt.Sprint(*f) }
func (f *fileFlags) Set(v string) error {
	*f = append(*f, v)
	return nil
}

func registryWithRulePacks(paths []string) (*replay.Registry, error) {
	registry := adapters.DefaultRegistry()
	for _, path := range paths {
		// #nosec G703 -- the local operator explicitly names each rule-pack file; arbitrary local input paths are intentional.
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read rule pack %s: %w", path, err)
		}
		a, err := adapters.CompileRulePackJSON(data)
		if err != nil {
			return nil, fmt.Errorf("compile rule pack %s: %w", path, err)
		}
		registry.Register(a)
	}
	return registry, nil
}

type analysisDocument struct {
	Preflight       preflightReport   `json:"preflight"`
	Coverage        replay.ReplayPlan `json:"coverage"`
	AdapterVersions map[string]string `json:"adapterVersions"`
	AutomaticRoute  protocolReadiness `json:"automaticRoute"`
}

func printCoverage(plan replay.ReplayPlan) {
	fmt.Printf("\nProtocol coverage (%s profile):\n", plan.Profile)
	fmt.Printf("  %-12s %-12s %-7s %-12s %-12s %-16s %s\n", "session", "fingerprint", "proto", "driver", "fidelity", "adapter", "notes")
	for _, e := range plan.Entries {
		fingerprint := e.Fingerprint
		if fingerprint == "" {
			fingerprint = "-"
		}
		note := ""
		if e.Excluded {
			note = "EXCLUDED by session selection"
		} else if len(e.Blockers) > 0 {
			note = "BLOCKER: " + e.Blockers[0]
		} else if len(e.Warnings) > 0 {
			note = e.Warnings[0]
		}
		adapter := e.Adapter
		if adapter == "" {
			adapter = "-"
		}
		fmt.Printf("  %-12s %-12s %-7s %-12s %-12s %-16s %s\n", e.SessionID, fingerprint, e.Transport, e.Driver, e.Fidelity, adapter, note)
	}
	fmt.Println("  A fingerprint names an exchange by content; -session accepts it, or a unique prefix, in any copy of this capture.")
}

// timingLine summarizes reply timing for a session verdict, or returns an
// empty string when the driver measured nothing.
func timingLine(t *replay.SessionTiming) string {
	if t == nil || t.Turns == 0 {
		return ""
	}
	line := fmt.Sprintf("TIMING: replies took %.1f ms live vs %.1f ms recorded (slowest %.1f ms over %d turn(s))", t.LiveResponseMS, t.RecordedResponseMS, t.MaxLiveResponseMS, t.Turns)
	if factor := t.SlowdownFactor(); factor >= 2 {
		line += fmt.Sprintf("; the device answered %.0fx slower than in the recording", factor)
	}
	if t.MaxPacingDriftMS > 0 {
		line += fmt.Sprintf("; paced sends left up to %.1f ms late", t.MaxPacingDriftMS)
	}
	return line + "\n"
}
