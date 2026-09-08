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
	fmt.Printf("  %-12s %-7s %-12s %-12s %-16s %s\n", "session", "proto", "driver", "fidelity", "adapter", "notes")
	for _, e := range plan.Entries {
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
		fmt.Printf("  %-12s %-7s %-12s %-12s %-16s %s\n", e.SessionID, e.Transport, e.Driver, e.Fidelity, adapter, note)
	}
}
