package replayintent

import (
	"fmt"
	"github.com/kvmukilan/livewire/internal/lab"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
)

// InspectLab advertises the two-sided actor plan, never a one-sided semantic
// adapter which the lab cannot execute.
func InspectLab(records []*pcapio.Record, opts Options) (*Inspection, error) {
	mode, profile, err := Resolve(opts.Mode, opts.Profile)
	if err != nil {
		return nil, err
	}
	if len(opts.Sessions) > 0 {
		return nil, fmt.Errorf("two-sided DUT replay requires the complete capture and topology mappings; session selection is available for one-sided replay")
	}
	trace := replay.ExtractTrace(records, replay.ExtractOptions{UDPIdle: opts.UDPIdle})
	plan := lab.BuildReplayPlan(trace, profile)
	ready := Readiness{Route: "lab", Supported: true, State: "needs-inputs", NeedsInterface: true, Requirements: []string{"client-facing and server-facing interfaces", "validated topology and scenario"}}
	if mode == "application" {
		ready.Supported = false
		ready.Blocker = "two-sided DUT replay provides transport or wire fidelity; explicitly choose transport or wire mode"
	}
	for _, e := range plan.Entries {
		if e.Mode == replay.ModeBlocked {
			ready.Supported = false
			if ready.Blocker == "" {
				ready.Blocker = e.SessionID + ": " + e.Blockers[0]
			}
		}
		if mode == "transport" && e.Mode == replay.ModeWire {
			ready.Supported = false
			ready.Blocker = "capture includes frames requiring wire actors; explicitly choose wire mode or isolate the intended transport exchange"
		}
	}
	if len(plan.Entries) == 0 {
		ready.Supported = false
		ready.Blocker = "capture has no packets"
	}
	if !ready.Supported {
		ready.State = "blocked"
	}
	if err := plan.ValidateCoverage(); err != nil {
		return nil, err
	}
	return &Inspection{Mode: mode, Trace: trace, Plan: plan, Readiness: ready, SelectedPackets: len(records)}, nil
}
