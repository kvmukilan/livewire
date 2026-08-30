package main

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/livereplay"
	"github.com/kvmukilan/livewire/internal/planexec"
	"github.com/kvmukilan/livewire/internal/replay"
)

type plannedResult = planexec.Result

type executePlanConfig struct {
	Context   context.Context
	Trace     *replay.Trace
	Plan      replay.ReplayPlan
	Registry  *replay.Registry
	Flows     []*engine.Flow
	Iface     string
	TargetIP  netip.Addr
	Variables map[string]string
	Live      liveOpts
	Log       func(int, string)
}

func executeReplayPlan(cfg executePlanConfig) []plannedResult {
	logf := cfg.Log
	if logf == nil {
		logf = func(int, string) {}
	}
	return planexec.Execute(planexec.Config{
		Context: cfg.Context, Trace: cfg.Trace, Plan: cfg.Plan, Registry: cfg.Registry,
		Flows: cfg.Flows, Iface: cfg.Iface, TargetIP: cfg.TargetIP, Variables: cfg.Variables,
		Verify: replay.VerifyMode(cfg.Live.verify.String()),
		TCPConfig: func(flow *engine.Flow, session *replay.Session) livereplay.Config {
			return cfg.Live.config(flow, cfg.TargetIP, session.Server.Port)
		},
		Progress: func(entry replay.PlanEntry, _ string, message string) {
			logf(planLogIndex(entry), message)
		},
	})
}

func planLogIndex(entry replay.PlanEntry) int {
	// Stable enough for human logs while session IDs remain the authoritative
	// machine-readable identity.
	for i := len(entry.SessionID) - 1; i >= 0; i-- {
		if entry.SessionID[i] < '0' || entry.SessionID[i] > '9' {
			var n int
			_, _ = fmt.Sscanf(entry.SessionID[i+1:], "%d", &n)
			return n
		}
	}
	return 0
}
