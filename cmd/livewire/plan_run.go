package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/livereplay"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
)

type plannedResult struct {
	Entry     replay.PlanEntry
	Session   *replay.Session
	Transport replay.TransportResult
	TCP       livereplay.Result
	Err       error
}

type executePlanConfig struct {
	Context   context.Context
	Trace     *replay.Trace
	Plan      replay.ReplayPlan
	Records   []*pcapio.Record
	Registry  *replay.Registry
	Flows     []*engine.Flow
	Iface     string
	TargetIP  netip.Addr
	Variables map[string]string
	Live      liveOpts
	Log       func(int, string)
}

func executeReplayPlan(cfg executePlanConfig) []plannedResult {
	if cfg.Context == nil {
		cfg.Context = context.Background()
	}
	if cfg.Registry == nil {
		cfg.Registry = adapters.DefaultRegistry()
	}
	if cfg.Log == nil {
		cfg.Log = func(int, string) {}
	}
	sessions := map[string]*replay.Session{}
	for _, s := range cfg.Trace.Sessions {
		sessions[s.ID] = s
	}
	results := make([]plannedResult, len(cfg.Plan.Entries))
	started := time.Now()
	run := func(i int, entry replay.PlanEntry) {
		s := sessions[entry.SessionID]
		results[i] = runPlanEntry(cfg, entry, s, started)
	}

	concurrent := cfg.Plan.Profile == replay.ProfileTiming || cfg.Plan.Profile == replay.ProfileTransport || cfg.Plan.Profile == replay.ProfileWire
	if !concurrent {
		for i, entry := range cfg.Plan.Entries {
			run(i, entry)
		}
		return results
	}
	var wg sync.WaitGroup
	for i, entry := range cfg.Plan.Entries {
		wg.Add(1)
		go func(i int, entry replay.PlanEntry) {
			defer wg.Done()
			run(i, entry)
		}(i, entry)
	}
	wg.Wait()
	return results
}

func runPlanEntry(cfg executePlanConfig, entry replay.PlanEntry, s *replay.Session, started time.Time) plannedResult {
	r := plannedResult{Entry: entry, Session: s}
	if entry.Mode == replay.ModeBlocked {
		r.Err = errors.New(entry.Blockers[0])
		r.Transport = replay.TransportResult{SessionID: entry.SessionID, Mode: replay.ModeBlocked, Fidelity: replay.FidelityBlocked, Error: r.Err.Error()}
		return r
	}
	if entry.Mode == replay.ModeWire {
		events := cfg.Trace.Raw
		if s != nil {
			events = s.Events
		}
		r.Transport, r.Err = runWireEvents(cfg.Context, cfg.Iface, entry, events, started, cfg.Log)
		return r
	}
	if s == nil {
		r.Err = fmt.Errorf("session %s is missing from trace", entry.SessionID)
		return r
	}
	if s.Server.IP.Is4() != cfg.TargetIP.Is4() {
		r.Err = fmt.Errorf("session uses %s but target %s has a different address family", s.Server.IP, cfg.TargetIP)
		return r
	}
	verify := replay.VerifyMode(cfg.Live.verify.String())
	if entry.Mode == replay.ModeSemantic && s.Transport == replay.TransportTCP {
		a := cfg.Registry.ByName(entry.Adapter)
		r.Transport, r.Err = replay.RunTCPSemanticContext(cfg.Context, replay.TCPSemanticConfig{
			Session: s, TargetIP: cfg.TargetIP, TargetPort: s.Server.Port, Adapter: a,
			Profile: cfg.Plan.Profile, Verify: verify, Variables: cfg.Variables, Start: started,
			Progress: func(p replay.ProgressEvent) { cfg.Log(planLogIndex(entry), p.Message) },
		})
		return r
	}
	if s.Transport == replay.TransportUDP || s.Transport == replay.TransportICMP4 || s.Transport == replay.TransportICMP6 {
		var a replay.Adapter
		if entry.Adapter != "" {
			a = cfg.Registry.ByName(entry.Adapter)
		}
		r.Transport, r.Err = replay.RunTransportContext(cfg.Context, replay.TransportRunConfig{
			Session: s, Iface: cfg.Iface, TargetIP: cfg.TargetIP, TargetPort: s.Server.Port,
			Profile: cfg.Plan.Profile, Verify: verify, Adapter: a, Variables: cfg.Variables, Start: started,
			Progress: func(p replay.ProgressEvent) { cfg.Log(planLogIndex(entry), p.Message) },
		})
		return r
	}
	if s.Transport != replay.TransportTCP {
		r.Err = fmt.Errorf("no runner for %s in %s mode", s.Transport, entry.Mode)
		return r
	}
	f := findEngineFlow(cfg.Flows, s)
	if f == nil {
		r.Err = fmt.Errorf("TCP engine flow for %s was not found", s.ID)
		return r
	}
	conf := cfg.Live.config(f, cfg.TargetIP, s.Server.Port)
	conf.Pace = cfg.Plan.Profile == replay.ProfileTiming || cfg.Plan.Profile == replay.ProfileTransport
	conf.RawL4 = cfg.Plan.Profile == replay.ProfileTransport
	if conf.Pace && !waitPlanOffset(cfg.Context, started, sessionOffset(s)) {
		r.Err = cfg.Context.Err()
		return r
	}
	r.TCP, r.Err = livereplay.RunContext(cfg.Context, conf, func(line string) { cfg.Log(planLogIndex(entry), line) })
	return r
}

func runWireEvents(ctx context.Context, iface string, entry replay.PlanEntry, events []replay.Event, started time.Time, logf func(int, string)) (replay.TransportResult, error) {
	res := replay.TransportResult{SessionID: entry.SessionID, Mode: replay.ModeWire, Fidelity: replay.FidelityWire, Verified: false, Matched: false}
	b, err := backend.OpenSender(iface)
	if err != nil {
		res.Error = err.Error()
		return res, err
	}
	defer b.Close()
	for _, e := range events {
		if !waitPlanOffset(ctx, started, e.At) {
			res.Error = "cancelled"
			return res, ctx.Err()
		}
		if err := b.Send(e.Record.Data); err != nil {
			res.Error = err.Error()
			return res, err
		}
		frame := append([]byte(nil), e.Record.Data...)
		res.Evidence = append(res.Evidence, pcapio.Record{Time: b.Now(), CapLen: len(frame), OrigLen: len(frame), Data: frame, LinkType: b.LinkType()})
		res.Sent++
	}
	res.Completed = true
	logf(planLogIndex(entry), fmt.Sprintf("wire replay sent %d frame(s); no live adaptation claimed", res.Sent))
	return res, nil
}

func findEngineFlow(flows []*engine.Flow, s *replay.Session) *engine.Flow {
	for _, f := range flows {
		if f.Client.Addr == s.Client.IP && f.Client.Port == s.Client.Port && f.Server.Addr == s.Server.IP && f.Server.Port == s.Server.Port {
			return f
		}
	}
	return nil
}

func sessionOffset(s *replay.Session) time.Duration {
	if len(s.Events) == 0 {
		return 0
	}
	return s.Events[0].At
}

func waitPlanOffset(ctx context.Context, started time.Time, offset time.Duration) bool {
	d := time.Until(started.Add(offset))
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
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
