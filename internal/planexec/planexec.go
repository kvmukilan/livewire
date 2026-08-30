// Package planexec executes a validated replay plan through the same protocol
// dispatch for every front end. The CLI and browser dashboard provide only
// configuration and progress presentation, so protocol support cannot drift.
package planexec

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/ftpreplay"
	"github.com/kvmukilan/livewire/internal/livereplay"
	"github.com/kvmukilan/livewire/internal/orchestration"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
)

type Result struct {
	Entry     replay.PlanEntry
	Session   *replay.Session
	Transport replay.TransportResult
	TCP       livereplay.Result
	FTP       ftpreplay.Result
	Err       error
}

type Config struct {
	Context   context.Context
	Trace     *replay.Trace
	Plan      replay.ReplayPlan
	Registry  *replay.Registry
	Flows     []*engine.Flow
	Iface     string
	TargetIP  netip.Addr
	Variables map[string]string
	Verify    replay.VerifyMode
	TCPConfig func(*engine.Flow, *replay.Session) livereplay.Config
	Progress  func(replay.PlanEntry, string, string)
}

func Execute(cfg Config) []Result {
	cfg = normalize(cfg)
	if cfg.Trace == nil {
		return configurationFailures(cfg.Plan, "replay trace is missing")
	}
	return orchestration.ExecutePlan(cfg.Context, cfg.Trace, cfg.Plan, func(_ context.Context, _ int, entry replay.PlanEntry, session *replay.Session, started time.Time) Result {
		return runEntry(cfg, entry, session, started)
	})
}

// ExecuteEntry is for a front end that already owns the plan scheduler and its
// shared start instant. It uses the same dispatch as Execute.
func ExecuteEntry(cfg Config, entry replay.PlanEntry, session *replay.Session, started time.Time) Result {
	if cfg.Trace == nil {
		return Result{Entry: entry, Session: session, Err: errors.New("replay trace is missing")}
	}
	return runEntry(normalize(cfg), entry, session, started)
}

func configurationFailures(plan replay.ReplayPlan, reason string) []Result {
	results := make([]Result, len(plan.Entries))
	for i, entry := range plan.Entries {
		results[i] = Result{Entry: entry, Err: errors.New(reason)}
	}
	return results
}

func normalize(cfg Config) Config {
	if cfg.Context == nil {
		cfg.Context = context.Background()
	}
	if cfg.Registry == nil {
		cfg.Registry = adapters.DefaultRegistry()
	}
	if cfg.Progress == nil {
		cfg.Progress = func(replay.PlanEntry, string, string) {}
	}
	return cfg
}

func runEntry(cfg Config, entry replay.PlanEntry, session *replay.Session, started time.Time) Result {
	result := Result{Entry: entry, Session: session}
	if entry.Mode == replay.ModeBlocked {
		reason := "session has no safe replay driver"
		if len(entry.Blockers) > 0 {
			reason = entry.Blockers[0]
		}
		result.Err = errors.New(reason)
		result.Transport = replay.TransportResult{SessionID: entry.SessionID, Mode: replay.ModeBlocked, Fidelity: replay.FidelityBlocked, Error: result.Err.Error()}
		cfg.Progress(entry, "blocked", reason)
		return result
	}
	if entry.Mode == replay.ModeWire {
		events := cfg.Trace.Raw
		if session != nil {
			events = session.Events
		}
		result.Transport, result.Err = runWireEvents(cfg, entry, events, started)
		return result
	}
	if session == nil {
		result.Err = fmt.Errorf("session %s is missing from trace", entry.SessionID)
		return result
	}
	if !cfg.TargetIP.IsValid() {
		result.Err = errors.New("live target IP is missing or invalid")
		return result
	}
	if session.Server.IP.Is4() != cfg.TargetIP.Is4() {
		result.Err = fmt.Errorf("session uses %s but target %s has a different address family", session.Server.IP, cfg.TargetIP)
		return result
	}
	if entry.Mode == replay.ModeCoordinated && entry.Adapter == "ftp" {
		result.FTP, result.Err = runFTP(cfg, entry, session)
		return result
	}
	if entry.Mode == replay.ModeSemantic && session.Transport == replay.TransportTCP {
		adapter := cfg.Registry.ByName(entry.Adapter)
		if adapter == nil {
			result.Err = fmt.Errorf("adapter %q is not registered", entry.Adapter)
			return result
		}
		result.Transport, result.Err = replay.RunTCPSemanticContext(cfg.Context, replay.TCPSemanticConfig{
			Session: session, TargetIP: cfg.TargetIP, TargetPort: session.Server.Port, Adapter: adapter,
			Profile: cfg.Plan.Profile, Verify: cfg.Verify, Variables: cfg.Variables, Start: started,
			Progress: func(p replay.ProgressEvent) { cfg.Progress(entry, p.Stage, p.Message) },
		})
		return result
	}
	if session.Transport == replay.TransportUDP || session.Transport == replay.TransportICMP4 || session.Transport == replay.TransportICMP6 {
		var adapter replay.Adapter
		if entry.Adapter != "" {
			adapter = cfg.Registry.ByName(entry.Adapter)
			if adapter == nil {
				result.Err = fmt.Errorf("adapter %q is not registered", entry.Adapter)
				return result
			}
		}
		result.Transport, result.Err = replay.RunTransportContext(cfg.Context, replay.TransportRunConfig{
			Session: session, Iface: cfg.Iface, TargetIP: cfg.TargetIP, TargetPort: session.Server.Port,
			Profile: cfg.Plan.Profile, Verify: cfg.Verify, Adapter: adapter, Variables: cfg.Variables, Start: started,
			Progress: func(p replay.ProgressEvent) { cfg.Progress(entry, p.Stage, p.Message) },
		})
		return result
	}
	if session.Transport != replay.TransportTCP {
		result.Err = fmt.Errorf("no runner for %s in %s mode", session.Transport, entry.Mode)
		return result
	}
	flow := findFlow(cfg.Flows, session)
	if flow == nil {
		result.Err = fmt.Errorf("TCP engine flow for %s was not found", session.ID)
		return result
	}
	if cfg.TCPConfig == nil {
		result.Err = fmt.Errorf("TCP replay configuration is missing for %s", session.ID)
		return result
	}
	config := cfg.TCPConfig(flow, session)
	config.Pace = cfg.Plan.Profile == replay.ProfileTiming || cfg.Plan.Profile == replay.ProfileTransport
	config.RawL4 = cfg.Plan.Profile == replay.ProfileTransport
	if config.Pace && !waitOffset(cfg.Context, started, sessionOffset(session)) {
		result.Err = cfg.Context.Err()
		return result
	}
	result.TCP, result.Err = livereplay.RunContext(cfg.Context, config, func(line string) { cfg.Progress(entry, "tcp", line) })
	return result
}

func runFTP(cfg Config, entry replay.PlanEntry, control *replay.Session) (ftpreplay.Result, error) {
	script, err := ftpreplay.BuildScript(control, nil)
	if err != nil {
		return ftpreplay.Result{}, err
	}
	byID := make(map[string]*replay.Session, len(cfg.Trace.Sessions))
	for _, session := range cfg.Trace.Sessions {
		byID[session.ID] = session
	}
	data := make([]*replay.Session, 0, len(entry.RelatedSessionIDs))
	for _, id := range entry.RelatedSessionIDs {
		related := byID[id]
		if related == nil {
			return ftpreplay.Result{}, fmt.Errorf("related FTP data session %s is missing from trace", id)
		}
		data = append(data, related)
	}
	address := netip.AddrPortFrom(cfg.TargetIP, control.Server.Port).String()
	return ftpreplay.RunContext(cfg.Context, ftpreplay.Config{
		Control: control, Data: data, Address: address, Script: script,
		Variables: cfg.Variables, Timeout: 30 * time.Second, Verify: cfg.Verify,
		Progress: func(line string) { cfg.Progress(entry, "ftp", line) },
	})
}

func runWireEvents(cfg Config, entry replay.PlanEntry, events []replay.Event, started time.Time) (result replay.TransportResult, retErr error) {
	result = replay.TransportResult{SessionID: entry.SessionID, Mode: replay.ModeWire, Fidelity: replay.FidelityWire}
	sender, err := backend.OpenSender(cfg.Iface)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	defer func() {
		if err := sender.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close wire backend: %w", err))
			result.Completed = false
			result.Error = retErr.Error()
		}
	}()
	for _, event := range events {
		if event.Record == nil {
			result.Error = "wire event has no capture record"
			return result, errors.New(result.Error)
		}
		if !waitOffset(cfg.Context, started, event.At) {
			result.Error = "cancelled"
			return result, cfg.Context.Err()
		}
		if err := sender.Send(event.Record.Data); err != nil {
			result.Error = err.Error()
			return result, err
		}
		frame := append([]byte(nil), event.Record.Data...)
		result.Evidence = append(result.Evidence, pcapio.Record{Time: sender.Now(), CapLen: len(frame), OrigLen: len(frame), Data: frame, LinkType: sender.LinkType()})
		result.Sent++
	}
	result.Completed = true
	cfg.Progress(entry, "wire", fmt.Sprintf("wire replay sent %d frame(s); no live adaptation claimed", result.Sent))
	return result, nil
}

func findFlow(flows []*engine.Flow, session *replay.Session) *engine.Flow {
	for _, flow := range flows {
		if flow.Client.Addr == session.Client.IP && flow.Client.Port == session.Client.Port && flow.Server.Addr == session.Server.IP && flow.Server.Port == session.Server.Port {
			return flow
		}
	}
	return nil
}

func sessionOffset(session *replay.Session) time.Duration {
	if len(session.Events) == 0 {
		return 0
	}
	return session.Events[0].At
}

func waitOffset(ctx context.Context, started time.Time, offset time.Duration) bool {
	duration := time.Until(started.Add(offset))
	if duration <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
