package replayintent

import (
	"fmt"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
)

type Options struct {
	KeyLog   []byte        `json:"-"`
	Mode     string        `json:"mode,omitempty"`
	Profile  string        `json:"profile,omitempty"`
	Sessions []string      `json:"sessions,omitempty"`
	UDPIdle  time.Duration `json:"-"`
}
type Readiness struct {
	Route          Kind     `json:"route"`
	Supported      bool     `json:"supported"`
	State          string   `json:"state"`
	Requirements   []string `json:"requirements,omitempty"`
	Blocker        string   `json:"blocker,omitempty"`
	NeedsInterface bool     `json:"needsInterface"`
}
type Inspection struct {
	Mode            string            `json:"mode"`
	Trace           *replay.Trace     `json:"-"`
	Plan            replay.ReplayPlan `json:"plan"`
	Readiness       Readiness         `json:"readiness"`
	Route           Route             `json:"-"`
	SelectedPackets int               `json:"selectedPackets"`
	ExcludedPackets int               `json:"excludedPackets"`
}

func Resolve(mode, profile string) (string, replay.Profile, error) {
	p, e := replay.ParseProfile(profile)
	if e != nil {
		return "", "", e
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "auto"
	}
	switch mode {
	case "auto":
	case "application":
		if p != replay.ProfileFunctional && p != replay.ProfileTiming {
			return "", "", fmt.Errorf("application mode requires functional or timing profile")
		}
	case "transport":
		if p == replay.ProfileWire {
			return "", "", fmt.Errorf("transport mode conflicts with wire profile")
		}
		p = replay.ProfileTransport
	case "wire":
		p = replay.ProfileWire
	default:
		return "", "", fmt.Errorf("unknown replay mode %q; use application, transport, wire, or auto", mode)
	}
	if p == replay.ProfileWire {
		mode = "wire"
	}
	return mode, p, nil
}

// Select preserves original packet indexes and session identities. FTP groups
// are indivisible: selecting any member selects its control and data sessions.
func Select(t *replay.Trace, ids []string, registry *replay.Registry) (*replay.Trace, error) {
	if len(ids) == 0 {
		return t, nil
	}
	if registry == nil {
		registry = adapters.DefaultRegistry()
	}
	known := map[string]bool{}
	selected := map[string]bool{}
	byFingerprint := map[string]string{}
	for _, s := range t.Sessions {
		known[s.ID] = true
		byFingerprint[s.Fingerprint()] = s.ID
	}
	if len(t.Raw) > 0 {
		known["raw-0"] = true
	}
	for _, id := range ids {
		if !known[id] {
			resolved, err := resolveFingerprint(id, byFingerprint)
			if err != nil {
				return nil, err
			}
			id = resolved
		}
		selected[id] = true
	}
	for _, g := range registry.CoordinatedGroups(t) {
		members := append([]string{g.Group.ControlSessionID}, g.Group.RelatedSessionIDs...)
		include := false
		for _, id := range members {
			include = include || selected[id]
		}
		if include {
			for _, id := range members {
				selected[id] = true
			}
		}
	}
	out := &replay.Trace{Started: t.Started, Packets: t.Packets}
	exclude := func(id, fingerprint string, transport replay.Transport, events []replay.Event) {
		e := replay.PlanEntry{SessionID: id, Fingerprint: fingerprint, Transport: transport, Excluded: true, Driver: "none", Mode: replay.ModeBlocked, Fidelity: replay.FidelityBlocked, Warnings: []string{"excluded by explicit session selection; equivalence covers selected sessions only"}}
		for _, event := range events {
			e.PacketIndexes = append(e.PacketIndexes, event.PacketIndex)
		}
		out.Excluded = append(out.Excluded, e)
	}
	for _, s := range t.Sessions {
		if selected[s.ID] {
			out.Sessions = append(out.Sessions, s)
		} else {
			exclude(s.ID, s.Fingerprint(), s.Transport, s.Events)
		}
	}
	if selected["raw-0"] {
		out.Raw = t.Raw
	} else if len(t.Raw) > 0 {
		exclude("raw-0", "", replay.TransportRaw, t.Raw)
	}
	return out, nil
}

// resolveFingerprint maps a session fingerprint, or a unique prefix of one,
// to the session ID it names in this capture.
func resolveFingerprint(selector string, byFingerprint map[string]string) (string, error) {
	if !replay.LooksLikeFingerprint(selector) {
		return "", fmt.Errorf("unknown session %q; use check -details to list session IDs and fingerprints", selector)
	}
	var matches []string
	for fingerprint, id := range byFingerprint {
		if strings.HasPrefix(fingerprint, selector) {
			matches = append(matches, id)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no session in this capture has fingerprint %q; use check -details to list them", selector)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("fingerprint prefix %q matches %d sessions; give more characters", selector, len(matches))
	}
}

func Inspect(records []*pcapio.Record, opts Options, registry *replay.Registry) (*Inspection, error) {
	mode, profile, err := Resolve(opts.Mode, opts.Profile)
	if err != nil {
		return nil, err
	}
	if registry == nil {
		registry = adapters.DefaultRegistry()
	}
	if mode != "wire" {
		registry, err = RegistryWithKeyLog(registry, opts.KeyLog)
		if err != nil {
			return nil, err
		}
	}
	t, err := Select(replay.ExtractTrace(records, replay.ExtractOptions{UDPIdle: opts.UDPIdle}), opts.Sessions, registry)
	if err != nil {
		return nil, err
	}
	route := Detect(t, registry)
	// Entropy is a routing hint, not evidence of encryption. An explicit
	// transport choice may replay unrecognized binary data without claiming
	// application fidelity. Recognized TLS/SSH and mixed secure routes stay blocked.
	if mode == "transport" && route.Kind == Opaque && route.Session != nil {
		route.Kind, route.Reason = Generic, ""
		route.Session.Warnings = append(route.Session.Warnings, "explicit transport replay of unrecognized binary data; application equivalence is not asserted")
	}
	// Explicit wire mode never needs application credentials or interpretation.
	if mode != "wire" {
		replay.MarkIntrinsicBlockers(t)
	}
	plan := replay.BuildPlan(t, profile, registry)
	r := Readiness{Route: route.Kind, Supported: true, State: "ready"}
	block := func(reason string) {
		r.Supported = false
		r.State = "blocked"
		if r.Blocker == "" {
			r.Blocker = reason
		}
	}
	secure := route.Kind == TLS || route.Kind == SSH || route.Kind == FTP
	if secure && mode != "wire" && mode != "transport" && profile != replay.ProfileFunctional && !(route.Kind == TLS && profile == replay.ProfileTiming) {
		block("this fresh-session driver requires the functional profile; timing is supported for TLS application replay only")
	}
	// Coordinated plans include data lanes as well as their control session.
	// A fresh driver must never erase a truncation blocker on a related lane.
	for _, session := range t.Sessions {
		for _, event := range session.Events {
			if event.Record != nil && (event.Record.CapLen < event.Record.OrigLen || len(event.Record.Data) < event.Record.OrigLen) {
				block(session.ID + ": selected exchange contains truncated frames")
				break
			}
		}
	}
	if mode == "wire" {
		r.Route = "wire"
		r.NeedsInterface = true
		secure = false
	} else if route.Reason != "" {
		block(route.Reason)
	} else if secure && mode == "transport" && (route.Kind != FTP || NeedsKeyLog(route.Session)) {
		block("encrypted sessions cannot be adapted in transport mode; choose application mode with fresh-session inputs or explicitly choose wire mode")
	} else if secure && mode != "transport" {
		for i := range plan.Entries {
			e := &plan.Entries[i]
			if e.Excluded {
				continue
			}
			belongs := route.Session != nil && e.SessionID == route.Session.ID
			if !belongs {
				if route.Kind == FTP && NeedsKeyLog(route.Session) && len(opts.KeyLog) == 0 {
					block("FTPS negotiation requires -keylog <file> to identify related data sessions before replay")
				} else {
					block("selected capture contains other exchanges; use --session <id> to select the intended exchange")
				}
				continue
			}
			truncated := false
			for _, event := range route.Session.Events {
				if event.Record != nil && event.Record.OrigLen > event.Record.CapLen {
					truncated = true
				}
			}
			if truncated {
				block("selected exchange contains truncated frames")
				continue
			}
			if route.Kind == FTP && len(opts.KeyLog) > 0 {
				groups := registry.CoordinatedGroups(t)
				if g, ok := groups[route.Session.ID]; ok && len(g.Group.Blockers) > 0 {
					block(g.Group.Blockers[0])
					continue
				}
			}
			e.Blockers = nil
			e.Mode = replay.ModeSemantic
			e.Fidelity = replay.FidelitySemantic
			e.Driver = string(route.Kind) + "-reterminate"
			e.Adapter = e.Driver
			if route.Kind == FTP {
				e.Mode = replay.ModeCoordinated
				e.Driver = "ftp-coordinator"
				e.Adapter = "ftp"
			}
		}
		r.Requirements = []string{"target host:port"}
		if route.Kind == TLS || route.Kind == FTP && NeedsKeyLog(route.Session) {
			r.Requirements = append(r.Requirements, "matching NSS key log (-keylog)", "trusted certificate or explicit private CA")
		}
		if route.Kind == SSH {
			r.Requirements = append(r.Requirements, "username and password or private key", "pinned host key", "explicit command script")
		}
	}
	for i := range plan.Entries {
		e := &plan.Entries[i]
		if e.Excluded {
			continue
		}
		if e.Mode == replay.ModeWire && mode != "wire" {
			e.Mode = replay.ModeBlocked
			e.Driver = "none"
			e.Fidelity = replay.FidelityBlocked
			e.Blockers = []string{fmt.Sprintf("%s requires explicit wire replay; select intended sessions with --session <id> to exclude background traffic", e.SessionID)}
		}
		// TCP needs a framing/application adapter to use a fresh OS socket.
		// UDP and ICMP already preserve message boundaries and have live reply
		// drivers; they do not need a captured TCP state machine.
		if mode == "application" && e.Mode == replay.ModeStateful && e.Transport == replay.TransportTCP {
			e.Mode = replay.ModeBlocked
			e.Driver = "none"
			e.Fidelity = replay.FidelityBlocked
			e.Blockers = []string{"no TCP application adapter; use -exact-tcp for captured transport behavior or -mode auto for the advanced TCP packet driver"}
		}
		if e.Mode == replay.ModeBlocked {
			reason := "no executable driver"
			if len(e.Blockers) > 0 {
				reason = e.Blockers[0]
			}
			block(e.SessionID + ": " + reason)
		}
		if e.Mode == replay.ModeWire || e.Mode == replay.ModeStateful || e.Mode == replay.ModeSemantic && e.Transport != replay.TransportTCP {
			r.NeedsInterface = true
		}
	}
	if len(plan.Entries) == 0 {
		block("capture has no packets")
	}
	if !r.Supported {
		for i := range plan.Entries {
			e := &plan.Entries[i]
			if !e.Excluded && e.Mode != replay.ModeBlocked {
				e.Mode = replay.ModeBlocked
				e.Driver = "none"
				e.Fidelity = replay.FidelityBlocked
				e.Blockers = []string{r.Blocker}
			}
		}
	}
	if r.Supported {
		if len(r.Requirements) == 0 && mode != "wire" {
			r.Requirements = []string{"target device IP"}
		}
		if r.NeedsInterface {
			r.Requirements = append(r.Requirements, "network interface (-i)")
		}
		r.State = "needs-inputs"
	}
	if err := plan.ValidateCoverage(); err != nil {
		return nil, err
	}
	out := &Inspection{Mode: mode, Trace: t, Plan: plan, Readiness: r, Route: route}
	for _, e := range plan.Entries {
		if e.Excluded {
			out.ExcludedPackets += len(e.PacketIndexes)
		} else {
			out.SelectedPackets += len(e.PacketIndexes)
		}
	}
	return out, nil
}
