package webui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/iterate"
	"github.com/kvmukilan/livewire/internal/lab"
	"github.com/kvmukilan/livewire/internal/livereplay"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/runvars"
	"github.com/kvmukilan/livewire/internal/wire"
)

type adaptiveRunReq struct {
	Pcap      string            `json:"pcap"`
	Iface     string            `json:"iface"`
	TargetIP  string            `json:"targetIP"`
	Profile   string            `json:"profile"`
	Verify    string            `json:"verify"`
	NoGuard   bool              `json:"noGuard"`
	Variables map[string]string `json:"variables,omitempty"`
	RulePacks []json.RawMessage `json:"rulePacks,omitempty"`
	UDPIdleMS int               `json:"udpIdleMs,omitempty"`
	// Attempts replays the whole plan this many times and reports how often the
	// device behaved the same. 0 or 1 means a single run.
	Attempts int `json:"attempts,omitempty"`
	// GapMS is the settle time between attempts. 0 takes the default.
	GapMS int `json:"gapMs,omitempty"`
	// attempt is the 0-based iteration currently running. It is internal, set by
	// the job loop, and is what varies the seed and client port per attempt.
	attempt int `json:"-"`
}

// maxWebAttempts bounds what the dashboard will accept. The browser holds one
// job at a time and a caller can type any number into the form, so an unbounded
// value would pin the host on the wire with no way back but a restart.
const maxWebAttempts = 100

// defaultWebGap matches the CLI's -gap: long enough for a device to settle
// between connections, short enough not to dominate a five-attempt run.
const defaultWebGap = time.Second

type webSessionResult struct {
	// Attempt is the 1-based iteration this result came from, omitted for a
	// single run so an un-repeated report is unchanged.
	Attempt     int                 `json:"attempt,omitempty"`
	Entry       replay.PlanEntry    `json:"entry"`
	Completed   bool                `json:"completed"`
	Verified    bool                `json:"verified"`
	Matched     bool                `json:"matched"`
	Sent        int                 `json:"sent"`
	Received    int                 `json:"received"`
	Differences []replay.Difference `json:"differences,omitempty"`
	Error       string              `json:"error,omitempty"`
	Evidence    []pcapio.Record     `json:"-"`
}

// verdict reduces one session result to the shared verdict vocabulary. Wire mode
// claims no equivalence, which is why it is reported separately rather than as a
// pass or a failure.
func (r webSessionResult) verdict() iterate.Verdict {
	if r.Error != "" {
		return iterate.Incomplete
	}
	return iterate.Classify(r.Completed, r.Matched, r.Entry.Mode == replay.ModeWire)
}

func (s *Server) handleAdaptiveRun(w http.ResponseWriter, r *http.Request) {
	var req adaptiveRunReq
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if req.Pcap == "" || req.Iface == "" || req.TargetIP == "" {
		writeErr(w, 400, fmt.Errorf("pcap, iface, and targetIP are required"))
		return
	}
	if _, err := netip.ParseAddr(req.TargetIP); err != nil {
		writeErr(w, 400, fmt.Errorf("invalid targetIP"))
		return
	}
	if _, err := replay.ParseProfile(req.Profile); err != nil {
		writeErr(w, 400, err)
		return
	}
	if req.UDPIdleMS < 0 {
		writeErr(w, 400, fmt.Errorf("udpIdleMs must not be negative"))
		return
	}
	if req.Attempts < 0 || req.Attempts > maxWebAttempts {
		writeErr(w, 400, fmt.Errorf("attempts must be between 1 and %d", maxWebAttempts))
		return
	}
	if req.GapMS < 0 {
		writeErr(w, 400, fmt.Errorf("gapMs must not be negative"))
		return
	}
	if req.Verify == "" {
		req.Verify = "lenient"
	}
	if _, err := engine.ParseVerifyMode(req.Verify); err != nil {
		writeErr(w, 400, err)
		return
	}
	for name, value := range req.Variables {
		if _, _, err := runvars.ParseAssignment(name + "=" + value); err != nil {
			writeErr(w, 400, err)
			return
		}
	}
	if _, err := registryForRulePacks(req.RulePacks); err != nil {
		writeErr(w, 400, err)
		return
	}
	path, err := s.pcapPath(req.Pcap)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	if _, err := s.startJob("adaptive-replay", func(j *job) { s.runAdaptiveJob(j, path, req) }); err != nil {
		writeErr(w, 409, err)
		return
	}
	writeJSON(w, map[string]any{"started": true})
}

func (s *Server) runAdaptiveJob(j *job, path string, req adaptiveRunReq) {
	j.protectVariables(req.Variables)
	records, _, err := loadPcap(path)
	if err != nil {
		j.log(err.Error())
		j.finish(false, "load failed")
		return
	}
	profile, _ := replay.ParseProfile(req.Profile)
	verifyEngine, _ := engine.ParseVerifyMode(req.Verify)
	verify := replay.VerifyMode(verifyEngine.String())
	target, _ := netip.ParseAddr(req.TargetIP)
	trace := replay.ExtractTrace(records, replay.ExtractOptions{UDPIdle: time.Duration(req.UDPIdleMS) * time.Millisecond})
	replay.MarkIntrinsicBlockers(trace)
	registry, err := registryForRulePacks(req.RulePacks)
	if err != nil {
		j.log(err.Error())
		j.finish(false, "rule-pack compilation failed")
		return
	}
	plan := replay.BuildPlan(trace, profile, registry)
	if err := plan.ValidateCoverage(); err != nil {
		j.log(err.Error())
		j.finish(false, "plan invalid")
		return
	}
	flows := engine.ExtractFlows(records)
	sessions := map[string]*replay.Session{}
	for _, sess := range trace.Sessions {
		sessions[sess.ID] = sess
	}
	gap := defaultWebGap
	if req.GapMS > 0 {
		gap = time.Duration(req.GapMS) * time.Millisecond
	}
	runs := iterate.Plan{Times: req.Attempts, Gap: gap}.Normalize()

	// The loop lives inside this one job because the server permits a single job
	// at a time: N attempts must not be N jobs, or the second would be refused.
	var (
		results  []webSessionResult
		evidence []pcapio.Record
		ok       = true
	)
	attempt := func(i int) iterate.Tally {
		// Vary what TCP uses to tell connections apart, so the device does not
		// see attempt two as a stale duplicate of attempt one and reset it.
		att := req
		att.attempt = i
		if runs.Repeats() {
			j.progress("attempt", "", fmt.Sprintf("attempt %d of %d", i+1, runs.Times))
		}
		started := time.Now()
		round := make([]webSessionResult, len(plan.Entries))
		run := func(k int) {
			entry := plan.Entries[k]
			round[k] = runWebEntry(j.ctx, j, entry, sessions[entry.SessionID], trace.Raw, flows, registry, target, att, profile, verify, verifyEngine, started)
			if runs.Repeats() {
				round[k].Attempt = i + 1
			}
		}
		if profile != replay.ProfileFunctional {
			var wg sync.WaitGroup
			for k := range round {
				wg.Add(1)
				go func(k int) { defer wg.Done(); run(k) }(k)
			}
			wg.Wait()
		} else {
			for k := range round {
				run(k)
			}
		}
		var tally iterate.Tally
		for _, r := range round {
			evidence = append(evidence, r.Evidence...)
			if r.Error != "" || !r.Completed {
				ok = false
			}
			tally.Add(r.verdict())
		}
		results = append(results, round...)
		if runs.Repeats() {
			j.progress("attempt", "", fmt.Sprintf("attempt %d of %d: %s", i+1, runs.Times, tally.Worst().Plain()))
		}
		return tally
	}

	per := runs.Run(j.ctx, attempt)
	summary := iterate.Summarize(per, runs.Times)
	stamp := time.Now().UTC().Format("20060102T150405.000Z")
	base := strings.TrimSuffix(filepath.Base(req.Pcap), filepath.Ext(req.Pcap)) + "." + stamp
	reportName := base + ".run.json"
	evidenceName := base + ".actual.pcapng"
	evidenceArtifact := ""
	if len(evidence) > 0 {
		if err := writeWebEvidence(filepath.Join(s.dir, evidenceName), req.Iface, evidence); err != nil {
			j.log("evidence: " + err.Error())
		} else {
			j.artifact(evidenceName)
			evidenceArtifact = evidenceName
		}
	}
	digest, digestErr := fileSHA256(path)
	if digestErr != nil {
		j.log("capture digest: " + digestErr.Error())
		ok = false
	}
	doc := map[string]any{
		"tool": "livewire", "version": Version, "when": time.Now().UTC(), "plan": plan,
		"adapterVersions": adapters.VersionsForRegistry(registry),
		"captureDigest":   digest, "limitations": plan.Limitations(),
		"target": target.String(), "interface": req.Iface, "variables": runvars.Redacted(req.Variables),
		"results": results, "evidence": evidenceArtifact,
	}
	if runs.Repeats() {
		doc["attempts"] = summary.Attempts
		doc["outcome"] = summary
		doc["transformations"] = []string{
			"each attempt used a fresh client port and ISN so the device would not treat it as a duplicate connection",
		}
	}
	if err := writeRedactedJSON(filepath.Join(s.dir, reportName), doc, req.Variables); err != nil {
		j.log("report: " + err.Error())
		ok = false
	} else {
		j.artifact(reportName)
	}
	if runs.Repeats() {
		verdict := summary.Verdict.Plain()
		if summary.Intermittent {
			verdict = "INTERMITTENT"
		}
		j.finish(ok, fmt.Sprintf("%d attempts: %s (%d same, %d different, %d did not complete)",
			summary.Attempts, verdict, summary.Same, summary.Different, summary.Incomplete))
		return
	}
	j.finish(ok, fmt.Sprintf("%d sessions completed", len(results)))
}

func runWebEntry(ctx context.Context, j *job, entry replay.PlanEntry, session *replay.Session, raw []replay.Event, flows []*engine.Flow, registry *replay.Registry, target netip.Addr, req adaptiveRunReq, profile replay.Profile, verify replay.VerifyMode, verifyEngine engine.VerifyMode, started time.Time) webSessionResult {
	out := webSessionResult{Entry: entry}
	if entry.Mode == replay.ModeBlocked {
		out.Error = strings.Join(entry.Blockers, "; ")
		j.progress("blocked", entry.SessionID, entry.SessionID+": "+out.Error)
		return out
	}
	if entry.Mode == replay.ModeWire {
		events := raw
		if session != nil {
			events = session.Events
		}
		b, err := backend.OpenSender(req.Iface)
		if err != nil {
			out.Error = err.Error()
			return out
		}
		defer b.Close()
		for _, e := range events {
			if !waitWeb(ctx, started.Add(e.At)) {
				out.Error = "cancelled"
				return out
			}
			if err := b.Send(e.Record.Data); err != nil {
				out.Error = err.Error()
				return out
			}
			frame := append([]byte(nil), e.Record.Data...)
			out.Evidence = append(out.Evidence, pcapio.Record{Time: b.Now(), Data: frame, CapLen: len(frame), OrigLen: len(frame), LinkType: b.LinkType()})
			out.Sent++
		}
		out.Completed = true
		out.Verified = false
		out.Matched = false
		j.progress("wire", entry.SessionID, fmt.Sprintf("%s: sent %d frame(s), wire-only", entry.SessionID, out.Sent))
		return out
	}
	if session == nil || session.Server.IP.Is4() != target.Is4() {
		out.Error = "missing session or target address family mismatch"
		return out
	}
	if entry.Mode == replay.ModeSemantic && session.Transport == replay.TransportTCP {
		res, err := replay.RunTCPSemanticContext(ctx, replay.TCPSemanticConfig{
			Session: session, TargetIP: target, TargetPort: session.Server.Port, Adapter: registry.ByName(entry.Adapter),
			Profile: profile, Verify: verify, Variables: req.Variables, Start: started,
			Progress: func(p replay.ProgressEvent) { j.progress(p.Stage, p.SessionID, p.Message) },
		})
		out.Completed, out.Verified, out.Matched, out.Sent, out.Received, out.Differences, out.Evidence = res.Completed, res.Verified, res.Matched, res.Sent, res.Received, res.Differences, res.Evidence
		if err != nil {
			out.Error = err.Error()
		}
		return out
	}
	if session.Transport == replay.TransportUDP || session.Transport == replay.TransportICMP4 || session.Transport == replay.TransportICMP6 {
		res, err := replay.RunTransportContext(ctx, replay.TransportRunConfig{
			Session: session, Iface: req.Iface, TargetIP: target, TargetPort: session.Server.Port,
			Profile: profile, Verify: verify, Adapter: registry.ByName(entry.Adapter), Variables: req.Variables, Start: started,
			Progress: func(p replay.ProgressEvent) { j.progress(p.Stage, p.SessionID, p.Message) },
		})
		out.Completed, out.Verified, out.Matched, out.Sent, out.Received, out.Differences, out.Evidence = res.Completed, res.Verified, res.Matched, res.Sent, res.Received, res.Differences, res.Evidence
		if err != nil {
			out.Error = err.Error()
		}
		return out
	}
	flow := findWebFlow(flows, session)
	if flow == nil {
		out.Error = "TCP engine flow not found"
		return out
	}
	if profile != replay.ProfileFunctional && len(session.Events) > 0 && !waitWeb(ctx, started.Add(session.Events[0].At)) {
		out.Error = "cancelled"
		return out
	}
	res, err := livereplay.RunContext(ctx, livereplay.Config{
		Flow: flow, Iface: req.Iface, TargetIP: target, TargetPort: session.Server.Port,
		Seed: 1 + int64(req.attempt), LocalPort: iterate.ShiftPort(flow.Client.Port, req.attempt),
		NoGuard: req.NoGuard, Verify: verifyEngine, Adaptive: profile != replay.ProfileTransport,
		Pace: profile == replay.ProfileTiming || profile == replay.ProfileTransport, RawL4: profile == replay.ProfileTransport,
	}, func(line string) { j.progress("tcp", entry.SessionID, line) })
	out.Completed, out.Verified, out.Matched, out.Sent, out.Evidence = res.Outcome.Succeeded(), res.Verified, res.Matched, res.Outcome.Sent, res.Evidence
	for _, d := range res.Outcome.Mismatches {
		out.Differences = append(out.Differences, replay.Difference{Field: "tcp-response", Actual: d.Detail, Structural: d.Structural})
	}
	if err != nil {
		out.Error = err.Error()
	}
	return out
}

func findWebFlow(flows []*engine.Flow, s *replay.Session) *engine.Flow {
	for _, f := range flows {
		if f.Client.Addr == s.Client.IP && f.Client.Port == s.Client.Port && f.Server.Addr == s.Server.IP && f.Server.Port == s.Server.Port {
			return f
		}
	}
	return nil
}

func waitWeb(ctx context.Context, target time.Time) bool {
	if d := time.Until(target); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
		}
	}
	return ctx.Err() == nil
}

type labRunReq struct {
	Pcap           string       `json:"pcap"`
	Profile        string       `json:"profile"`
	Topology       lab.Topology `json:"topology"`
	Scenario       lab.Scenario `json:"scenario"`
	DrainMS        int          `json:"drainMs,omitempty"`
	ActorTimeoutMS int          `json:"actorTimeoutMs,omitempty"`
	UDPIdleMS      int          `json:"udpIdleMs,omitempty"`
}

func (s *Server) handleLab(w http.ResponseWriter, r *http.Request) {
	var req labRunReq
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	path, err := s.pcapPath(req.Pcap)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	if err := req.Topology.Validate(); err != nil {
		writeErr(w, 400, err)
		return
	}
	if err := req.Scenario.Validate(); err != nil {
		writeErr(w, 400, err)
		return
	}
	if _, err := replay.ParseProfile(req.Profile); err != nil {
		writeErr(w, 400, err)
		return
	}
	if req.UDPIdleMS < 0 {
		writeErr(w, 400, fmt.Errorf("udpIdleMs must not be negative"))
		return
	}
	if _, err := s.startJob("dut-lab", func(j *job) { s.runLabJob(j, path, req) }); err != nil {
		writeErr(w, 409, err)
		return
	}
	writeJSON(w, map[string]any{"started": true})
}

func (s *Server) runLabJob(j *job, path string, req labRunReq) {
	records, _, err := loadPcap(path)
	if err != nil {
		j.log(err.Error())
		j.finish(false, "load failed")
		return
	}
	trace := replay.ExtractTrace(records, replay.ExtractOptions{UDPIdle: time.Duration(req.UDPIdleMS) * time.Millisecond})
	profile, _ := replay.ParseProfile(req.Profile)
	plan := lab.BuildReplayPlan(trace, profile)
	result, runErr := lab.RunContext(j.ctx, lab.Config{
		Trace: trace, Plan: &plan, Topology: req.Topology, Scenario: req.Scenario, Profile: profile, Drain: time.Duration(req.DrainMS) * time.Millisecond, ActorTimeout: time.Duration(req.ActorTimeoutMS) * time.Millisecond,
		Progress: func(p lab.Progress) { j.progress(p.Stage, p.SessionID, p.Message) },
	})
	stamp := time.Now().UTC().Format("20060102T150405Z")
	base := strings.TrimSuffix(filepath.Base(req.Pcap), filepath.Ext(req.Pcap)) + "." + stamp
	evidenceName, reportName := base+".lab.pcapng", base+".lab.json"
	if err := lab.WriteEvidence(filepath.Join(s.dir, evidenceName), result, req.Topology); err != nil {
		j.log(err.Error())
		j.finish(false, "evidence failed")
		return
	}
	j.artifact(evidenceName)
	digest, _ := fileSHA256(path)
	doc := map[string]any{
		"tool": "livewire", "version": Version, "when": time.Now().UTC(), "captureDigest": digest,
		"plan": plan, "adapterVersions": adapters.Versions(), "variables": map[string]string{},
		"transformations": webLabTransformations(plan, result), "limitations": result.Limitations,
		"topology": req.Topology, "scenario": req.Scenario, "result": result, "evidence": evidenceName,
	}
	if err := writeRedactedJSON(filepath.Join(s.dir, reportName), doc, nil); err != nil {
		j.log(err.Error())
		j.finish(false, "report failed")
		return
	}
	j.artifact(reportName)
	if runErr != nil {
		j.log(runErr.Error())
		j.finish(false, "lab stopped")
		return
	}
	j.finish(true, fmt.Sprintf("crossed %d/%d frames", result.Metrics.Crossed, result.Metrics.Injected))
}

func webLabTransformations(plan replay.ReplayPlan, result lab.Result) []string {
	var out []string
	seen := map[string]bool{}
	add := func(value string) {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
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

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}

func writeRedactedJSON(path string, value any, variables map[string]string) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	for key, value := range variables {
		if runvars.IsSecret(key) && value != "" {
			b = bytes.ReplaceAll(b, []byte(value), []byte("[REDACTED]"))
		}
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func writeWebEvidence(path, iface string, records []pcapio.Record) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	links := []wire.LinkType{}
	ids := map[wire.LinkType]uint32{}
	for _, rec := range records {
		if _, ok := ids[rec.LinkType]; !ok {
			ids[rec.LinkType] = uint32(len(links))
			links = append(links, rec.LinkType)
		}
	}
	interfaces := make([]pcapio.NgInterface, len(links))
	for i, link := range links {
		interfaces[i] = pcapio.NgInterface{Name: iface, LinkType: link}
	}
	w, err := pcapio.NewNgWriter(f, interfaces)
	if err != nil {
		return err
	}
	for i := range records {
		records[i].InterfaceID = ids[records[i].LinkType]
		if err := w.Write(&records[i]); err != nil {
			return err
		}
	}
	return w.Flush()
}
