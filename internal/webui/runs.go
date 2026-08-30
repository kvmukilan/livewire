package webui

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/iterate"
	"github.com/kvmukilan/livewire/internal/lab"
	"github.com/kvmukilan/livewire/internal/livereplay"
	"github.com/kvmukilan/livewire/internal/orchestration"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/planexec"
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
	return iterate.ClassifyVerified(r.Completed, r.Verified, r.Matched, r.Entry.Mode == replay.ModeWire)
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
	if req.UDPIdleMS > int(time.Hour/time.Millisecond) {
		writeErr(w, 400, fmt.Errorf("udpIdleMs must not exceed 3600000"))
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
	if req.GapMS > int(10*time.Minute/time.Millisecond) {
		writeErr(w, 400, fmt.Errorf("gapMs must not exceed 600000"))
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
	records, _, err := s.loadPcap(path)
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
		round := orchestration.ExecutePlan(j.ctx, trace, plan, func(runCtx context.Context, k int, entry replay.PlanEntry, session *replay.Session, started time.Time) webSessionResult {
			result := runWebEntry(runCtx, j, entry, session, sessions, trace.Raw, flows, registry, target, att, profile, verify, verifyEngine, started)
			if runs.Repeats() {
				result.Attempt = i + 1
			}
			return result
		})
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
			ok = false
		} else {
			j.artifact(evidenceName)
			evidenceArtifact = evidenceName
		}
	}
	digest, digestErr := s.fileSHA256(path)
	if digestErr != nil {
		j.log("capture digest: " + digestErr.Error())
		ok = false
	}
	doc := map[string]any{
		"tool": "livewire", "version": s.version, "when": time.Now().UTC(), "plan": plan,
		"adapterVersions": adapters.VersionsForRegistry(registry),
		"captureDigest":   digest, "limitations": plan.Limitations(),
		"target": target.String(), "interface": req.Iface, "variables": runvars.Redacted(req.Variables),
		"results": results, "evidence": evidenceArtifact,
	}
	if runs.Repeats() {
		doc["attempts"] = summary.Attempts
		doc["outcome"] = summary
		doc["transformations"] = []string{
			"repeated TCP sessions used a fresh client port and ISN so the device would not treat them as duplicate connections",
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
		j.finish(ok, fmt.Sprintf("%d attempts: %s (%d same, %d different, %d unverified, %d wire-only, %d did not complete)",
			summary.Attempts, verdict, summary.Same, summary.Different, summary.Unverified, summary.WireOnly, summary.Incomplete))
		return
	}
	j.finish(ok, fmt.Sprintf("%d sessions completed", len(results)))
}

func runWebEntry(ctx context.Context, j *job, entry replay.PlanEntry, session *replay.Session, sessions map[string]*replay.Session, raw []replay.Event, flows []*engine.Flow, registry *replay.Registry, target netip.Addr, req adaptiveRunReq, profile replay.Profile, verify replay.VerifyMode, verifyEngine engine.VerifyMode, started time.Time) webSessionResult {
	trace := &replay.Trace{Raw: raw}
	for _, item := range sessions {
		trace.Sessions = append(trace.Sessions, item)
	}
	executed := planexec.ExecuteEntry(planexec.Config{
		Context: ctx, Trace: trace, Plan: replay.ReplayPlan{Profile: profile}, Registry: registry,
		Flows: flows, Iface: req.Iface, TargetIP: target, Variables: req.Variables, Verify: verify,
		TCPConfig: func(flow *engine.Flow, selected *replay.Session) livereplay.Config {
			return livereplay.Config{
				Flow: flow, Iface: req.Iface, TargetIP: target, TargetPort: selected.Server.Port,
				Seed: 1 + int64(req.attempt), LocalPort: iterate.ShiftPort(flow.Client.Port, req.attempt),
				NoGuard: req.NoGuard, Verify: verifyEngine, Adaptive: profile != replay.ProfileTransport,
			}
		},
		Progress: func(selected replay.PlanEntry, stage, message string) {
			j.progress(stage, selected.SessionID, message)
		},
	}, entry, session, started)
	return webResult(executed)
}

func webResult(executed planexec.Result) webSessionResult {
	out := webSessionResult{Entry: executed.Entry}
	if executed.Err != nil {
		out.Error = executed.Err.Error()
	}
	if executed.Entry.Transport == replay.TransportTCP && executed.Entry.Mode == replay.ModeStateful {
		out.Completed, out.Verified, out.Matched = executed.TCP.Outcome.Succeeded(), executed.TCP.Verified, executed.TCP.Matched
		out.Sent, out.Evidence = executed.TCP.Outcome.Sent, executed.TCP.Evidence
		for _, difference := range executed.TCP.Outcome.Mismatches {
			out.Differences = append(out.Differences, replay.Difference{Field: "tcp-response", Actual: difference.Detail, Structural: difference.Structural})
		}
		return out
	}
	if executed.Entry.Mode == replay.ModeCoordinated && executed.Entry.Adapter == "ftp" {
		out.Completed, out.Verified = executed.FTP.Completed, executed.FTP.Verified
		out.Matched = executed.FTP.Verified && executed.FTP.Completed && len(executed.FTP.Differences) == 0
		for _, transfer := range executed.FTP.Transfers {
			out.Matched = out.Matched && transfer.Matched
		}
		out.Sent, out.Received, out.Differences = executed.FTP.Commands, executed.FTP.Replies, executed.FTP.Differences
		return out
	}
	out.Completed, out.Verified, out.Matched = executed.Transport.Completed, executed.Transport.Verified, executed.Transport.Matched
	out.Sent, out.Received, out.Differences, out.Evidence = executed.Transport.Sent, executed.Transport.Received, executed.Transport.Differences, executed.Transport.Evidence
	return out
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
	if req.UDPIdleMS > int(time.Hour/time.Millisecond) {
		writeErr(w, 400, fmt.Errorf("udpIdleMs must not exceed 3600000"))
		return
	}
	if req.DrainMS < 0 || req.DrainMS > int(5*time.Minute/time.Millisecond) {
		writeErr(w, 400, fmt.Errorf("drainMs must be between 0 and 300000"))
		return
	}
	if req.ActorTimeoutMS < 0 || req.ActorTimeoutMS > int(10*time.Minute/time.Millisecond) {
		writeErr(w, 400, fmt.Errorf("actorTimeoutMs must be between 0 and 600000"))
		return
	}
	if _, err := s.startJob("dut-lab", func(j *job) { s.runLabJob(j, path, req) }); err != nil {
		writeErr(w, 409, err)
		return
	}
	writeJSON(w, map[string]any{"started": true})
}

func (s *Server) runLabJob(j *job, path string, req labRunReq) {
	records, _, err := s.loadPcap(path)
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
	digest, digestErr := s.fileSHA256(path)
	if digestErr != nil {
		j.log("capture digest: " + digestErr.Error())
		j.finish(false, "capture digest failed")
		return
	}
	doc := map[string]any{
		"tool": "livewire", "version": s.version, "when": time.Now().UTC(), "captureDigest": digest,
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

func (s *Server) fileSHA256(path string) (string, error) {
	f, err := s.openRootedPath(path)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, copyErr := io.Copy(h, f)
	if err := errors.Join(copyErr, f.Close()); err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}

func writeRedactedJSON(path string, value any, variables map[string]string) error {
	return orchestration.WriteJSON(path, value, runvars.NewRedactor(variables))
}

func writeWebEvidence(path, iface string, records []pcapio.Record) (retErr error) {
	af, err := orchestration.CreateArtifact(path)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, af.Abort()) }()
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
	w, err := pcapio.NewNgWriter(af, interfaces)
	if err != nil {
		return err
	}
	for i := range records {
		records[i].InterfaceID = ids[records[i].LinkType]
		if err := w.Write(&records[i]); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	return af.Commit()
}
