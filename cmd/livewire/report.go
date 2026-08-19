package main

import (
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/iterate"
	"github.com/kvmukilan/livewire/internal/livereplay"
	"github.com/kvmukilan/livewire/internal/orchestration"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/runvars"
)

// flowResult is one flow's outcome in a replay report.
type flowResult struct {
	// Attempt is the 1-based iteration this result came from, omitted for a
	// single run so a one-shot report is byte-for-byte what it always was.
	Attempt              int      `json:"attempt,omitempty"`
	Flow                 int      `json:"flow"`
	Client               string   `json:"client"`
	Server               string   `json:"server"`
	Target               string   `json:"target"`
	Mode                 string   `json:"mode"` // stateful | stateless | failed
	Phase                string   `json:"phase"`
	Succeeded            bool     `json:"succeeded"`
	Sent                 int      `json:"framesSent"`
	CapturedClientFrames int      `json:"capturedClientFrames"`
	StimulusCompleted    bool     `json:"stimulusCompleted"`
	Retransmits          int      `json:"retransmits"`
	Verified             bool     `json:"verified"`
	RepliesMatched       bool     `json:"repliesMatched"`
	Divergences          []string `json:"divergences,omitempty"`
	Error                string   `json:"error,omitempty"`
	// Diagnosis is a best-effort explanation of why a flow did not faithfully
	// reproduce the capture, to point the user at what to change.
	Diagnosis string `json:"diagnosis,omitempty"`
}

// replayReport is the JSON document written by -report.
type replayReport struct {
	Tool            string             `json:"tool"`
	Version         string             `json:"version"`
	When            string             `json:"when"`
	Iface           string             `json:"iface"`
	Verify          string             `json:"verify"`
	Adaptive        bool               `json:"adaptive"`
	Paced           bool               `json:"paced"`
	RawL4           bool               `json:"rawL4"`
	Profile         string             `json:"profile,omitempty"`
	Preflight       *preflightReport   `json:"preflight,omitempty"`
	ActualCapture   string             `json:"actualCapture,omitempty"`
	CaptureDigest   string             `json:"captureDigest,omitempty"`
	Plan            *replay.ReplayPlan `json:"replayPlan,omitempty"`
	AdapterVersions map[string]string  `json:"adapterVersions"`
	Variables       map[string]string  `json:"variables,omitempty"`
	Transformations []string           `json:"transformations"`
	Limitations     []string           `json:"limitations,omitempty"`
	// Attempts is how many times the replay ran, present only when it ran more
	// than once. Outcome then reduces those attempts to one answer, including
	// whether the device was consistent between them.
	Attempts     int              `json:"attempts,omitempty"`
	Outcome      *iterate.Summary `json:"outcome,omitempty"`
	Flows        []flowResult     `json:"flows"`
	Sessions     []sessionResult  `json:"sessions,omitempty"`
	secretValues []string
	// attempt is the 1-based iteration currently being recorded, stamped onto
	// each result as it is added. Zero means a single un-repeated run.
	attempt int
}

// startAttempt marks subsequent add/addPlanned calls as belonging to iteration n
// (1-based). Callers that never repeat leave it alone.
func (r *replayReport) startAttempt(n int) { r.attempt = n }

// recordIterations attaches the cross-attempt answer, and records that the
// attempts were deliberately not identical — a reader comparing the evidence
// pcap against the capture needs to know the client port and ISN moved on
// purpose.
func (r *replayReport) recordIterations(s iterate.Summary) {
	r.Attempts = s.Attempts
	r.Outcome = &s
	r.Transformations = append(r.Transformations,
		"each attempt used a fresh client port and ISN so the device would not treat it as a duplicate connection")
}

type sessionResult struct {
	// Attempt is the 1-based iteration this result came from, omitted for a
	// single run.
	Attempt     int                 `json:"attempt,omitempty"`
	SessionID   string              `json:"sessionId"`
	Protocol    replay.Transport    `json:"protocol"`
	Driver      string              `json:"driver"`
	Adapter     string              `json:"adapter,omitempty"`
	Mode        replay.Mode         `json:"mode"`
	Fidelity    replay.Fidelity     `json:"fidelity"`
	Target      string              `json:"target,omitempty"`
	PacketCount int                 `json:"packetCount"`
	Completed   bool                `json:"completed"`
	Verified    bool                `json:"verified"`
	Matched     bool                `json:"matched"`
	Sent        int                 `json:"sent"`
	Received    int                 `json:"received"`
	Differences []replay.Difference `json:"differences,omitempty"`
	Warnings    []string            `json:"warnings,omitempty"`
	Blockers    []string            `json:"blockers,omitempty"`
	Error       string              `json:"error,omitempty"`
}

func newReplayReport(o liveOpts) *replayReport {
	r := &replayReport{
		Tool: "livewire", Version: version, When: time.Now().Format(time.RFC3339),
		Iface: o.iface, Verify: o.verify.String(), Adaptive: o.adaptive, Paced: o.pace,
		RawL4: o.rawL4, Profile: o.profile, AdapterVersions: adapters.Versions(),
	}
	r.Variables = runvars.Redacted(o.variables)
	for k, v := range o.variables {
		if runvars.IsSecret(k) && v != "" {
			r.secretValues = append(r.secretValues, v)
		}
	}
	r.Transformations = []string{"target IP and link-layer addresses retargeted", "TCP sequence and acknowledgement numbers aligned to the live session", "checksums recomputed after header changes"}
	if o.adaptive {
		r.Transformations = append(r.Transformations, "client acknowledgements adapted to the live device response length")
	}
	if !o.pace {
		r.Transformations = append(r.Transformations, "captured packet timing not preserved")
	}
	return r
}

func (r *replayReport) addPlanned(p plannedResult, target string) {
	sr := sessionResult{
		Attempt:   r.attempt,
		SessionID: p.Entry.SessionID, Protocol: p.Entry.Transport, Driver: p.Entry.Driver, Adapter: p.Entry.Adapter,
		Mode: p.Entry.Mode, Fidelity: p.Entry.Fidelity, Target: target,
		PacketCount: len(p.Entry.PacketIndexes), Warnings: p.Entry.Warnings, Blockers: p.Entry.Blockers,
	}
	if p.Entry.Transport == replay.TransportTCP && p.Entry.Mode == replay.ModeStateful {
		sr.Completed = p.TCP.Outcome.Succeeded()
		sr.Verified = p.TCP.Verified
		sr.Matched = p.TCP.Matched
		sr.Sent = p.TCP.Outcome.Sent
		for _, d := range p.TCP.Outcome.Mismatches {
			sr.Differences = append(sr.Differences, replay.Difference{Field: "tcp-response", Actual: d.Detail, Structural: d.Structural})
		}
	} else if p.Entry.Mode == replay.ModeCoordinated && p.Entry.Adapter == "ftp" {
		sr.Completed = p.FTP.Completed
		sr.Verified = r.Verify != string(replay.VerifyOff)
		sr.Matched = p.FTP.Completed && len(p.FTP.Differences) == 0
		for _, transfer := range p.FTP.Transfers {
			sr.Matched = sr.Matched && transfer.Matched
		}
		sr.Sent, sr.Received = p.FTP.Commands, p.FTP.Replies
		sr.Differences = append(sr.Differences, p.FTP.Differences...)
	} else {
		sr.Completed, sr.Matched = p.Transport.Completed, p.Transport.Matched
		sr.Verified = p.Transport.Verified
		sr.Sent, sr.Received = p.Transport.Sent, p.Transport.Received
		sr.Differences = append(sr.Differences, p.Transport.Differences...)
	}
	if p.Err != nil {
		sr.Error = p.Err.Error()
	}
	r.Sessions = append(r.Sessions, sr)
}

// add records one flow's result. err is non-nil when the flow could not run.
func (r *replayReport) add(idx int, f *engine.Flow, target, mode string, res livereplay.Result, err error) {
	fr := flowResult{
		Attempt: r.attempt,
		Flow:    idx, Client: f.Client.String(), Server: f.Server.String(),
		Target: target, Mode: mode,
	}
	for _, cp := range f.Packets {
		if cp.Dir == engine.C2S {
			fr.CapturedClientFrames++
		}
	}
	if err != nil {
		fr.Error = err.Error()
		fr.Diagnosis = "flow could not be opened — check the interface, target, and privileges"
	} else {
		out := res.Outcome
		fr.Phase = out.Phase.String()
		fr.Succeeded = out.Succeeded()
		fr.StimulusCompleted = out.Succeeded()
		fr.Sent = out.Sent
		fr.Retransmits = out.Retransmits
		fr.Verified = r.Verify != "off"
		fr.RepliesMatched = fr.Verified && out.RepliesMatched()
		for _, m := range out.Mismatches {
			fr.Divergences = append(fr.Divergences, m.Detail)
		}
		if fr.Succeeded && !fr.Verified {
			fr.Diagnosis = "exchange completed; response equivalence was not checked"
		} else {
			fr.Diagnosis = diagnose(out, mode)
		}
	}
	r.Flows = append(r.Flows, fr)
}

// diagnose infers the most likely reason a flow did not faithfully reproduce the
// capture, so the report points the user at what to fix rather than leaving them
// to guess.
func diagnose(out engine.Outcome, mode string) string {
	switch {
	case out.Succeeded() && out.RepliesMatched():
		return "" // faithful reproduction; nothing to explain
	case out.Succeeded() && !out.RepliesMatched():
		return "completed, but the device answered differently than the capture — likely a different device state, " +
			"firmware, or register contents (see divergences)"
	case strings.Contains(out.Reason, "RST"):
		return "the device reset the connection — it may have rejected the synthesized/handshake options, or the " +
			"host kernel raced the replay (ensure RST suppression is armed)"
	case strings.Contains(out.Reason, "retransmit"), strings.Contains(out.Reason, "stalled"):
		return "the device stopped responding mid-exchange — it may be in a different state, or a reply diverged " +
			"enough to break the flow (try -verify strict to see where)"
	case mode == "stateless":
		return "no handshake and one could not be synthesized — frames were sent raw; the device won't form a connection"
	default:
		return "flow ended in phase " + out.Phase.String() + "; see the log and any divergences"
	}
}

func (r *replayReport) write(path string) error {
	return orchestration.WriteJSON(path, r, runvars.NewRedactor(nil, r.secretValues...))
}
