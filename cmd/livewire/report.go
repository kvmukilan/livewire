package main

import (
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/livereplay"
)

// flowResult is one flow's outcome in a replay report.
type flowResult struct {
	Flow           int      `json:"flow"`
	Client         string   `json:"client"`
	Server         string   `json:"server"`
	Target         string   `json:"target"`
	Mode           string   `json:"mode"` // stateful | stateless | failed
	Phase          string   `json:"phase"`
	Succeeded      bool     `json:"succeeded"`
	Sent           int      `json:"framesSent"`
	Retransmits    int      `json:"retransmits"`
	RepliesMatched bool     `json:"repliesMatched"`
	Divergences    []string `json:"divergences,omitempty"`
	Error          string   `json:"error,omitempty"`
	// Diagnosis is a best-effort explanation of why a flow did not faithfully
	// reproduce the capture, to point the user at what to change.
	Diagnosis string `json:"diagnosis,omitempty"`
}

// replayReport is the JSON document written by -report.
type replayReport struct {
	Tool     string       `json:"tool"`
	Version  string       `json:"version"`
	When     string       `json:"when"`
	Iface    string       `json:"iface"`
	Verify   string       `json:"verify"`
	Adaptive bool         `json:"adaptive"`
	Paced    bool         `json:"paced"`
	Flows    []flowResult `json:"flows"`
}

func newReplayReport(o liveOpts) *replayReport {
	return &replayReport{
		Tool: "livewire", Version: version, When: time.Now().Format(time.RFC3339),
		Iface: o.iface, Verify: o.verify.String(), Adaptive: o.adaptive, Paced: o.pace,
	}
}

// add records one flow's result. err is non-nil when the flow could not run.
func (r *replayReport) add(idx int, f *engine.Flow, target, mode string, res livereplay.Result, err error) {
	fr := flowResult{
		Flow: idx, Client: f.Client.String(), Server: f.Server.String(),
		Target: target, Mode: mode,
	}
	if err != nil {
		fr.Error = err.Error()
		fr.Diagnosis = "flow could not be opened — check the interface, target, and privileges"
	} else {
		out := res.Outcome
		fr.Phase = out.Phase.String()
		fr.Succeeded = out.Succeeded()
		fr.Sent = out.Sent
		fr.Retransmits = out.Retransmits
		fr.RepliesMatched = out.RepliesMatched()
		for _, m := range out.Mismatches {
			fr.Divergences = append(fr.Divergences, m.Detail)
		}
		fr.Diagnosis = diagnose(out, mode)
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
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
