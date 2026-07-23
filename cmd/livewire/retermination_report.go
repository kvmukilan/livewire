package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/runvars"
)

// reterminationReport gives TLS and SSH the same auditable report envelope as
// reproduce and lab without ever serializing key logs, private keys, passwords,
// plaintext commands, or response bodies.
type reterminationReport struct {
	Tool            string               `json:"tool"`
	Version         string               `json:"version"`
	When            time.Time            `json:"when"`
	Kind            string               `json:"kind"`
	CaptureDigest   string               `json:"captureDigest"`
	ReplayPlan      replay.ReplayPlan    `json:"replayPlan"`
	AdapterVersions map[string]string    `json:"adapterVersions"`
	Variables       map[string]string    `json:"variables"`
	Target          string               `json:"target"`
	Transformations []string             `json:"transformations"`
	Limitations     []string             `json:"limitations"`
	Outcome         reterminationOutcome `json:"outcome"`
	secretValues    []string
}

type reterminationOutcome struct {
	Completed           bool                `json:"completed"`
	Verified            bool                `json:"verified"`
	Matched             bool                `json:"matched"`
	Adapter             string              `json:"adapter"`
	ProtocolVersion     string              `json:"protocolVersion,omitempty"`
	CipherSuite         string              `json:"cipherSuite,omitempty"`
	ALPN                string              `json:"alpn,omitempty"`
	PeerIdentityChecked bool                `json:"peerIdentityChecked"`
	Requests            int                 `json:"requests"`
	Responses           int                 `json:"responses"`
	Mismatches          int                 `json:"mismatches"`
	Differences         []replay.Difference `json:"differences,omitempty"`
	Commands            []commandEvidence   `json:"commands,omitempty"`
	Error               string              `json:"error,omitempty"`
}

type commandEvidence struct {
	Index        int    `json:"index"`
	OutputBytes  int    `json:"outputBytes"`
	OutputSHA256 string `json:"outputSha256"`
	Matched      bool   `json:"matched"`
}

func newReterminationReport(kind, captureDigest, target string, plan replay.ReplayPlan, registry *replay.Registry, variables map[string]string, secrets ...string) *reterminationReport {
	versions := adapters.Versions()
	if registry != nil {
		versions = adapters.VersionsForRegistry(registry)
	}
	r := &reterminationReport{
		Tool: "livewire", Version: version, When: time.Now().UTC(), Kind: kind,
		CaptureDigest: captureDigest, ReplayPlan: plan, AdapterVersions: versions,
		Variables: runvars.Redacted(variables), Target: target,
		Transformations: []string{}, Limitations: plan.Limitations(),
	}
	if r.Limitations == nil {
		r.Limitations = []string{}
	}
	for name, value := range variables {
		if runvars.IsSecret(name) && value != "" {
			r.secretValues = append(r.secretValues, value)
		}
	}
	for _, value := range secrets {
		if value != "" {
			r.secretValues = append(r.secretValues, value)
		}
	}
	return r
}

func (r *reterminationReport) write(path string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	for _, secret := range r.secretValues {
		b = []byte(strings.ReplaceAll(string(b), secret, "[REDACTED]"))
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// buildReterminationPlan accounts for the entire input capture. Only the
// selected encrypted session is executable by the specialized command; every
// other lane is explicit and blocked instead of being silently discarded.
func buildReterminationPlan(trace *replay.Trace, selected *replay.Session, adapter, driver string) replay.ReplayPlan {
	plan := replay.ReplayPlan{Profile: replay.ProfileFunctional, Packets: trace.Packets}
	for _, session := range trace.Sessions {
		entry := replay.PlanEntry{
			SessionID: session.ID, Transport: session.Transport,
			PacketIndexes: reterminationPacketIndexes(session.Events),
			Warnings:      append([]string(nil), session.Warnings...),
		}
		if session == selected {
			entry.Driver, entry.Adapter = driver, adapter
			entry.Mode, entry.Fidelity = replay.ModeSemantic, replay.FidelitySemantic
			entry.Transformations = []string{"captured encrypted transport replaced by a fresh authenticated connection", "application operations replayed through " + adapter}
			entry.Blockers = append(entry.Blockers, session.Blockers...)
			if reterminationEventsTruncated(session.Events) {
				entry.Blockers = append(entry.Blockers, "capture contains snaplen-truncated frames; encrypted stream reconstruction is incomplete")
			}
			if len(entry.Blockers) > 0 {
				entry.Driver, entry.Mode, entry.Fidelity = "none", replay.ModeBlocked, replay.FidelityBlocked
			}
		} else {
			entry.Driver, entry.Mode, entry.Fidelity = "none", replay.ModeBlocked, replay.FidelityBlocked
			entry.Blockers = []string{fmt.Sprintf("%s executes only the selected encrypted session; use reproduce or lab for this lane", driver)}
		}
		plan.Entries = append(plan.Entries, entry)
	}
	if len(trace.Raw) > 0 {
		plan.Entries = append(plan.Entries, replay.PlanEntry{
			SessionID: "raw-0", Transport: replay.TransportRaw, Driver: "none",
			Mode: replay.ModeBlocked, Fidelity: replay.FidelityBlocked,
			PacketIndexes: reterminationPacketIndexes(trace.Raw),
			Blockers:      []string{fmt.Sprintf("%s does not execute the capture's raw frame lane; use explicit wire replay or lab", driver)},
		})
	}
	return plan
}

func reterminationPacketIndexes(events []replay.Event) []int {
	out := make([]int, len(events))
	for i := range events {
		out[i] = events[i].PacketIndex
	}
	sort.Ints(out)
	return out
}

func reterminationEventsTruncated(events []replay.Event) bool {
	for _, event := range events {
		if event.Record != nil && event.Record.OrigLen > 0 && (event.Record.CapLen < event.Record.OrigLen || len(event.Record.Data) < event.Record.OrigLen) {
			return true
		}
	}
	return false
}
