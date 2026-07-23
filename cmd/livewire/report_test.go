package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
)

func TestDiagnose(t *testing.T) {
	cases := []struct {
		name string
		out  engine.Outcome
		mode string
		want string // substring expected ("" = empty diagnosis)
	}{
		{"faithful", engine.Outcome{Phase: engine.PhaseClosed}, "stateful", ""},
		{"answered-differently",
			engine.Outcome{Phase: engine.PhaseClosed, Mismatches: []engine.Mismatch{{Structural: true}}, ReplyMismatches: 1},
			"stateful", "differently"},
		{"reset", engine.Outcome{Phase: engine.PhaseAborted, Aborted: true, Reason: "peer sent RST"}, "stateful", "reset"},
		{"stalled", engine.Outcome{Phase: engine.PhaseAborted, Aborted: true, Reason: "stalled in phase established"}, "stateful", "stopped responding"},
		{"stateless", engine.Outcome{Phase: engine.PhaseClosed}, "stateless", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := diagnose(tc.out, tc.mode)
			if tc.want == "" {
				if got != "" {
					t.Fatalf("expected no diagnosis, got %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("diagnosis %q does not contain %q", got, tc.want)
			}
		})
	}
}

func TestReplayReportRedactsSecrets(t *testing.T) {
	secret := "super-secret-value"
	r := newReplayReport(liveOpts{variables: map[string]string{
		"mqtt.password": secret,
		"http.host":     "device.local",
	}})
	// Exercise defense in depth: even if a downstream error accidentally
	// includes a supplied credential, write must scrub it.
	r.Sessions = append(r.Sessions, sessionResult{Error: "authentication failed for " + secret})
	path := filepath.Join(t.TempDir(), "report.json")
	if err := r.write(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if strings.Contains(text, secret) || !strings.Contains(text, "[REDACTED]") || !strings.Contains(text, "device.local") {
		t.Fatalf("report redaction failed: %s", text)
	}
}

func TestRedactRunText(t *testing.T) {
	got := redactRunText("login operator with hunter2 at lab", map[string]string{
		"mqtt.username": "operator", "mqtt.password": "hunter2", "site": "lab",
	})
	if strings.Contains(got, "operator") || strings.Contains(got, "hunter2") || !strings.Contains(got, "lab") {
		t.Fatalf("runtime redaction=%q", got)
	}
}

func TestSetFlagsStringRedactsSecrets(t *testing.T) {
	flags := setFlags{"mqtt.username": "operator", "mqtt.password": "hunter2", "site": "lab"}
	got := flags.String()
	if strings.Contains(got, "operator") || strings.Contains(got, "hunter2") || !strings.Contains(got, "site=lab") {
		t.Fatalf("flag string leaked a secret: %q", got)
	}
}

func TestReterminationPlanAccountsForEveryPacket(t *testing.T) {
	selected := &replay.Session{ID: "tcp-0", Transport: replay.TransportTCP, Events: []replay.Event{{PacketIndex: 0}, {PacketIndex: 2}}}
	other := &replay.Session{ID: "udp-0", Transport: replay.TransportUDP, Events: []replay.Event{{PacketIndex: 1}}}
	trace := &replay.Trace{Packets: 4, Sessions: []*replay.Session{selected, other}, Raw: []replay.Event{{PacketIndex: 3}}}
	plan := buildReterminationPlan(trace, selected, "tls-reterminate", "tls-reterminate")
	if err := plan.ValidateCoverage(); err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if len(plan.Entries) != 3 || plan.Entries[0].Mode != replay.ModeSemantic || plan.Entries[1].Mode != replay.ModeBlocked || plan.Entries[2].Mode != replay.ModeBlocked {
		t.Fatalf("unexpected specialized plan: %+v", plan.Entries)
	}
	if len(plan.Entries[1].Blockers) == 0 || len(plan.Entries[2].Blockers) == 0 {
		t.Fatalf("non-selected lanes must be explicit blockers: %+v", plan.Entries)
	}
}

func TestReterminationPlanBlocksTruncatedSelectedSession(t *testing.T) {
	record := &pcapio.Record{Data: []byte{1, 2}, CapLen: 2, OrigLen: 10}
	selected := &replay.Session{ID: "tcp-0", Transport: replay.TransportTCP, Events: []replay.Event{{PacketIndex: 0, Record: record}}}
	plan := buildReterminationPlan(&replay.Trace{Packets: 1, Sessions: []*replay.Session{selected}}, selected, "ssh-reterminate", "ssh-reterminate")
	if plan.Entries[0].Mode != replay.ModeBlocked || len(plan.Entries[0].Blockers) == 0 {
		t.Fatalf("truncated encrypted session should be blocked: %+v", plan.Entries[0])
	}
}

func TestReterminationReportRedactsCredentialsAndCarriesReleaseEvidence(t *testing.T) {
	secret := "Bearer-super-secret"
	plan := replay.ReplayPlan{Profile: replay.ProfileFunctional, Packets: 1, Entries: []replay.PlanEntry{{SessionID: "tcp-0", Transport: replay.TransportTCP, Driver: "tls-reterminate", Adapter: "tls-reterminate", Mode: replay.ModeSemantic, Fidelity: replay.FidelitySemantic, PacketIndexes: []int{0}}}}
	report := newReterminationReport("tls", "sha256:capture", "device.example:443", plan, nil, map[string]string{"Authorization": secret, "http.host": "device.example"}, secret)
	report.Outcome = reterminationOutcome{Completed: false, Adapter: "http/1", Error: "server echoed " + secret}
	path := filepath.Join(t.TempDir(), "tls.report.json")
	if err := report.write(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), secret) || !strings.Contains(string(b), "[REDACTED]") {
		t.Fatalf("credential leaked from retermination report: %s", b)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"captureDigest", "replayPlan", "adapterVersions", "variables", "transformations", "limitations", "outcome"} {
		if _, ok := doc[field]; !ok {
			t.Fatalf("report missing %s: %s", field, b)
		}
	}
}
