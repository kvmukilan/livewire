package qualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Synthetic validator inputs only; these do not qualify a binary or network.
func syntheticApplicationReports(version string, event labEvent) []applicationLabReport {
	kind, adapter := applicationLabProtocol(event.Case)
	outcome := applicationLabOutcome{Adapter: adapter, Status: "matched", Completed: true, Verified: true, Matched: true, Compared: 1, Responses: 1, PeerIdentityChecked: true, Cleanup: "complete"}
	if kind == "ftp" {
		body := []byte("livewire software-lab transfer\x00\x01\xff\n")
		digest := fmt.Sprintf("sha256:%x", sha256.Sum256(body))
		for _, command := range []string{"RETR", "STOR"} {
			outcome.Transfers = append(outcome.Transfers, applicationLabTransfer{Command: command, ExpectedBytes: len(body), ActualBytes: len(body), ExpectedSHA256: digest, ActualSHA256: digest, Matched: true})
		}
	}
	report := applicationLabReport{Tool: "livewire", Version: version, Kind: kind, When: event.Started}
	if kind == "" {
		report.Intent, report.Attempts = "application", event.Repeat
		for i := 1; i <= event.Repeat; i++ {
			outcome.Attempt, outcome.Mode = i, "semantic"
			report.Sessions = append(report.Sessions, outcome)
		}
		return []applicationLabReport{report}
	}
	report.Outcome = outcome
	var reports []applicationLabReport
	for i := 0; i < event.Repeat; i++ {
		reports = append(reports, report)
	}
	return reports
}

func TestApplicationReportsIndependentlyRequireLiveSuccess(t *testing.T) {
	for _, tc := range []struct {
		name, fixture string
		change        func(*applicationLabReport)
	}{
		{"wire", "http1", func(r *applicationLabReport) { r.Sessions[0].Mode = "wire"; r.Sessions[0].Verified = false }},
		{"wire disguised verified", "http1", func(r *applicationLabReport) { r.Sessions[0].Mode = "wire" }},
		{"unmatched", "http1", func(r *applicationLabReport) { r.Sessions[0].Matched = false }},
		{"incomplete", "http1", func(r *applicationLabReport) { r.Sessions[0].Completed = false }},
		{"error", "http1", func(r *applicationLabReport) { r.Sessions[0].Error = "peer reset" }},
		{"cleanup", "http1", func(r *applicationLabReport) { r.Sessions[0].Cleanup = "failed" }},
		{"no comparison", "http1", func(r *applicationLabReport) { r.Sessions[0].Compared = 0 }},
		{"inflated comparison", "http1", func(r *applicationLabReport) { r.Sessions[0].Compared++ }},
		{"version", "http1", func(r *applicationLabReport) { r.Version = "1.0.1" }},
		{"reused report time", "http1", func(r *applicationLabReport) { r.When = r.When.Add(-time.Hour) }},
		{"duplicate attempt", "http1", func(r *applicationLabReport) { r.Sessions[1].Attempt = 1 }},
		{"attempt count", "http1", func(r *applicationLabReport) { r.Attempts-- }},
		{"wrong kind", "http1-tls", func(r *applicationLabReport) { r.Kind = "ssh" }},
		{"wrong adapter", "http1-tls", func(r *applicationLabReport) { r.Outcome.Adapter = "mqtt" }},
		{"TLS identity", "http1-tls", func(r *applicationLabReport) { r.Outcome.PeerIdentityChecked = false }},
		{"SSH identity", "ssh", func(r *applicationLabReport) { r.Outcome.PeerIdentityChecked = false }},
		{"FTPS identity", "ftps-explicit", func(r *applicationLabReport) { r.Outcome.PeerIdentityChecked = false }},
		{"FTP transfer missing", "ftp", func(r *applicationLabReport) { r.Outcome.Transfers = r.Outcome.Transfers[:1] }},
		{"FTP transfer hash", "ftp", func(r *applicationLabReport) { r.Outcome.Transfers[0].ActualSHA256 = "wrong" }},
		{"FTP duplicate direction", "ftp", func(r *applicationLabReport) { r.Outcome.Transfers[0].Command = "STOR" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := labEvent{Case: tc.fixture, Repeat: 2, VerifiedResponses: 2, Started: time.Now(), Finished: time.Now()}
			reports := syntheticApplicationReports("1.1.0", event)
			encode := func() [][]byte {
				var data [][]byte
				for _, report := range reports {
					b, err := json.Marshal(report)
					if err != nil {
						t.Fatal(err)
					}
					data = append(data, b)
				}
				return data
			}
			if err := validateApplicationCLIReports("1.1.0", event, encode()); err != nil {
				t.Fatal(err)
			}
			tc.change(&reports[0])
			if err := validateApplicationCLIReports("1.1.0", event, encode()); err == nil {
				t.Fatal("invalid report accepted")
			}
		})
	}
}

func TestApplicationTranscriptRejectsRehashedReportsAndReuse(t *testing.T) {
	for _, mutation := range []string{"malformed", "wire", "reuse-report", "reuse-output", "missing-secure-attempt"} {
		t.Run(mutation, func(t *testing.T) {
			doc, options := labValidatorFixtureVersion(t, "1.1.0")
			data, path, err := verifiedLabEvidence(options.Base, doc.SoftwareLab.Runs[0])
			if err != nil {
				t.Fatal(err)
			}
			var run LabRun
			if err := json.Unmarshal(data, &run); err != nil {
				t.Fatal(err)
			}
			base := filepath.Dir(path)
			data, err = os.ReadFile(filepath.Join(base, "transcript.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			var events []labEvent
			for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
				var e labEvent
				if err := json.Unmarshal(line, &e); err != nil {
					t.Fatal(err)
				}
				events = append(events, e)
			}
			replace := func(name string, data []byte) {
				file := filepath.Join(base, name)
				if err := os.WriteFile(file, data, 0600); err != nil {
					t.Fatal(err)
				}
				sum, err := FileSHA256(file)
				if err != nil {
					t.Fatal(err)
				}
				for i := range run.Evidence {
					if run.Evidence[i].Path == name {
						run.Evidence[i].SHA256 = sum
						return
					}
				}
				t.Fatal("missing evidence")
			}
			switch mutation {
			case "malformed":
				replace(events[0].CLIReports[0], []byte("{broken"))
			case "wire":
				replace(events[0].CLIReports[0], []byte(`{"tool":"livewire","version":"1.1.0","mode":"wire","verified":false}`))
			case "reuse-report":
				events[1].CLIReports, events[1].CLIReport = events[0].CLIReports, events[0].CLIReport
			case "reuse-output":
				events[1].Output = events[0].Output
			case "missing-secure-attempt":
				for i := range events {
					if strings.HasSuffix(events[i].Case, "-tls") {
						events[i].CLIReports = events[i].CLIReports[:1]
						break
					}
				}
			}
			var transcript bytes.Buffer
			for _, e := range events {
				if err := json.NewEncoder(&transcript).Encode(e); err != nil {
					t.Fatal(err)
				}
			}
			replace("transcript.jsonl", transcript.Bytes())
			if err := validateLabTranscript(run, base); err == nil {
				t.Fatal("rehashed invalid report accepted")
			}
		})
	}
}

func TestStatelessExperimentalEtherTypeCannotBeKnownProtocol(t *testing.T) {
	for _, etherType := range []uint16{0x0806, 0x8100, 0x88a8} {
		frames := protocolStatelessTestFrames()
		frames[len(frames)-1][12], frames[len(frames)-1][13] = byte(etherType>>8), byte(etherType)
		if err := validateStatelessProtocolCoverage(encodeStatelessTestCapture(t, frames)); err == nil || !strings.Contains(err.Error(), "unknown-ether-type") {
			t.Fatalf("known EtherType accepted: %x, %v", etherType, err)
		}
	}
}

func TestRecordedApplicationLabTranscript(t *testing.T) {
	base := os.Getenv("LIVEWIRE_APPLICATION_LAB_SMOKE")
	if base == "" {
		t.Skip("set LIVEWIRE_APPLICATION_LAB_SMOKE to a recorded application lab directory")
	}
	data, err := os.ReadFile(filepath.Join(base, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var run LabRun
	if err := json.Unmarshal(data, &run); err != nil {
		t.Fatal(err)
	}
	if run.Suite != "application" {
		t.Fatal("unexpected application run identity")
	}
	if err := validateLabTranscript(run, base); err != nil {
		t.Fatal(err)
	}
	t.Logf("validated %s/%s: %d cases", run.Platform, run.Command, len(run.Cases))
}
