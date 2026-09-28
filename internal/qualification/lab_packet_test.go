package qualification

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These inputs exercise the gate, not the network lab. Every mutation gets a
// fresh transcript hash so a checksum alone cannot hide missing observations.
func TestPacketTranscriptRejectsIncompleteObservations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*LabRun, *[]labEvent)
	}{
		{"missing cleanup", func(_ *LabRun, events *[]labEvent) { *events = (*events)[:len(*events)-1] }},
		{"failed cleanup", func(_ *LabRun, events *[]labEvent) { (*events)[len(*events)-1].Verified = false }},
		{"execution after cleanup", func(_ *LabRun, events *[]labEvent) { *events = append(*events, (*events)[0]) }},
		{"unknown packet command", func(_ *LabRun, events *[]labEvent) {
			extra := (*events)[0]
			extra.Command = "unknown-command"
			cleanup := (*events)[len(*events)-1]
			*events = append((*events)[:len(*events)-1], extra, cleanup)
		}},
		{"failed execution", func(_ *LabRun, events *[]labEvent) { (*events)[0].Event = "failure" }},
		{"missing per-process cleanup", func(_ *LabRun, events *[]labEvent) { (*events)[0].CleanupVerified = false }},
		{"single CLI iteration", func(_ *LabRun, events *[]labEvent) { (*events)[0].Repeat = 1 }},
		{"missing requests", func(_ *LabRun, events *[]labEvent) { (*events)[0].Requests = 0 }},
		{"missing responses", func(_ *LabRun, events *[]labEvent) { (*events)[0].Responses = 0 }},
		{"skipped round", func(_ *LabRun, events *[]labEvent) { (*events)[0].Round = 2 }},
		{"execution outside run", func(r *LabRun, events *[]labEvent) { (*events)[0].Finished = r.Finished.Add(1) }},
		{"unbound capture", func(_ *LabRun, events *[]labEvent) { (*events)[0].IndependentCapture = "missing.pcap" }},
		{"unbound CLI report", func(_ *LabRun, events *[]labEvent) { (*events)[0].Report = "missing.report.json" }},
		{"changed capture binding", func(_ *LabRun, events *[]labEvent) { (*events)[0].CaptureSHA256 = strings.Repeat("0", 64) }},
		{"missing report digest", func(_ *LabRun, events *[]labEvent) { (*events)[0].ReportSHA256 = "" }},
		{"missing TCP loss exercise", func(_ *LabRun, events *[]labEvent) {
			for i := range *events {
				if (*events)[i].Case == "stateful-tcp" {
					(*events)[i].Impairment = "none"
				}
			}
		}},
		{"inflated pass summary", func(r *LabRun, _ *[]labEvent) { r.Cases[0].Passes++ }},
		{"inflated traffic summary", func(r *LabRun, _ *[]labEvent) { r.Cases[0].RequestsObserved++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, options := labValidatorFixture(t)
			var run LabRun
			var base string
			for _, ref := range doc.SoftwareLab.Runs {
				data, path, err := verifiedLabEvidence(options.Base, ref)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(data, &run); err != nil {
					t.Fatal(err)
				}
				if run.Suite == "packet" && run.Command == "live" {
					base = filepath.Dir(path)
					break
				}
			}
			if base == "" {
				t.Fatal("packet validator fixture missing")
			}
			if err := validateLabTranscript(run, base); err != nil {
				t.Fatalf("valid packet fixture rejected: %v", err)
			}
			path := filepath.Join(base, "events.jsonl")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var events []labEvent
			for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
				var event labEvent
				if err := json.Unmarshal(line, &event); err != nil {
					t.Fatal(err)
				}
				events = append(events, event)
			}
			tc.change(&run, &events)
			var encoded bytes.Buffer
			for _, event := range events {
				if err := json.NewEncoder(&encoded).Encode(event); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, encoded.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			sum, err := FileSHA256(path)
			if err != nil {
				t.Fatal(err)
			}
			for i := range run.Evidence {
				if run.Evidence[i].Path == "events.jsonl" {
					run.Evidence[i].SHA256 = sum
				}
			}
			if err := validateLabTranscript(run, base); err == nil {
				t.Fatal("invalid packet observations accepted after rehashing")
			}
		})
	}
}

// An opt-in read-only check of existing packet lab output. A short smoke can
// validate schema/integrity here; it still fails the separate two-hour gate.
func TestRecordedPacketLabTranscript(t *testing.T) {
	base := os.Getenv("LIVEWIRE_PACKET_LAB_SMOKE")
	if base == "" {
		t.Skip("set LIVEWIRE_PACKET_LAB_SMOKE to a recorded packet lab directory")
	}
	for _, command := range []string{"live", "reproduce"} {
		t.Run(command, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(base, command+".run.json"))
			if err != nil {
				t.Fatal(err)
			}
			var run LabRun
			if err := json.Unmarshal(data, &run); err != nil {
				t.Fatal(err)
			}
			if run.Suite != "packet" || run.Command != command {
				t.Fatal("unexpected packet run identity")
			}
			for _, ref := range run.Evidence {
				if _, _, err := verifiedLabEvidence(base, ref); err != nil {
					t.Fatal(err)
				}
			}
			if err := validateLabTranscript(run, base); err != nil {
				t.Fatal(err)
			}
			t.Logf("validated %s: %d cases, %d hashed artifacts", command, len(run.Cases), len(run.Evidence))
		})
	}
}
