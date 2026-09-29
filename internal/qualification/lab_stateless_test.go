package qualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

func statelessTestFrames() [][]byte {
	frames := make([][]byte, 6)
	for i := range frames {
		b := make([]byte, 80)
		copy(b, []byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2})
		b[12], b[13], b[14], b[23] = 8, 0, 0x45, 6
		b[46], b[79] = 0x50, byte(i)
		frames[i] = b
	}
	frames[0][54], frames[0][55] = 23, 3 // opaque TLS record bytes
	copy(frames[1][:12], []byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1})
	frames[2][23], frames[3][23] = 17, 1
	frames[4][12], frames[4][13], frames[4][20] = 0x86, 0xdd, 58
	frames[5][12], frames[5][13] = 0x88, 0xb5
	return frames
}

func encodeStatelessTestCapture(t *testing.T, frames [][]byte, at ...time.Time) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := pcapio.NewWriter(&out, wire.LinkEthernet, false)
	if err != nil {
		t.Fatal(err)
	}
	when := time.Unix(1700000000, 0)
	if len(at) > 0 {
		when = at[0]
	}
	for _, frame := range frames {
		if err := w.Write(&pcapio.Record{Time: when, CapLen: len(frame), OrigLen: len(frame), Data: frame, LinkType: wire.LinkEthernet}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func statelessValidatorFixture(t *testing.T) (LabRun, string, func(string, []byte) Evidence) {
	t.Helper()
	base := t.TempDir()
	start := time.Unix(1700000000, 0).UTC()
	run := LabRun{SchemaVersion: 1, Version: "1.0.1", Suite: "stateless", Platform: "linux-amd64", Command: "replay", Environment: "synthetic gate test only", Started: start, Finished: start.Add(7201 * time.Second), CleanupVerified: true}
	write := func(name string, data []byte) Evidence {
		t.Helper()
		if err := os.WriteFile(filepath.Join(base, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		return Evidence{Path: name, SHA256: fmt.Sprintf("%x", sha256.Sum256(data))}
	}
	frames := statelessTestFrames()
	fixture := write("mixed.pcap", encodeStatelessTestCapture(t, frames))
	run.Evidence = []Evidence{fixture}
	var transcript bytes.Buffer
	for round := 1; round <= 3; round++ {
		at := start.Add(time.Duration(round-1) * time.Hour)
		prefix := ""
		if round > 1 {
			prefix = fmt.Sprintf("round-%d-", round)
		}
		actual := write(prefix+"actual.pcap", encodeStatelessTestCapture(t, append(append([][]byte{}, frames...), frames...), at))
		output := write(prefix+"output.txt", []byte("synthetic output"))
		firewall := write(prefix+"firewall.txt", []byte("# empty owned-namespace firewall\n"))
		report := write(prefix+"report.json", []byte(fmt.Sprintf(`{"tool":"livewire","version":"1.0.1","mode":"wire","status":"wire","completed":true,"verified":false,"passes":2,"framesPerPass":6,"framesSent":12,"captureDigest":"sha256:%s"}`, fixture.SHA256)))
		run.Evidence = append(run.Evidence, actual, output, firewall, report)
		e := statelessLabEvent{labEvent: labEvent{Event: "pass", Case: "mixed-frames", Command: "replay", Round: round, Repeat: 2, Started: at, Finished: at, CleanupVerified: true, IndependentCapture: actual.Path, CaptureSHA256: actual.SHA256, Report: report.Path, ReportSHA256: report.SHA256, Output: output.Path}, Fixture: fixture.Path, FixtureSHA256: fixture.SHA256, FramesObserved: 12, Firewall: firewall.Path, FirewallSHA256: firewall.SHA256}
		if err := json.NewEncoder(&transcript).Encode(e); err != nil {
			t.Fatal(err)
		}
	}
	transcript.WriteString("{\"event\":\"cleanup\",\"verified\":true}\n")
	run.Cases = []LabCaseResult{{Name: "mixed-frames", Passes: 3, RepeatedProcessPasses: 3, FirstAt: start, LastAt: start.Add(7200 * time.Second), CleanupVerified: true, FramesObserved: 36}}
	run.Evidence = append(run.Evidence, write("events.jsonl", transcript.Bytes()))
	return run, base, write
}

func TestStatelessTranscriptRequiresExactFramesAndHonestOutcome(t *testing.T) {
	for _, mutation := range []string{"valid", "frame-byte", "frame-order", "missing-frame", "extra-frame", "missing-protocol", "verified-claim", "missing-verified", "wrong-count", "wrong-source", "wrong-version", "missing-output", "missing-cleanup", "failed-event", "inflated-summary", "response-claim", "old-timestamps", "reused-capture", "reused-report", "reused-output", "missing-firewall", "guard-leak"} {
		t.Run(mutation, func(t *testing.T) {
			run, base, write := statelessValidatorFixture(t)
			change := func(name string, data []byte) {
				t.Helper()
				ref := write(name, data)
				var old string
				for i := range run.Evidence {
					if run.Evidence[i].Path == name {
						old, run.Evidence[i] = run.Evidence[i].SHA256, ref
					}
				}
				if name != "events.jsonl" {
					data, err := os.ReadFile(filepath.Join(base, "events.jsonl"))
					if err != nil {
						t.Fatal(err)
					}
					ref = write("events.jsonl", bytes.ReplaceAll(data, []byte(old), []byte(ref.SHA256)))
					for i := range run.Evidence {
						if run.Evidence[i].Path == ref.Path {
							run.Evidence[i] = ref
						}
					}
				}
			}
			read := func(name string) []byte {
				t.Helper()
				data, err := os.ReadFile(filepath.Join(base, name))
				if err != nil {
					t.Fatal(err)
				}
				return data
			}
			switch mutation {
			case "frame-byte", "frame-order", "missing-frame", "extra-frame":
				frames := statelessTestFrames()
				frames = append(frames, statelessTestFrames()...)
				switch mutation {
				case "frame-byte":
					frames[0][79] ^= 1
				case "frame-order":
					frames[0], frames[1] = frames[1], frames[0]
				case "missing-frame":
					frames = frames[:len(frames)-1]
				case "extra-frame":
					frames = append(frames, frames[0])
				}
				change("actual.pcap", encodeStatelessTestCapture(t, frames))
			case "missing-protocol":
				frames := statelessTestFrames()
				binary.BigEndian.PutUint16(frames[5][12:14], 0x0800)
				change("mixed.pcap", encodeStatelessTestCapture(t, frames))
				change("actual.pcap", encodeStatelessTestCapture(t, append(frames, frames...)))
			case "verified-claim":
				change("report.json", bytes.ReplaceAll(read("report.json"), []byte(`"verified":false`), []byte(`"verified":true`)))
			case "missing-verified":
				change("report.json", bytes.ReplaceAll(read("report.json"), []byte(`"verified":false,`), nil))
			case "wrong-count":
				change("report.json", bytes.ReplaceAll(read("report.json"), []byte(`"framesSent":12`), []byte(`"framesSent":11`)))
			case "wrong-source":
				change("report.json", bytes.ReplaceAll(read("report.json"), []byte(`"sha256:`), []byte(`"sha256:wrong`)))
			case "wrong-version":
				change("report.json", bytes.ReplaceAll(read("report.json"), []byte(`1.0.1`), []byte(`1.0.0`)))
			case "missing-output":
				change("events.jsonl", bytes.ReplaceAll(read("events.jsonl"), []byte(`output.txt`), []byte(`missing.txt`)))
			case "missing-cleanup":
				change("events.jsonl", bytes.ReplaceAll(read("events.jsonl"), []byte("{\"event\":\"cleanup\",\"verified\":true}\n"), nil))
			case "failed-event":
				change("events.jsonl", bytes.ReplaceAll(read("events.jsonl"), []byte(`"event":"pass"`), []byte(`"event":"failure"`)))
			case "inflated-summary":
				run.Cases[0].FramesObserved++
			case "response-claim":
				run.Cases[0].ResponsesVerified++
			case "old-timestamps":
				frames := statelessTestFrames()
				change("round-2-actual.pcap", encodeStatelessTestCapture(t, append(frames, frames...)))
			case "reused-capture", "reused-report", "reused-output":
				kind := map[string]string{"reused-capture": "actual.pcap", "reused-report": "report.json", "reused-output": "output.txt"}[mutation]
				data := read("events.jsonl")
				data = bytes.ReplaceAll(data, []byte("round-2-"+kind), []byte(kind))
				if mutation == "reused-capture" {
					data = bytes.ReplaceAll(data, []byte(fmt.Sprintf("%x", sha256.Sum256(read("round-2-actual.pcap")))), []byte(fmt.Sprintf("%x", sha256.Sum256(read("actual.pcap")))))
				}
				change("events.jsonl", data)
			case "missing-firewall":
				for i, ref := range run.Evidence {
					if ref.Path == "firewall.txt" {
						run.Evidence = append(run.Evidence[:i], run.Evidence[i+1:]...)
						break
					}
				}
			case "guard-leak":
				change("firewall.txt", []byte("-A OUTPUT -p tcp --tcp-flags RST RST -j DROP\n"))
			}
			err := validateLabTranscript(run, base)
			if (mutation == "valid") != (err == nil) {
				t.Fatalf("mutation=%s err=%v", mutation, err)
			}
		})
	}
}

func TestStatelessRequirementPreservesHistoricalQualification(t *testing.T) {
	for version, want := range map[string]bool{"0.9.0": false, "1.0.0": false, "v1.0.0": false, "1.0.1": true, "1.0.1-rc.1": true, "1.1.0": true, "2.0.0": true, "invalid": true} {
		if requiresStatelessLab(version) != want {
			t.Errorf("version %s requirement differs", version)
		}
	}
	doc, options := labValidatorFixture(t)
	if errs := Validate(doc, options); len(errs) != 0 {
		t.Fatal("historical six-run evidence rejected", errs)
	}
	doc.Version, options.Version = "1.0.1", "1.0.1"
	if errs := strings.Join(Validate(doc, options), "\n"); !strings.Contains(errs, "missing lab run: linux-amd64/stateless/replay") {
		t.Fatal("new release did not require stateless evidence", errs)
	}
}

func TestRecordedStatelessLabTranscript(t *testing.T) {
	base := os.Getenv("LIVEWIRE_STATELESS_LAB_SMOKE")
	if base == "" {
		t.Skip("set LIVEWIRE_STATELESS_LAB_SMOKE to a recorded stateless lab directory")
	}
	data, err := os.ReadFile(filepath.Join(base, "replay.run.json"))
	if err != nil {
		t.Fatal(err)
	}
	var run LabRun
	if err := json.Unmarshal(data, &run); err != nil {
		t.Fatal(err)
	}
	if run.Suite != "stateless" {
		t.Fatal("not a stateless lab run")
	}
	if err := validateLabTranscript(run, base); err != nil {
		t.Fatal(err)
	}
	t.Logf("validated stateless replay: %d passes, %d observed frames", run.Cases[0].Passes, run.Cases[0].FramesObserved)
}
