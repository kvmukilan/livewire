package qualification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLabContinuityRequiresActivityThroughoutSpan(t *testing.T) {
	start := time.Unix(1700000000, 0)
	for _, version := range []string{"1.1.0", "v1.1.0-rc.1", "invalid"} {
		c := LabContinuity{Version: version}
		// A regularly exercised matrix is accepted for a full two-hour span.
		for second := 0; second <= 7200; second += 20 {
			at := start.Add(time.Duration(second) * time.Second)
			if err := c.Observe(fmt.Sprint(second/20%7), at, at.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, test := range []struct {
		name, caseName, want string
		started, finished    time.Duration
	}{
		{"suspend between rounds", "a", "idle gap", time.Hour, time.Hour + time.Second},
		{"suspend inside process", "a", "execution duration", 20 * time.Second, 2 * time.Hour},
		{"clock moves backward", "a", "idle gap", -time.Second, 0},
		{"finish moves backward", "a", "execution duration", 20 * time.Second, 19 * time.Second},
		{"other case out of order", "b", "idle gap", 0, time.Second},
		{"idle boundary exceeded", "a", "idle gap", 61*time.Second + time.Nanosecond, 62 * time.Second},
		{"duration boundary exceeded", "a", "execution duration", 20 * time.Second, 140*time.Second + time.Nanosecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := LabContinuity{Version: "1.1.0"}
			if err := c.Observe("a", start, start.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := c.Observe(test.caseName, start.Add(test.started), start.Add(test.finished)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unexpected continuity result: %v", err)
			}
			// A failed observation must not advance the credited boundary.
			if err := c.Observe("a", start.Add(20*time.Second), start.Add(21*time.Second)); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("case cannot disappear while other cases run", func(t *testing.T) {
		c := LabContinuity{Version: "1.1.0"}
		if err := c.Observe("a", start, start); err != nil {
			t.Fatal(err)
		}
		for second := 60; second <= 300; second += 60 {
			at := start.Add(time.Duration(second) * time.Second)
			if err := c.Observe("b", at, at); err != nil {
				t.Fatal(err)
			}
		}
		if err := c.CheckStart("a", start.Add(300*time.Second+time.Nanosecond)); err == nil || !strings.Contains(err.Error(), "case gap") {
			t.Fatalf("inactive case accepted: %v", err)
		}
		if err := c.Observe("a", start.Add(300*time.Second), start.Add(420*time.Second)); err != nil {
			t.Fatalf("exact documented limits should pass: %v", err)
		}
	})
	for _, version := range []string{"1.0.0", "1.0.1", "v1.0.1-rc.1"} {
		c := LabContinuity{Version: version}
		if err := c.Observe("historical", start, start.Add(8*time.Hour)); err != nil {
			t.Fatalf("historical gate changed: %v", err)
		}
	}
}

func TestLabTranscriptsRejectRehashedSuspendedExecutions(t *testing.T) {
	for _, suite := range []string{"application", "packet", "stateless"} {
		for _, within := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/within-process-%t", suite, within), func(t *testing.T) {
				run, base := applicationTranscriptFixture(t)
				name := "transcript.jsonl"
				if suite == "stateless" {
					run, base, _ = statelessValidatorFixtureVersion(t, "1.1.0", "reproduce", protocolStatelessTestFrames())
					name = "events.jsonl"
				}
				data, err := os.ReadFile(filepath.Join(base, name))
				if err != nil {
					t.Fatal(err)
				}
				lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
				if suite == "packet" {
					run.Suite = "packet"
					for i, line := range lines {
						var e labEvent
						if err := json.Unmarshal(line, &e); err != nil {
							t.Fatal(err)
						}
						e.Event, e.CleanupVerified, e.Requests, e.Responses = "pass", true, 2, 2
						// The outcome tests above separately validate application reports;
						// these existing bound bytes suffice for packet timing validation.
						for _, ref := range run.Evidence {
							if ref.Path == e.CLIReport {
								e.Report, e.ReportSHA256 = ref.Path, ref.SHA256
								e.IndependentCapture, e.CaptureSHA256 = ref.Path, ref.SHA256
							}
						}
						lines[i], _ = json.Marshal(e)
					}
					lines = append(lines, []byte(`{"event":"cleanup","verified":true}`))
					name = "events.jsonl"
					run.Evidence = append(run.Evidence, Evidence{Path: name})
				}
				index := 1
				if within {
					index = 0
				}
				var event map[string]any
				if err := json.Unmarshal(lines[index], &event); err != nil {
					t.Fatal(err)
				}
				later := run.Started.Add(8 * time.Hour)
				event["finished"] = later.Format(time.RFC3339Nano)
				if !within {
					event["started"] = later.Format(time.RFC3339Nano)
				}
				lines[index], _ = json.Marshal(event)
				run.Finished = later.Add(time.Minute)
				path := filepath.Join(base, name)
				if err := os.WriteFile(path, append(bytes.Join(lines, []byte{'\n'}), '\n'), 0600); err != nil {
					t.Fatal(err)
				}
				sum, err := FileSHA256(path)
				if err != nil {
					t.Fatal(err)
				}
				for i := range run.Evidence {
					if run.Evidence[i].Path == name {
						run.Evidence[i].SHA256 = sum
					}
				}
				if err := validateLabTranscript(run, base); err == nil || !strings.Contains(err.Error(), "lab continuity") {
					t.Fatalf("rehashed suspension not independently rejected: %v", err)
				}
			})
		}
	}
}
