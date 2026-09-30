package qualification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// These are deliberately synthetic validator inputs, not release evidence.
func syntheticLabCadence(version string, cases int) (int, time.Duration) {
	if !UsesStatelessReproduce(version) {
		return 3, time.Hour
	}
	interval := 4 * time.Minute
	if cases == 1 {
		interval = time.Minute
	}
	return int(2*time.Hour/interval) + 1, interval
}

func labValidatorFixture(t *testing.T) (Manifest, ValidateOptions) {
	return labValidatorFixtureVersion(t, "1.0.0")
}

func labValidatorFixtureVersion(t *testing.T, version string) (Manifest, ValidateOptions) {
	t.Helper()
	base := t.TempDir()
	write := func(name string, value any) Evidence {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(base, name)
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		sum, err := FileSHA256(path)
		if err != nil {
			t.Fatal(err)
		}
		return Evidence{Path: name, SHA256: sum}
	}
	proof := write("synthetic-proof.json", "synthetic validator fixture only")
	doc := Manifest{SchemaVersion: 1, Version: version, SourceDigest: "source", Profile: SoftwareLabProfile, SoftwareLab: &SoftwareLab{Limitations: []string{"No physical or human-pilot evidence"}}}
	start := time.Unix(1700000000, 0).UTC()
	for _, platform := range Platforms {
		name := "livewire-" + version + "-" + platform
		if platform == "windows-amd64" {
			name += ".exe"
		}
		if err := os.WriteFile(filepath.Join(base, name), []byte("synthetic executable"), 0600); err != nil {
			t.Fatal(err)
		}
		sum, err := FileSHA256(filepath.Join(base, name))
		if err != nil {
			t.Fatal(err)
		}
		suites := []string{"application"}
		if platform == "linux-amd64" {
			suites = append(suites, "packet")
		}
		for _, suite := range suites {
			for _, command := range []string{"live", "reproduce"} {
				if !labCommandAllowed(version, suite, command) {
					continue
				}
				prefix := platform + "-" + suite + "-" + command
				dir := filepath.Join(base, prefix)
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				run := LabRun{SchemaVersion: 1, Version: doc.Version, SourceDigest: doc.SourceDigest, Platform: platform, Suite: suite, Command: command, BinarySHA256: sum, Environment: "synthetic", Started: start, Finished: start.Add(7201 * time.Second), CleanupVerified: true}
				addEvidence := func(name string, data []byte) Evidence {
					t.Helper()
					path := filepath.Join(dir, name)
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
					sum, err := FileSHA256(path)
					if err != nil {
						t.Fatal(err)
					}
					ref := Evidence{Path: name, SHA256: sum}
					run.Evidence = append(run.Evidence, ref)
					return ref
				}
				var transcript bytes.Buffer
				encoder := json.NewEncoder(&transcript)
				artifact := addEvidence("synthetic.json", []byte(`{"synthetic":"validator fixture only"}`))
				cases := ApplicationLabCasesForVersion(version)
				if suite == "packet" {
					cases = PacketLabCases
				}
				rounds, interval := syntheticLabCadence(version, len(cases))
				spacing := time.Duration(0)
				if UsesStatelessReproduce(version) {
					spacing = interval / time.Duration(len(cases))
				}
				for i, c := range cases {
					first := start.Add(time.Duration(i) * spacing)
					last := first.Add(2 * time.Hour)
					run.Cases = append(run.Cases, LabCaseResult{Name: c, Passes: rounds, FirstAt: first, LastAt: last, RequestsObserved: rounds * 2, ResponsesVerified: rounds * 2, CleanupVerified: true, RepeatedProcessPasses: rounds})
					if c == "tls-handshake" {
						result := &run.Cases[len(run.Cases)-1]
						result.RequestsObserved, result.ResponsesVerified, result.HandshakesObserved = 0, 0, rounds*2
					}
					run.Finished = last.Add(time.Second)
				}
				for round := 1; round <= rounds; round++ {
					for i, c := range cases {
						at := start.Add(time.Duration(round-1)*interval + time.Duration(i)*spacing)
						e := labEvent{Case: c, Command: command, Round: round, Repeat: 2, Started: at, Finished: at, Requests: 2, Responses: 2, CleanupVerified: true}
						if suite == "application" {
							e.Before = labCounts{Requests: (round - 1) * 2, Responses: (round - 1) * 2}
							e.After = labCounts{Requests: round * 2, Responses: round * 2}
							e.VerifiedResponses = 2
							e.Output, e.CLIReport = artifact.Path, artifact.Path
							if UsesStatelessReproduce(version) {
								e.Output = addEvidence(fmt.Sprintf("%s-%d-output.txt", c, round), []byte("synthetic CLI output")).Path
								var reports [][]byte
								if c == "tls-handshake" {
									reports, e.PeerEvents = syntheticTLSHandshakeReports(t, version, e)
									e.Before, e.After = labCounts{}, labCounts{}
									e.VerifiedResponses, e.Requests, e.Responses, e.HandshakesObserved = 0, 0, 0, 2
								} else {
									for _, report := range syntheticApplicationReports(version, e) {
										data, err := json.Marshal(report)
										if err != nil {
											t.Fatal(err)
										}
										reports = append(reports, data)
									}
								}
								for i, data := range reports {
									ref := addEvidence(fmt.Sprintf("%s-%d-report-%d.json", c, round, i), data)
									e.CLIReports = append(e.CLIReports, ref.Path)
								}
								e.CLIReport = e.CLIReports[0]
							}
						} else {
							e.Event = "pass"
							e.Report, e.ReportSHA256 = artifact.Path, artifact.SHA256
							e.IndependentCapture, e.CaptureSHA256 = artifact.Path, artifact.SHA256
							e.Impairment = "synthetic loss"
						}
						if err := encoder.Encode(e); err != nil {
							t.Fatal(err)
						}
					}
				}
				transcriptName := "transcript.jsonl"
				if suite == "packet" {
					transcriptName = "events.jsonl"
					if err := encoder.Encode(labEvent{Event: "cleanup", Verified: true}); err != nil {
						t.Fatal(err)
					}
				}
				addEvidence(transcriptName, transcript.Bytes())
				doc.SoftwareLab.Runs = append(doc.SoftwareLab.Runs, write(prefix+"/run.json", run))
			}
		}
		checks := LabChecks{Platform: platform, SourceDigest: doc.SourceDigest, Checks: map[string]bool{}, Evidence: []Evidence{proof}}
		for _, c := range SoftwareChecks {
			checks.Checks[c] = true
		}
		doc.SoftwareLab.Checks = append(doc.SoftwareLab.Checks, write(platform+"-checks.json", checks))
	}
	if requiresStatelessLab(version) {
		for _, command := range []string{"replay", "reproduce"} {
			if !labCommandAllowed(version, "stateless", command) {
				continue
			}
			frames := statelessTestFrames()
			if UsesStatelessReproduce(version) {
				frames = protocolStatelessTestFrames()
			}
			run, source, _ := statelessValidatorFixtureVersion(t, version, command, frames)
			run.SourceDigest = doc.SourceDigest
			run.BinarySHA256, _ = FileSHA256(filepath.Join(base, "livewire-"+version+"-linux-amd64"))
			prefix := "linux-amd64-stateless-" + command
			if err := os.Mkdir(filepath.Join(base, prefix), 0700); err != nil {
				t.Fatal(err)
			}
			for _, ref := range run.Evidence {
				data, err := os.ReadFile(filepath.Join(source, ref.Path))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(base, prefix, ref.Path), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			doc.SoftwareLab.Runs = append(doc.SoftwareLab.Runs, write(prefix+"/run.json", run))
		}
	}
	return doc, ValidateOptions{Base: base, Version: doc.Version, SourceDigest: doc.SourceDigest, Artifacts: base}
}

func TestSoftwareLabQualificationRequiresBoundedEvidence(t *testing.T) {
	doc, opts := labValidatorFixture(t)
	if errs := Validate(doc, opts); len(errs) != 0 {
		t.Fatal(errs)
	}
	for _, tc := range []struct {
		name   string
		change func(*Manifest)
	}{
		{"missing run", func(d *Manifest) { d.SoftwareLab.Runs = d.SoftwareLab.Runs[1:] }},
		{"duplicate run", func(d *Manifest) { d.SoftwareLab.Runs = append(d.SoftwareLab.Runs, d.SoftwareLab.Runs[0]) }},
		{"physical claim", func(d *Manifest) { d.SoftwareLab.PhysicalQualified = true }},
		{"human claim", func(d *Manifest) { d.SoftwareLab.HumanPilotQualified = true }},
		{"missing limitations", func(d *Manifest) { d.SoftwareLab.Limitations = nil }},
		{"missing checks", func(d *Manifest) { d.SoftwareLab.Checks = nil }},
		{"changed source", func(d *Manifest) { d.SourceDigest = "changed" }},
		{"unknown profile", func(d *Manifest) { d.Profile = "skip" }},
		{"unresolved issue", func(d *Manifest) { d.BlockingFindings = []string{"failure"} }},
		{"no lab", func(d *Manifest) { d.SoftwareLab = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, o := labValidatorFixture(t)
			tc.change(&d)
			if len(Validate(d, o)) == 0 {
				t.Fatal("invalid evidence accepted")
			}
		})
	}
}

func TestSoftwareLabDoesNotTrustPassFlags(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*LabRun)
	}{
		{"short case span", func(r *LabRun) { r.Cases[0].LastAt = r.Cases[0].FirstAt.Add(time.Minute) }},
		{"missing protocol", func(r *LabRun) { r.Cases = r.Cases[1:] }},
		{"no peer check", func(r *LabRun) { r.Cases[0].RequestsObserved = 0 }},
		{"no reply check", func(r *LabRun) { r.Cases[0].ResponsesVerified = 0 }},
		{"failed case", func(r *LabRun) { r.Cases[0].Failures = 1 }},
		{"interrupted", func(r *LabRun) { r.Interrupted = true }},
		{"wrong binary", func(r *LabRun) { r.BinarySHA256 = "wrong" }},
		{"wrong source", func(r *LabRun) { r.SourceDigest = "wrong" }},
		{"missing transcript", func(r *LabRun) { r.Evidence = nil }},
		{"cleanup missing", func(r *LabRun) { r.CleanupVerified = false }},
		{"outside run", func(r *LabRun) { r.Cases[0].LastAt = r.Finished.Add(time.Hour) }},
		{"no repetitions", func(r *LabRun) { r.Cases[0].RepeatedProcessPasses = 0 }},
		{"inflated passes", func(r *LabRun) { r.Cases[0].Passes++ }},
		{"inflated traffic", func(r *LabRun) { r.Cases[0].RequestsObserved++ }},
		{"inflated comparisons", func(r *LabRun) { r.Cases[0].ResponsesVerified++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, o := labValidatorFixture(t)
			ref := &d.SoftwareLab.Runs[0]
			path := filepath.Join(o.Base, ref.Path)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var run LabRun
			if err = json.Unmarshal(data, &run); err != nil {
				t.Fatal(err)
			}
			tc.change(&run)
			data, err = json.Marshal(run)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			ref.SHA256, err = FileSHA256(path)
			if err != nil {
				t.Fatal(err)
			}
			if errs := Validate(d, o); len(errs) == 0 {
				t.Fatal("self-consistent hashes bypassed behavior validation")
			}
		})
	}
}

func TestLabEvidenceCannotEscapeOrChange(t *testing.T) {
	doc, o := labValidatorFixture(t)
	path := filepath.Join(o.Base, doc.SoftwareLab.Runs[0].Path)
	if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if len(Validate(doc, o)) == 0 {
		t.Fatal("changed proof accepted")
	}
	for _, p := range []string{"../outside.json", filepath.Join(o.Base, "synthetic-proof.json"), ""} {
		if _, _, err := verifiedLabEvidence(o.Base, Evidence{Path: p, SHA256: fmt.Sprint(0)}); err == nil {
			t.Fatalf("accepted %q", p)
		}
	}
}

func TestLabTranscriptRejectsMissingProofAndFalseSuccess(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*labEvent)
	}{
		{"peer rejected traffic", func(e *labEvent) { e.After.Errors++ }},
		{"peer socket leaked", func(e *labEvent) { e.After.ActiveConnections++ }},
		{"missing CLI report", func(e *labEvent) { e.CLIReport = "not-retained.json" }},
		{"missing CLI output", func(e *labEvent) { e.Output = "not-retained.txt" }},
		{"failed command", func(e *labEvent) { e.Error = "exit status 1" }},
		{"wrong command", func(e *labEvent) { e.Command = "inspect" }},
		{"reused round", func(e *labEvent) { e.Round = 2 }},
		{"no repeated process", func(e *labEvent) { e.Repeat = 1 }},
		{"no peer replies", func(e *labEvent) { e.After.Responses = e.Before.Responses }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, opts := labValidatorFixture(t)
			path := filepath.Join(opts.Base, doc.SoftwareLab.Runs[0].Path)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var run LabRun
			if err := json.Unmarshal(data, &run); err != nil {
				t.Fatal(err)
			}
			base := filepath.Dir(path)
			for i := range run.Evidence {
				ref := &run.Evidence[i]
				if ref.Path != "transcript.jsonl" {
					continue
				}
				path := filepath.Join(base, ref.Path)
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				lines := bytes.Split(data, []byte{'\n'})
				var event labEvent
				if err := json.Unmarshal(lines[0], &event); err != nil {
					t.Fatal(err)
				}
				tc.change(&event)
				lines[0], err = json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, bytes.Join(lines, []byte{'\n'}), 0600); err != nil {
					t.Fatal(err)
				}
				ref.SHA256, err = FileSHA256(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := validateLabTranscript(run, base); err == nil {
				t.Fatal("hashed invalid transcript accepted")
			}
		})
	}
}
