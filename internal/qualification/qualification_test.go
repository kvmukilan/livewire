package qualification

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestHelperProcess is the child process the Record and Soak tests execute.
// It is a no-op unless the helper environment variable selects a behavior.
func TestHelperProcess(t *testing.T) {
	switch os.Getenv("LIVEWIRE_QUALIFICATION_HELPER") {
	case "exit3":
		os.Exit(3)
	case "sleep":
		time.Sleep(5 * time.Second)
		os.Exit(0)
	case "pass":
		os.Exit(0)
	}
}

func helperArgv(t *testing.T, behavior string) []string {
	t.Helper()
	t.Setenv("LIVEWIRE_QUALIFICATION_HELPER", behavior)
	return []string{os.Args[0], "-test.run=^TestHelperProcess$"}
}

type fixture struct {
	base     string
	evidence []Evidence
	doc      Manifest
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	base := t.TempDir()
	proof := filepath.Join(base, "proof.txt")
	if err := os.WriteFile(proof, []byte("Synthetic validator fixture; not actual qualification"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum, err := FileSHA256(proof)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{base: base, evidence: []Evidence{{Path: "proof.txt", SHA256: sum}}}
	doc := Template("test")
	doc.Version = "0.9.0" // Preserve the historical physical-profile fixture.
	doc.BlockingFindings = []string{}
	cancel := 0.1
	for name, p := range doc.Platforms {
		p.OS, p.Driver, p.NIC, p.DUT, p.Firmware, p.BinarySHA256 = "test", "test", "test", "test", "test", "test"
		for _, scenario := range Scenarios {
			runs := make([]ScenarioRun, 3)
			for i := range runs {
				c := cancel
				runs[i] = ScenarioRun{Passed: true, CleanupVerified: true, ExpectedResult: "expected", ObservedResult: "observed", CancelSeconds: &c, Evidence: f.evidence}
			}
			p.Scenarios[scenario] = runs
		}
		p.Soak = SoakRecord{Seconds: SoakSeconds, Passed: true, CleanupVerified: true, Evidence: f.evidence}
		p.CommandSoaks = map[string]SoakRecord{"reproduce": p.Soak, "live": p.Soak}
		p.Combinations = []string{"synthetic HTTP/1.1 fixture"}
		doc.Platforms[name] = p
	}
	doc.Browser = Browser{BrowserVersion: "test", Checks: map[string]bool{}, Evidence: f.evidence}
	for _, c := range BrowserChecks {
		doc.Browser.Checks[c] = true
	}
	for _, c := range BenchmarkCases {
		doc.Benchmarks = append(doc.Benchmarks, Benchmark{Case: c, Passed: true, Evidence: f.evidence})
	}
	for i := 0; i < PilotEngineers; i++ {
		p := Pilot{Engineer: string(rune('0' + i)), FirstReplaySeconds: 100, Tasks: map[string]TaskResult{}, Evidence: f.evidence}
		for _, task := range Tasks {
			p.Tasks[task] = TaskResult{Passed: true, Uncoached: true}
		}
		doc.Pilot = append(doc.Pilot, p)
	}
	f.doc = doc
	return f
}

func (f *fixture) validate(artifacts string) []string {
	return Validate(f.doc, ValidateOptions{Base: f.base, Version: "0.9.0", Artifacts: artifacts, SourceDigest: "test"})
}

func TestCompleteFixtureValidates(t *testing.T) {
	if errs := newFixture(t).validate(""); len(errs) != 0 {
		t.Fatalf("complete fixture rejected: %v", errs)
	}
}

func TestPendingTemplateCannotQualify(t *testing.T) {
	errs := Validate(Template("real"), ValidateOptions{Base: t.TempDir(), Version: "0.9.0", SourceDigest: "test"})
	if len(errs) <= 25 {
		t.Fatalf("template produced only %d blockers: %v", len(errs), errs)
	}
}

func TestStaleSourceAndVersion(t *testing.T) {
	f := newFixture(t)
	f.doc.SourceDigest, f.doc.Version = "different", "0.8.0"
	if errs := f.validate(""); len(errs) != 2 {
		t.Fatalf("want 2 blockers, got %v", errs)
	}
}

func TestCleanupCancelAndSoak(t *testing.T) {
	f := newFixture(t)
	p := f.doc.Platforms["windows-amd64"]
	slow := 2.1
	p.Scenarios["cancellation"][0].CancelSeconds = &slow
	p.Scenarios["wire"][0].CleanupVerified = false
	p.Soak.Seconds = SoakSeconds - 1
	f.doc.Platforms["windows-amd64"] = p
	if errs := f.validate(""); len(errs) != 3 {
		t.Fatalf("want 3 blockers, got %v", errs)
	}
}

func TestEvidenceIntegrity(t *testing.T) {
	f := newFixture(t)
	f.evidence[0].SHA256 = "bad"
	if !containsSubstring(f.validate(""), "checksum") {
		t.Fatal("checksum mismatch was accepted")
	}
	f.evidence[0].Path = "../outside.txt"
	if !containsSubstring(f.validate(""), "escapes") {
		t.Fatal("evidence outside the manifest directory was accepted")
	}
}

func TestPilotThresholds(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < 3; i++ {
		f.doc.Pilot[i].Tasks["inspect-select"] = TaskResult{Passed: false, Uncoached: true}
		f.doc.Pilot[i].FirstReplaySeconds = PilotMedianSeconds + 1
	}
	f.doc.Pilot[1].Engineer = "0"
	if errs := f.validate(""); len(errs) != 3 {
		t.Fatalf("want 3 blockers, got %v", errs)
	}
}

func TestNonFiniteMetrics(t *testing.T) {
	f := newFixture(t)
	f.doc.Pilot[0].FirstReplaySeconds = math.NaN()
	p := f.doc.Platforms["linux-amd64"]
	p.Soak.Seconds = math.Inf(1)
	f.doc.Platforms["linux-amd64"] = p
	if len(f.validate("")) == 0 {
		t.Fatal("non-finite metrics were accepted")
	}
}

func TestPackagedBinaryBinding(t *testing.T) {
	f := newFixture(t)
	if errs := f.validate(f.base); len(errs) != 2 {
		t.Fatalf("want 2 missing-binary blockers, got %v", errs)
	}
	for name, p := range f.doc.Platforms {
		suffix := ""
		if strings.HasPrefix(name, "windows") {
			suffix = ".exe"
		}
		path := filepath.Join(f.base, "livewire-0.9.0-"+name+suffix)
		if err := os.WriteFile(path, []byte("fixture binary"), 0o600); err != nil {
			t.Fatal(err)
		}
		p.BinarySHA256, _ = FileSHA256(path)
		f.doc.Platforms[name] = p
	}
	if errs := f.validate(f.base); len(errs) != 0 {
		t.Fatalf("bound binaries rejected: %v", errs)
	}
}

func TestPackagedBinaryBindingUsesChecksumManifest(t *testing.T) {
	f := newFixture(t)
	artifacts := t.TempDir()
	var manifest strings.Builder
	for name, p := range f.doc.Platforms {
		suffix := ""
		if strings.HasPrefix(name, "windows") {
			suffix = ".exe"
		}
		p.BinarySHA256 = strings.Repeat("a", 64)
		f.doc.Platforms[name] = p
		manifest.WriteString(p.BinarySHA256 + "  livewire-0.9.0-" + name + suffix + "\n")
	}
	if err := os.WriteFile(filepath.Join(artifacts, "SHA256SUMS"), []byte(manifest.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if errs := f.validate(artifacts); len(errs) != 0 {
		t.Fatalf("manifest-bound binaries rejected: %v", errs)
	}
	p := f.doc.Platforms["linux-amd64"]
	p.BinarySHA256 = strings.Repeat("b", 64)
	f.doc.Platforms["linux-amd64"] = p
	if !containsSubstring(f.validate(artifacts), "differs from release") {
		t.Fatal("a binary digest that differs from the release manifest was accepted")
	}
}

func TestRecorderExitAndOverwriteProtection(t *testing.T) {
	out := filepath.Join(t.TempDir(), "record")
	o := RecordOptions{Output: out, Timeout: 20 * time.Second, ExpectedExit: 3, Argv: helperArgv(t, "exit3")}
	result, err := Record(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ExitMatched || result.ExitCode == nil || *result.ExitCode != 3 {
		t.Fatalf("exit code not recorded: %+v", result)
	}
	data, err := os.ReadFile(filepath.Join(out, "record.json"))
	if err != nil {
		t.Fatal(err)
	}
	var written RecordResult
	if err := json.Unmarshal(data, &written); err != nil {
		t.Fatal(err)
	}
	if written.BehaviorVerified || written.CleanupVerified {
		t.Fatalf("recorder claimed human verification: %+v", written)
	}
	if _, err := Record(context.Background(), o); err == nil {
		t.Fatal("recorder overwrote existing evidence")
	}
}

func TestRecorderTimeoutCannotPass(t *testing.T) {
	out := filepath.Join(t.TempDir(), "timeout")
	result, err := Record(context.Background(), RecordOptions{Output: out, Timeout: 50 * time.Millisecond, ExpectedExit: 0, Argv: helperArgv(t, "sleep")})
	if err != nil {
		t.Fatal(err)
	}
	if !result.TimedOut || result.ExitMatched {
		t.Fatalf("timed-out command passed: %+v", result)
	}
}

func TestShortSoakCannotClaimQualification(t *testing.T) {
	out := filepath.Join(t.TempDir(), "soak")
	result, err := Soak(context.Background(), SoakOptions{Output: out, Seconds: 0.1, Gap: 0.01, Timeout: 20 * time.Second, Argv: helperArgv(t, "pass")})
	if err != nil {
		t.Fatal(err)
	}
	if !result.CommandsPassed || result.Passed || result.QualificationDurationMet || result.CleanupVerified {
		t.Fatalf("short soak overclaimed: %+v", result)
	}
	if result.Attempts < 1 {
		t.Fatalf("soak ran no attempts: %+v", result)
	}
}

func TestSourceDigestIgnoresLineEndings(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"go.mod", "go.sum", filepath.Join("qualification", "corpus.json")} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	src := filepath.Join(root, "cmd", "main.go")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lf, err := SourceDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("package main\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	crlf, err := SourceDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if lf != crlf {
		t.Fatal("CRLF checkout changed the source digest")
	}
	if err := os.WriteFile(src, []byte("package changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, _ := SourceDigest(root); changed == lf {
		t.Fatal("source change did not move the digest")
	}
}

func TestManifestLookup(t *testing.T) {
	manifest := []byte(strings.Repeat("c", 64) + "  livewire-1.0.0-linux-amd64\n" + strings.Repeat("d", 64) + "  SBOM.json\r\n")
	if sum, ok := ManifestSHA256(manifest, "SBOM.json"); !ok || sum != strings.Repeat("d", 64) {
		t.Fatalf("manifest lookup failed: %q %v", sum, ok)
	}
	if _, ok := ManifestSHA256(manifest, "missing"); ok {
		t.Fatal("missing name matched")
	}
}

func containsSubstring(items []string, sub string) bool {
	for _, item := range items {
		if strings.Contains(item, sub) {
			return true
		}
	}
	return false
}
