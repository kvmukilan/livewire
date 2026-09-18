// Package qualification records operator-run checks and enforces the
// stable-release qualification gate. Nothing here sends traffic on its own:
// Record and Soak execute only the argv the operator supplies, on a host and
// target the operator selected. Evidence stays local unless the maintainer
// deliberately includes a reviewed, redacted copy in a release.
package qualification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Scenarios are the field checks every supported platform must pass three
// times in a row before a stable release.
var Scenarios = []string{"capture", "application", "stateful-tcp", "udp", "icmp", "wire",
	"two-interface-dut", "cancellation", "driver-error", "interface-removal",
	"target-disconnect", "invalid-credentials", "disk-full", "report-collision"}

// BrowserChecks are the dashboard checks a human performs in a real browser.
var BrowserChecks = []string{"preview", "changed-inputs", "start-stop", "results", "downloads",
	"keyboard", "narrow-width", "desktop-width"}

// Tasks are the uncoached pilot tasks each engineer attempts.
var Tasks = []string{"inspect-select", "preview-replay", "compare-results", "repeat-stop", "bundle"}

// BenchmarkCases are the size and record-count limits the loader must honor.
var BenchmarkCases = []string{"10MiB", "100MiB", "512MiB", "513MiB-limit", "1000000-records", "1000001-records-limit"}

// Platforms are the release targets that need physical qualification.
var Platforms = []string{"windows-amd64", "linux-amd64"}

const (
	// SoakSeconds is the minimum soak duration for one platform.
	SoakSeconds = 7200
	// CancelSeconds is the longest an operator stop may take.
	CancelSeconds = 2
	// PilotEngineers is how many uncoached engineers must complete the pilot.
	PilotEngineers = 5
	// PilotPassFloor is the minimum number of passed pilot tasks out of 25.
	PilotPassFloor = 23
	// PilotMedianSeconds bounds the median time to a first successful replay.
	PilotMedianSeconds = 600
)

// Evidence names a local file and the checksum it had when recorded.
type Evidence struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// ScenarioRun is one execution of a field scenario.
type ScenarioRun struct {
	Passed          bool       `json:"passed"`
	CleanupVerified bool       `json:"cleanupVerified"`
	ExpectedResult  string     `json:"expectedResult"`
	ObservedResult  string     `json:"observedResult"`
	CancelSeconds   *float64   `json:"cancelSeconds,omitempty"`
	Evidence        []Evidence `json:"evidence"`
}

// SoakRecord summarizes a long-running platform soak.
type SoakRecord struct {
	Seconds         float64    `json:"seconds"`
	Passed          bool       `json:"passed"`
	CleanupVerified bool       `json:"cleanupVerified"`
	Evidence        []Evidence `json:"evidence"`
}

// Platform is the qualification record for one release target.
type Platform struct {
	OS           string                   `json:"os"`
	Driver       string                   `json:"driver"`
	NIC          string                   `json:"nic"`
	DUT          string                   `json:"dut"`
	Firmware     string                   `json:"firmware"`
	BinarySHA256 string                   `json:"binarySha256"`
	Scenarios    map[string][]ScenarioRun `json:"scenarios"`
	Soak         SoakRecord               `json:"soak"`
}

// Browser is the manual dashboard qualification record.
type Browser struct {
	BrowserVersion string          `json:"browserVersion"`
	Checks         map[string]bool `json:"checks"`
	Evidence       []Evidence      `json:"evidence"`
}

// Benchmark is one loader limit case.
type Benchmark struct {
	Case     string     `json:"case"`
	Passed   bool       `json:"passed"`
	Evidence []Evidence `json:"evidence"`
}

// TaskResult is one pilot task outcome.
type TaskResult struct {
	Passed    bool `json:"passed"`
	Uncoached bool `json:"uncoached"`
}

// Pilot is one engineer's uncoached pilot.
type Pilot struct {
	Engineer           string                `json:"engineer"`
	FirstReplaySeconds float64               `json:"firstReplaySeconds"`
	Tasks              map[string]TaskResult `json:"tasks"`
	Evidence           []Evidence            `json:"evidence"`
}

// Manifest is the stable-release qualification document.
type Manifest struct {
	SchemaVersion    int                 `json:"schemaVersion"`
	Version          string              `json:"version"`
	SourceDigest     string              `json:"sourceDigest"`
	BlockingFindings []string            `json:"blockingFindings"`
	Platforms        map[string]Platform `json:"platforms"`
	Browser          Browser             `json:"browser"`
	Benchmarks       []Benchmark         `json:"benchmarks"`
	Pilot            []Pilot             `json:"pilot"`
}

// FileSHA256 returns the lowercase hex digest of a file's contents.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// FindRoot walks upward from dir until it finds the module's go.mod.
func FindRoot(dir string) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("qualification: go.mod not found above " + dir)
		}
		dir = parent
	}
}

var sourceSuffixes = map[string]bool{".go": true, ".html": true, ".cjs": true, ".ps1": true}

// SourceDigest binds evidence to the executable source and the qualification
// tooling. It scans actual files rather than the Git index so new,
// not-yet-tracked source during local work also changes the digest. Line
// endings are normalized so a CRLF checkout hashes like Git's LF content.
func SourceDigest(root string) (string, error) {
	var paths []string
	for _, folder := range []string{"cmd", "internal", "scripts"} {
		if _, err := os.Stat(filepath.Join(root, folder)); errors.Is(err, os.ErrNotExist) {
			continue
		}
		err := filepath.WalkDir(filepath.Join(root, folder), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && sourceSuffixes[filepath.Ext(p)] {
				paths = append(paths, p)
			}
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	paths = append(paths, filepath.Join(root, "go.mod"), filepath.Join(root, "go.sum"), filepath.Join(root, "qualification", "corpus.json"))
	rel := func(p string) string {
		r, err := filepath.Rel(root, p)
		if err != nil {
			return p
		}
		return filepath.ToSlash(r)
	}
	sort.Slice(paths, func(i, j int) bool { return rel(paths[i]) < rel(paths[j]) })
	h := sha256.New()
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return "", err
		}
		h.Write([]byte(rel(p)))
		h.Write([]byte{0})
		h.Write(bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Template is an empty manifest with every required section present and one
// blocking finding, so an untouched template can never validate.
func Template(sourceDigest string) Manifest {
	m := Manifest{
		SchemaVersion: 1, Version: "0.9.0", SourceDigest: sourceDigest,
		BlockingFindings: []string{"Qualification has not been completed"},
		Platforms:        map[string]Platform{},
		Browser:          Browser{Checks: map[string]bool{}, Evidence: []Evidence{}},
		Benchmarks:       []Benchmark{},
		Pilot:            []Pilot{},
	}
	for _, platform := range Platforms {
		p := Platform{Scenarios: map[string][]ScenarioRun{}, Soak: SoakRecord{Evidence: []Evidence{}}}
		for _, s := range Scenarios {
			p.Scenarios[s] = []ScenarioRun{}
		}
		m.Platforms[platform] = p
	}
	for _, c := range BrowserChecks {
		m.Browser.Checks[c] = false
	}
	return m
}

// ValidateOptions binds a manifest to the release it claims to qualify.
type ValidateOptions struct {
	// Base is the directory evidence paths are relative to, normally the
	// manifest's own directory.
	Base string
	// Version is the release being qualified.
	Version string
	// Artifacts optionally names the release directory. It may hold the packaged
	// binaries themselves or only their SHA256SUMS manifest.
	Artifacts string
	// SourceDigest is the current SourceDigest of the tree being released.
	SourceDigest string
}

func finite(x float64) bool { return !math.IsNaN(x) && !math.IsInf(x, 0) }

// Validate lists every reason the manifest does not qualify the release. An
// empty result means the stable release may proceed.
func Validate(doc Manifest, o ValidateOptions) []string {
	var errs []string
	need := func(ok bool, message string) {
		if !ok {
			errs = append(errs, message)
		}
	}
	base, baseErr := filepath.Abs(o.Base)
	evidence := func(items []Evidence, label string) {
		need(len(items) > 0, label+": missing evidence")
		for _, item := range items {
			if baseErr != nil {
				errs = append(errs, label+": invalid evidence entry")
				continue
			}
			path, err := filepath.Abs(filepath.Join(base, item.Path))
			if err != nil {
				errs = append(errs, label+": invalid evidence entry")
				continue
			}
			rel, err := filepath.Rel(base, path)
			inside := err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
			need(inside, label+": evidence escapes its directory")
			if !inside {
				continue
			}
			info, err := os.Stat(path)
			isFile := err == nil && info.Mode().IsRegular()
			need(isFile, label+": evidence file missing")
			if isFile {
				sum, err := FileSHA256(path)
				need(err == nil && sum == item.SHA256, label+": evidence checksum mismatch")
			}
		}
	}

	need(doc.SchemaVersion == 1, "unsupported qualification schema")
	need(doc.Version == o.Version, "qualification version mismatch")
	need(doc.SourceDigest == o.SourceDigest, "qualification source changed; requalify")
	need(len(doc.BlockingFindings) == 0, "unresolved blocking findings")
	for _, platform := range Platforms {
		p := doc.Platforms[platform]
		for _, field := range []struct{ name, value string }{
			{"os", p.OS}, {"driver", p.Driver}, {"nic", p.NIC}, {"dut", p.DUT}, {"firmware", p.Firmware}, {"binarySha256", p.BinarySHA256},
		} {
			need(strings.TrimSpace(field.value) != "", platform+": missing "+field.name)
		}
		if o.Artifacts != "" {
			suffix := ""
			if strings.HasPrefix(platform, "windows") {
				suffix = ".exe"
			}
			sum, ok := packagedBinarySHA256(o.Artifacts, "livewire-"+o.Version+"-"+platform+suffix)
			need(ok, platform+": packaged binary missing")
			if ok {
				need(sum == p.BinarySHA256, platform+": tested binary differs from release")
			}
		}
		for _, scenario := range Scenarios {
			runs := p.Scenarios[scenario]
			label := platform + "/" + scenario
			need(len(runs) >= 3, label+": three consecutive passes required")
			if len(runs) > 3 {
				runs = runs[len(runs)-3:]
			}
			for _, r := range runs {
				need(r.Passed && r.CleanupVerified, label+": failed result/cleanup")
				need(r.ExpectedResult != "" && r.ObservedResult != "", label+": missing expected/observed behavior")
				if scenario == "cancellation" {
					need(r.CancelSeconds != nil && finite(*r.CancelSeconds) && *r.CancelSeconds >= 0 && *r.CancelSeconds <= CancelSeconds,
						label+": cancellation exceeds two seconds or is unmeasured")
				}
				evidence(r.Evidence, label)
			}
		}
		need(finite(p.Soak.Seconds) && p.Soak.Seconds >= SoakSeconds, platform+": two-hour soak missing")
		need(p.Soak.Passed && p.Soak.CleanupVerified, platform+": soak failed or cleanup unverified")
		evidence(p.Soak.Evidence, platform+"/soak")
	}
	need(doc.Browser.BrowserVersion != "", "browser version missing")
	for _, check := range BrowserChecks {
		need(doc.Browser.Checks[check], "browser check missing: "+check)
	}
	evidence(doc.Browser.Evidence, "browser")
	cases := map[string]Benchmark{}
	for _, b := range doc.Benchmarks {
		cases[b.Case] = b
	}
	for _, name := range BenchmarkCases {
		b := cases[name]
		need(b.Passed, "benchmark missing/failed: "+name)
		evidence(b.Evidence, "benchmark/"+name)
	}
	need(len(doc.Pilot) == PilotEngineers, "five pilot engineers required")
	ids := map[string]bool{}
	distinct := true
	for _, p := range doc.Pilot {
		if strings.TrimSpace(p.Engineer) == "" || ids[p.Engineer] {
			distinct = false
		}
		ids[p.Engineer] = true
	}
	need(distinct && len(ids) == PilotEngineers, "pilot engineer identifiers must be distinct")
	successes := 0
	var times []float64
	for _, p := range doc.Pilot {
		for _, task := range Tasks {
			r := p.Tasks[task]
			need(r.Uncoached, "pilot task must be uncoached: "+task)
			if r.Passed {
				successes++
			}
		}
		valid := finite(p.FirstReplaySeconds) && p.FirstReplaySeconds >= 0
		need(valid, "invalid pilot first-replay time")
		if valid {
			times = append(times, p.FirstReplaySeconds)
		}
		evidence(p.Evidence, "pilot")
	}
	need(successes >= PilotPassFloor, "pilot completion below 23/25")
	need(len(times) == PilotEngineers && median(times) <= PilotMedianSeconds, "pilot median first replay exceeds ten minutes or is unmeasured")
	return errs
}

// packagedBinarySHA256 finds the release checksum of one packaged binary, from
// the file itself when present or from the directory's SHA256SUMS manifest.
func packagedBinarySHA256(artifacts, name string) (string, bool) {
	if sum, err := FileSHA256(filepath.Join(artifacts, name)); err == nil {
		return sum, true
	}
	manifest, err := os.ReadFile(filepath.Join(artifacts, "SHA256SUMS"))
	if err != nil {
		return "", false
	}
	return ManifestSHA256(manifest, name)
}

var checksumLine = regexp.MustCompile(`^([0-9a-f]{64})  (.+)$`)

// ManifestSHA256 looks a file name up in a SHA256SUMS manifest.
func ManifestSHA256(manifest []byte, name string) (string, bool) {
	for _, line := range strings.Split(string(manifest), "\n") {
		m := checksumLine.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m != nil && m[2] == name {
			return m[1], true
		}
	}
	return "", false
}

func median(values []float64) float64 {
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	n := len(sorted)
	if n == 0 {
		return math.NaN()
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

// RecordOptions describe one operator command whose behavior is being recorded.
type RecordOptions struct {
	Output       string
	Timeout      time.Duration
	ExpectedExit int
	Argv         []string
	SourceDigest string
}

// RecordResult is the transcript metadata written beside stdout and stderr.
// BehaviorVerified and CleanupVerified are always false when written: a human
// sets them after reviewing the transcript and the host.
type RecordResult struct {
	Argv             []string   `json:"argv"`
	ElapsedSeconds   float64    `json:"elapsedSeconds"`
	ExitCode         *int       `json:"exitCode"`
	TimedOut         bool       `json:"timedOut"`
	SourceDigest     string     `json:"sourceDigest"`
	ExpectedExit     int        `json:"expectedExit"`
	ExitMatched      bool       `json:"exitMatched"`
	BehaviorVerified bool       `json:"behaviorVerified"`
	CleanupVerified  bool       `json:"cleanupVerified"`
	Files            []Evidence `json:"files"`
}

// Record runs exactly the supplied argv with no shell, capturing stdout and
// stderr into a new private directory. It refuses to reuse an existing
// directory so evidence is never overwritten.
func Record(ctx context.Context, o RecordOptions) (RecordResult, error) {
	if o.Timeout <= 0 {
		return RecordResult{}, errors.New("timeout must be positive")
	}
	if len(o.Argv) == 0 {
		return RecordResult{}, errors.New("record requires an explicit command after --")
	}
	if err := newPrivateDir(o.Output); err != nil {
		return RecordResult{}, err
	}
	stdout, err := os.OpenFile(filepath.Join(o.Output, "stdout.txt"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return RecordResult{}, err
	}
	stderr, err := os.OpenFile(filepath.Join(o.Output, "stderr.txt"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		stdout.Close()
		return RecordResult{}, err
	}
	runCtx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, o.Argv[0], o.Argv[1:]...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	start := time.Now()
	runErr := cmd.Run()
	elapsed := time.Since(start)
	if err := errors.Join(stdout.Close(), stderr.Close()); err != nil {
		return RecordResult{}, err
	}
	result := RecordResult{Argv: o.Argv, ElapsedSeconds: elapsed.Seconds(), SourceDigest: o.SourceDigest, ExpectedExit: o.ExpectedExit}
	switch {
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		result.TimedOut = true
	case cmd.ProcessState != nil:
		code := cmd.ProcessState.ExitCode()
		result.ExitCode = &code
	default:
		// The command never started, which is an operator error rather than an
		// observed behavior.
		return RecordResult{}, runErr
	}
	result.ExitMatched = !result.TimedOut && result.ExitCode != nil && *result.ExitCode == o.ExpectedExit
	for _, name := range []string{"stdout.txt", "stderr.txt"} {
		sum, err := FileSHA256(filepath.Join(o.Output, name))
		if err != nil {
			return RecordResult{}, err
		}
		result.Files = append(result.Files, Evidence{Path: name, SHA256: sum})
	}
	if err := writeJSON(filepath.Join(o.Output, "record.json"), result); err != nil {
		return RecordResult{}, err
	}
	return result, nil
}

// SoakOptions repeat a recorded command for a wall-clock duration.
type SoakOptions struct {
	Output       string
	Seconds      float64
	Gap          float64
	Timeout      time.Duration
	ExpectedExit int
	Argv         []string
	SourceDigest string
}

// SoakResult summarizes a soak. Passed and CleanupVerified are always false
// when written; a human sets them after reviewing memory, handles, and host
// cleanup.
type SoakResult struct {
	Seconds                  float64 `json:"seconds"`
	RequestedSeconds         float64 `json:"requestedSeconds"`
	Attempts                 int     `json:"attempts"`
	CommandsPassed           bool    `json:"commandsPassed"`
	Interrupted              bool    `json:"interrupted"`
	Passed                   bool    `json:"passed"`
	CleanupVerified          bool    `json:"cleanupVerified"`
	QualificationDurationMet bool    `json:"qualificationDurationMet"`
	SourceDigest             string  `json:"sourceDigest"`
	HostOS                   string  `json:"hostOS"`
	NextAction               string  `json:"nextAction"`
}

// Soak records the command repeatedly until the requested duration elapses,
// the command fails, or ctx is cancelled. The literal {attempt} in any argv
// element is replaced with the 1-based attempt number.
func Soak(ctx context.Context, o SoakOptions) (SoakResult, error) {
	if !finite(o.Seconds) || o.Seconds <= 0 || !finite(o.Gap) || o.Gap < 0 {
		return SoakResult{}, errors.New("seconds must be positive and gap nonnegative, both finite")
	}
	if o.Timeout <= 0 {
		return SoakResult{}, errors.New("timeout must be positive")
	}
	if len(o.Argv) == 0 {
		return SoakResult{}, errors.New("soak requires an explicit lab command after --")
	}
	if err := newPrivateDir(o.Output); err != nil {
		return SoakResult{}, err
	}
	start := time.Now()
	attempts, success, interrupted := 0, true, false
	for time.Since(start).Seconds() < o.Seconds {
		if ctx.Err() != nil {
			interrupted, success = true, false
			break
		}
		attempts++
		argv := make([]string, len(o.Argv))
		for i, v := range o.Argv {
			argv[i] = strings.ReplaceAll(v, "{attempt}", fmt.Sprint(attempts))
		}
		result, err := Record(ctx, RecordOptions{Output: filepath.Join(o.Output, fmt.Sprintf("attempt-%d", attempts)), Timeout: o.Timeout, ExpectedExit: o.ExpectedExit, Argv: argv, SourceDigest: o.SourceDigest})
		if err != nil {
			return SoakResult{}, err
		}
		if ctx.Err() != nil {
			interrupted, success = true, false
			break
		}
		if !result.ExitMatched {
			success = false
			break
		}
		remaining := o.Seconds - time.Since(start).Seconds()
		pause := math.Min(o.Gap, math.Max(0, remaining))
		if !sleepContext(ctx, time.Duration(pause*float64(time.Second))) {
			interrupted, success = true, false
			break
		}
	}
	elapsed := time.Since(start).Seconds()
	result := SoakResult{
		Seconds: elapsed, RequestedSeconds: o.Seconds, Attempts: attempts,
		CommandsPassed: success && !interrupted, Interrupted: interrupted,
		QualificationDurationMet: elapsed >= SoakSeconds, SourceDigest: o.SourceDigest,
		HostOS:     runtime.GOOS + "/" + runtime.GOARCH,
		NextAction: "Review attempt behavior, memory/handle observations, and host cleanup before marking qualification passed.",
	}
	if err := writeJSON(filepath.Join(o.Output, "soak.json"), result); err != nil {
		return SoakResult{}, err
	}
	return result, nil
}

// CorpusCase names one regression test that proves a documented behavior.
type CorpusCase struct {
	Behavior string `json:"behavior"`
	Package  string `json:"package"`
	Test     string `json:"test"`
}

// CorpusManifest is qualification/corpus.json.
type CorpusManifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	Description   string       `json:"description"`
	Cases         []CorpusCase `json:"cases"`
}

// CorpusResult is the outcome for one package's corpus tests.
type CorpusResult struct {
	Package  string   `json:"package"`
	Tests    []string `json:"tests"`
	Passed   bool     `json:"passed"`
	Evidence Evidence `json:"evidence"`
}

// Corpus runs every named regression test with go test -json and requires each
// one to report a pass. A renamed, skipped, or missing test fails the corpus.
func Corpus(ctx context.Context, root, manifestPath, output string) ([]CorpusResult, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	var manifest CorpusManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("corpus manifest: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return nil, err
	}
	if err := os.Mkdir(output, 0o755); err != nil {
		return nil, err
	}
	var order []string
	grouped := map[string][]string{}
	for _, c := range manifest.Cases {
		if _, seen := grouped[c.Package]; !seen {
			order = append(order, c.Package)
		}
		grouped[c.Package] = append(grouped[c.Package], c.Test)
	}
	var results []CorpusResult
	for _, pkg := range order {
		tests := grouped[pkg]
		quoted := make([]string, len(tests))
		for i, t := range tests {
			quoted[i] = regexp.QuoteMeta(t)
		}
		pattern := "^(" + strings.Join(quoted, "|") + ")$"
		runCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		cmd := exec.CommandContext(runCtx, "go", "test", "-json", "-count=1", "-run", pattern, pkg)
		cmd.Dir = root
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		runErr := cmd.Run()
		cancel()
		name := strings.ReplaceAll(strings.TrimPrefix(pkg, "./"), "/", "-")
		log := filepath.Join(output, name+".jsonl")
		if err := os.WriteFile(log, stdout.Bytes(), 0o644); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(output, name+".stderr.txt"), stderr.Bytes(), 0o644); err != nil {
			return nil, err
		}
		passed := map[string]bool{}
		for _, line := range bytes.Split(stdout.Bytes(), []byte("\n")) {
			var event struct{ Action, Test string }
			if len(bytes.TrimSpace(line)) == 0 || json.Unmarshal(line, &event) != nil {
				continue
			}
			if event.Action == "pass" && event.Test != "" {
				passed[event.Test] = true
			}
		}
		ok := runErr == nil
		for _, t := range tests {
			ok = ok && passed[t]
		}
		sum, err := FileSHA256(log)
		if err != nil {
			return nil, err
		}
		results = append(results, CorpusResult{Package: pkg, Tests: tests, Passed: ok, Evidence: Evidence{Path: filepath.Base(log), SHA256: sum}})
	}
	if err := writeJSON(filepath.Join(output, "corpus-results.json"), results); err != nil {
		return nil, err
	}
	return results, nil
}

// RunBenchmarks builds the loader benchmark and runs each limit case in its
// own process while sampling the operating system's peak resident set.
func RunBenchmarks(ctx context.Context, root, output, sourceDigest string) ([]Benchmark, error) {
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return nil, err
	}
	if err := os.Mkdir(output, 0o755); err != nil {
		return nil, err
	}
	absOutput, err := filepath.Abs(output)
	if err != nil {
		return nil, err
	}
	binary := filepath.Join(absOutput, "qualifybench")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "scripts/qualifybench.go")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("build qualifybench: %w\n%s", err, out)
	}
	cases := []struct {
		name string
		args []string
	}{
		{"10MiB", []string{"-mib", "10"}}, {"100MiB", []string{"-mib", "100"}},
		{"512MiB", []string{"-mib", "512"}}, {"513MiB-limit", []string{"-mib", "513"}},
		{"1000000-records", []string{"-records", "1000000"}}, {"1000001-records-limit", []string{"-records", "1000001"}},
	}
	var results []Benchmark
	for _, c := range cases {
		stdoutPath := filepath.Join(output, c.name+".json")
		stdout, err := os.OpenFile(stdoutPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, err
		}
		stderr, err := os.OpenFile(filepath.Join(output, c.name+".stderr.txt"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			stdout.Close()
			return nil, err
		}
		runCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		cmd := exec.CommandContext(runCtx, binary, c.args...)
		cmd.Stdout, cmd.Stderr = stdout, stderr
		var peak uint64
		if err := cmd.Start(); err != nil {
			cancel()
			stdout.Close()
			stderr.Close()
			return nil, err
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		ticker := time.NewTicker(10 * time.Millisecond)
	sample:
		for {
			select {
			case <-done:
				break sample
			case <-ticker.C:
				if rss := peakRSS(cmd.Process.Pid); rss > peak {
					peak = rss
				}
			}
		}
		ticker.Stop()
		cancel()
		if err := errors.Join(stdout.Close(), stderr.Close()); err != nil {
			return nil, err
		}
		result := map[string]any{}
		if data, err := os.ReadFile(stdoutPath); err == nil && len(bytes.TrimSpace(data)) > 0 {
			if err := json.Unmarshal(data, &result); err != nil {
				result = map[string]any{"decodeError": err.Error()}
			}
		}
		passed := cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 0 && result["passed"] == true
		result["case"] = c.name
		result["observedPeakRSSBytes"] = peak
		result["hostOS"] = runtime.GOOS + "/" + runtime.GOARCH
		result["processor"] = runtime.GOARCH
		result["logicalCPUs"] = runtime.NumCPU()
		result["rssMethod"] = "Observed OS process high-water mark at 10ms intervals; excludes fixture file cache"
		result["passed"] = passed
		result["sourceDigest"] = sourceDigest
		metrics := filepath.Join(output, c.name+".metrics.json")
		if err := writeJSON(metrics, result); err != nil {
			return nil, err
		}
		sum, err := FileSHA256(metrics)
		if err != nil {
			return nil, err
		}
		results = append(results, Benchmark{Case: c.name, Passed: passed, Evidence: []Evidence{{Path: filepath.Base(metrics), SHA256: sum}}})
	}
	if err := writeJSON(filepath.Join(output, "benchmarks.json"), results); err != nil {
		return nil, err
	}
	return results, nil
}

func newPrivateDir(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.Mkdir(path, 0o700)
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}
