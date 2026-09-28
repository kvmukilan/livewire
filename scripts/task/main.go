// Command task mirrors the CI pipeline for local use, so a contributor can run
// the same gates with one command and one toolchain:
//
//	go run ./scripts/task check            # build, vet, test, dashboard, lint
//	go run ./scripts/task all              # everything CI runs on every push
//	go run ./scripts/task <target>...      # any subset, in order
//
// Tool versions are pinned here and nowhere else. The workflows call these
// targets, so CI and a local run cannot drift apart.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/qualification"
)

// Pinned analysis tools. Bump deliberately. staticcheck must be able to read
// the export data of every Go release CI tests with; 2026.2.x is the first
// line that understands Go 1.27.
const (
	staticcheck = "honnef.co/go/tools/cmd/staticcheck@2026.2.1"
	gosec       = "github.com/securego/gosec/v2/cmd/gosec@v2.28.0"
	govulncheck = "golang.org/x/vuln/cmd/govulncheck@v1.7.0"
)

// coverageFloors are the minimum statement coverage per profile.
var coverageFloors = []struct {
	name, pkg string
	floor     float64
}{
	{"aggregate", "./...", 60},
	{"pcapio", "./internal/pcapio", 85},
	{"webui", "./internal/webui", 60},
	{"cmd", "./cmd/livewire", 30},
	{"backend", "./internal/backend", 20},
}

// fuzzTargets are the smoke fuzzers. Each runs a fixed iteration count under a
// watchdog so a hang fails instead of stalling the pipeline.
var fuzzTargets = []struct{ pkg, name string }{
	{"./internal/adapters", "FuzzBuiltInDecoders"},
	{"./internal/adapters", "FuzzRulePackCompiler"},
	{"./internal/lab", "FuzzScenarioParsing"},
	{"./internal/tlsreplay", "FuzzTLSRecordAndHandshakeParsing"},
	{"./internal/replay", "FuzzTraceExtractionCoverage"},
	{"./internal/ipreasm", "FuzzIPv6FragmentReassembly"},
	{"./internal/ipreasm", "FuzzMalformedFragmentFrames"},
}

type target struct {
	name    string
	summary string
	// options is true for a target that owns the rest of the command line.
	options bool
	run     func(ctx context.Context, args []string) error
}

var targets []target

func init() {
	targets = []target{
		{name: "build", summary: "compile every package", run: func(ctx context.Context, _ []string) error {
			return sh(ctx, "go", "build", "./...")
		}},
		{name: "vet", summary: "go vet", run: func(ctx context.Context, _ []string) error {
			return sh(ctx, "go", "vet", "./...")
		}},
		{name: "test", summary: "unit tests, no cache", run: func(ctx context.Context, _ []string) error {
			return sh(ctx, "go", "test", "-count=1", "./...")
		}},
		{name: "dashboard", summary: "dashboard state tests under node", run: func(ctx context.Context, _ []string) error {
			return sh(ctx, "node", "--test", "scripts/dashboard.test.cjs")
		}},
		{name: "lint", summary: "govulncheck, staticcheck, high-confidence gosec", run: lint},
		{name: "race", summary: "tests under the race detector", run: func(ctx context.Context, _ []string) error {
			return sh(ctx, "go", "test", "-race", "-count=1", "./...")
		}},
		{name: "shuffle", summary: "shuffled and repeated tests", run: func(ctx context.Context, _ []string) error {
			if err := sh(ctx, "go", "test", "-shuffle=on", "-count=3", "./..."); err != nil {
				return err
			}
			return sh(ctx, "go", "test", "-shuffle=on", "-count=20", "./internal/webui")
		}},
		{name: "fuzz", summary: "fuzz smoke, 200k iterations per target", run: fuzz},
		{name: "cover", summary: "coverage profiles under coverage/ with floors", run: cover},
		{name: "corpus", summary: "maintained regression corpus", run: corpus},
		{name: "compare-releases", summary: "behavior comparison against published releases", options: true, run: compareReleases},
		{name: "check", summary: "build, vet, test, dashboard, lint", run: func(ctx context.Context, _ []string) error {
			return runTargets(ctx, []string{"build", "vet", "test", "dashboard", "lint"})
		}},
		{name: "all", summary: "every gate CI runs on push", run: func(ctx context.Context, _ []string) error {
			return runTargets(ctx, []string{"build", "vet", "test", "dashboard", "lint", "race", "shuffle", "fuzz", "cover", "corpus"})
		}},
	}
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	root, err := qualification.FindRoot(".")
	if err != nil {
		fail(err)
	}
	if err := os.Chdir(root); err != nil {
		fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if t := lookup(os.Args[1]); t != nil && t.options {
		if err := t.run(ctx, os.Args[2:]); err != nil {
			fail(err)
		}
		return
	}
	if err := runTargets(ctx, os.Args[1:]); err != nil {
		fail(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: go run ./scripts/task <target>...")
	fmt.Fprintln(os.Stderr, "\ntargets:")
	for _, t := range targets {
		fmt.Fprintf(os.Stderr, "  %-18s %s\n", t.name, t.summary)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "task:", err)
	os.Exit(1)
}

func lookup(name string) *target {
	for i := range targets {
		if targets[i].name == name {
			return &targets[i]
		}
	}
	return nil
}

func runTargets(ctx context.Context, names []string) error {
	for _, name := range names {
		t := lookup(name)
		if t == nil {
			usage()
			return fmt.Errorf("unknown target %q", name)
		}
		if t.options {
			return fmt.Errorf("%s takes options and must be the only target", name)
		}
		fmt.Printf("==> %s\n", name)
		started := time.Now()
		if err := t.run(ctx, nil); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		fmt.Printf("==> %s ok (%s)\n", name, time.Since(started).Round(time.Millisecond))
	}
	return nil
}

// sh runs a command with inherited output so a failure prints exactly what
// the tool said.
func sh(ctx context.Context, name string, args ...string) error {
	fmt.Printf("$ %s %s\n", name, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func lint(ctx context.Context, _ []string) error {
	if err := sh(ctx, "go", "run", govulncheck, "./..."); err != nil {
		return err
	}
	if err := sh(ctx, "go", "run", staticcheck, "./..."); err != nil {
		return err
	}
	return sh(ctx, "go", "run", gosec, "-severity", "high", "-confidence", "high", "-exclude-generated", "./...")
}

func fuzz(ctx context.Context, _ []string) error {
	for _, f := range fuzzTargets {
		if err := sh(ctx, "go", "test", f.pkg, "-run=^$", "-fuzz="+f.name, "-fuzztime=200000x", "-parallel=1", "-timeout=2m"); err != nil {
			return err
		}
	}
	return nil
}

func cover(ctx context.Context, _ []string) error {
	if err := os.MkdirAll("coverage", 0o755); err != nil {
		return err
	}
	var failures []string
	for _, c := range coverageFloors {
		profile := filepath.Join("coverage", c.name+".out")
		args := []string{"test", "-coverprofile=" + profile}
		// Integration tests exercise replay through adapters, TLS, and the CLI.
		// Instrument dependencies for the aggregate so these executions count;
		// retain isolated package coverage and every existing minimum unchanged.
		if c.name == "aggregate" {
			args = append(args, "-coverpkg=./...")
		}
		args = append(args, c.pkg)
		if err := sh(ctx, "go", args...); err != nil {
			return err
		}
		actual, err := totalCoverage(ctx, profile)
		if err != nil {
			return err
		}
		fmt.Printf("%s coverage: %.1f%% (required %.0f%%)\n", c.name, actual, c.floor)
		if actual < c.floor {
			failures = append(failures, fmt.Sprintf("%s %.1f%% < %.0f%%", c.name, actual, c.floor))
		}
	}
	if len(failures) > 0 {
		return errors.New("coverage below floor: " + strings.Join(failures, "; "))
	}
	return nil
}

func totalCoverage(ctx context.Context, profile string) (float64, error) {
	out, err := exec.CommandContext(ctx, "go", "tool", "cover", "-func="+profile).Output()
	if err != nil {
		return 0, err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[0] == "total:" {
			return strconv.ParseFloat(strings.TrimSuffix(fields[len(fields)-1], "%"), 64)
		}
	}
	return 0, errors.New("no total line in " + profile)
}

func corpus(ctx context.Context, _ []string) error {
	output := filepath.Join(os.TempDir(), "livewire-corpus-"+time.Now().UTC().Format("20060102T150405"))
	results, err := qualification.Corpus(ctx, ".", filepath.Join("qualification", "corpus.json"), output)
	if err != nil {
		return err
	}
	ok := true
	for _, r := range results {
		status := "passed"
		if !r.Passed {
			status, ok = "FAILED (missing, skipped, or failing test)", false
		}
		fmt.Printf("%s: %s\n", r.Package, status)
	}
	if !ok {
		return errors.New("corpus failed; evidence in " + output)
	}
	fmt.Println("corpus evidence:", output)
	return nil
}

// parseOptions parses a target's options and rejects stray arguments.
func parseOptions(name string, args []string, define func(*flag.FlagSet)) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	define(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%s: unexpected argument %q", name, fs.Arg(0))
	}
	return nil
}
