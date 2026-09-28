// Command qualify records operator-run checks and enforces the stable-release
// qualification gate. Run it from anywhere inside the repository:
//
//	go run ./scripts/qualify init qualification/stable.json
//	go run ./scripts/qualify corpus -output coverage/corpus-new
//	go run ./scripts/qualify benchmark -output coverage/benchmark-new
//	go run ./scripts/qualify record -output coverage/doctor-new -- livewire doctor -json
//	go run ./scripts/qualify soak -output coverage/soak-new -seconds 7200 -- livewire reproduce issue.pcap -t 192.168.1.50
//	go run ./scripts/qualify validate -version 1.0.0 -artifacts dist/v1.0.0 qualification/stable.json
//
// No subcommand sends traffic by itself. record and soak execute only the argv
// after --, on the lab host and target the operator selected.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/qualification"
)

func main() {
	code, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "qualify:", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

func usage() error {
	return errors.New("usage: qualify <init|validate|corpus|benchmark|record|soak> [options]")
}

func run(args []string) (int, error) {
	if len(args) == 0 {
		return 2, usage()
	}
	root, err := qualification.FindRoot(".")
	if err != nil {
		return 1, err
	}
	digest := func() (string, error) { return qualification.SourceDigest(root) }
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	switch args[0] {
	case "init":
		fs := flag.NewFlagSet("init", flag.ContinueOnError)
		if err := fs.Parse(args[1:]); err != nil {
			return 2, err
		}
		if fs.NArg() != 1 {
			return 2, errors.New("usage: qualify init <output.json>")
		}
		d, err := digest()
		if err != nil {
			return 1, err
		}
		return 0, writeNew(fs.Arg(0), qualification.Template(d))
	case "validate":
		fs := flag.NewFlagSet("validate", flag.ContinueOnError)
		version := fs.String("version", "", "release version being qualified (required)")
		artifacts := fs.String("artifacts", "", "release directory holding the binaries or their SHA256SUMS")
		parseArgs := args[1:]
		// Preserve the documented positional-first form as well as normal Go
		// flag order. Only the manifest is positional for this subcommand.
		if len(parseArgs) > 1 && !strings.HasPrefix(parseArgs[0], "-") {
			parseArgs = append(append([]string(nil), parseArgs[1:]...), parseArgs[0])
		}
		if err := fs.Parse(parseArgs); err != nil {
			return 2, err
		}
		if fs.NArg() != 1 || *version == "" {
			return 2, errors.New("usage: qualify validate <manifest.json> -version <x.y.z> [-artifacts <dir>]")
		}
		data, err := os.ReadFile(fs.Arg(0))
		if err != nil {
			return 1, err
		}
		var doc qualification.Manifest
		if err := json.Unmarshal(data, &doc); err != nil {
			return 1, fmt.Errorf("manifest: %w", err)
		}
		d, err := digest()
		if err != nil {
			return 1, err
		}
		blockers := qualification.Validate(doc, qualification.ValidateOptions{Base: filepath.Dir(fs.Arg(0)), Version: *version, Artifacts: *artifacts, SourceDigest: d})
		if blockers == nil {
			blockers = []string{}
		}
		printJSON(map[string]any{"ready": len(blockers) == 0, "blockers": blockers})
		if len(blockers) > 0 {
			return 1, nil
		}
		return 0, nil
	case "corpus":
		fs := flag.NewFlagSet("corpus", flag.ContinueOnError)
		output := fs.String("output", "", "new evidence directory (required)")
		if err := fs.Parse(args[1:]); err != nil {
			return 2, err
		}
		if *output == "" {
			return 2, errors.New("corpus requires -output <new directory>")
		}
		results, err := qualification.Corpus(ctx, root, filepath.Join(root, "qualification", "corpus.json"), *output)
		if err != nil {
			return 1, err
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
			return 1, nil
		}
		return 0, nil
	case "benchmark":
		fs := flag.NewFlagSet("benchmark", flag.ContinueOnError)
		output := fs.String("output", "", "new evidence directory (required)")
		if err := fs.Parse(args[1:]); err != nil {
			return 2, err
		}
		if *output == "" {
			return 2, errors.New("benchmark requires -output <new directory>")
		}
		d, err := digest()
		if err != nil {
			return 1, err
		}
		results, err := qualification.RunBenchmarks(ctx, root, *output, d)
		if err != nil {
			return 1, err
		}
		ok := true
		for _, r := range results {
			printJSON(r)
			ok = ok && r.Passed
		}
		if !ok {
			return 1, nil
		}
		return 0, nil
	case "record":
		fs := flag.NewFlagSet("record", flag.ContinueOnError)
		output := fs.String("output", "", "new evidence directory (required)")
		timeout := fs.Duration("timeout", 5*time.Minute, "kill the command after this long")
		expected := fs.Int("expected-exit", 0, "exit code that counts as a pass")
		if err := fs.Parse(args[1:]); err != nil {
			return 2, err
		}
		if *output == "" {
			return 2, errors.New("record requires -output <new directory>")
		}
		d, err := digest()
		if err != nil {
			return 1, err
		}
		result, err := qualification.Record(ctx, qualification.RecordOptions{Output: *output, Timeout: *timeout, ExpectedExit: *expected, Argv: fs.Args(), SourceDigest: d})
		if err != nil {
			return 1, err
		}
		printJSON(result)
		if !result.ExitMatched {
			return 1, nil
		}
		return 0, nil
	case "soak":
		fs := flag.NewFlagSet("soak", flag.ContinueOnError)
		output := fs.String("output", "", "new evidence directory (required)")
		seconds := fs.Float64("seconds", qualification.SoakSeconds, "how long to keep repeating the command")
		gap := fs.Float64("gap", 1, "seconds between attempts")
		timeout := fs.Duration("timeout", 5*time.Minute, "kill one attempt after this long")
		expected := fs.Int("expected-exit", 0, "exit code that counts as a pass")
		if err := fs.Parse(args[1:]); err != nil {
			return 2, err
		}
		if *output == "" {
			return 2, errors.New("soak requires -output <new directory>")
		}
		d, err := digest()
		if err != nil {
			return 1, err
		}
		result, err := qualification.Soak(ctx, qualification.SoakOptions{Output: *output, Seconds: *seconds, Gap: *gap, Timeout: *timeout, ExpectedExit: *expected, Argv: fs.Args(), SourceDigest: d})
		if err != nil {
			return 1, err
		}
		printJSON(result)
		if !result.CommandsPassed {
			return 1, nil
		}
		return 0, nil
	}
	return 2, usage()
}

func writeNew(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(append(data, '\n'))
	return errors.Join(werr, f.Close())
}

func printJSON(v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "qualify:", err)
		return
	}
	fmt.Println(string(data))
}
