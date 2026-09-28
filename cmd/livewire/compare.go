package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/compare"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/securefile"
)

// cmdCompare answers the question a peer has after a replay that did not
// reproduce: where, exactly, did the device diverge? It reads two captures of
// the same exchange and never touches the network.
func cmdCompare(args []string) error {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	jsonPath := fs.String("json", "", "also write the comparison to this JSON file")
	details := fs.Bool(flagDetails, false, "list every difference, not only the first divergence per session")
	strict := fs.Bool("strict", false, "compare exact application bytes")
	scenarioPath := fs.String("scenario", "", "same versioned comparison policy used by replay")
	udpIdle := fs.Duration("udp-idle", 30*time.Second, "split a UDP tuple into a new session after this idle interval")
	var rulePacks fileFlags
	fs.Var(&rulePacks, "rules", "JSON adapter rule pack (repeatable)")
	allFlags := registerAllFlags(fs)
	fs.Usage = func() {
		fmt.Println("usage: livewire compare <recorded.pcap> <actual.pcap> [options]")
		fmt.Println("\nPair the sessions of two captures of the same exchange and report, per session,")
		fmt.Println("whether the device answered the same way, where the first divergence is, and")
		fmt.Println("how the reply timing compares. Use it on the original capture and the")
		fmt.Println("<capture>.actual.pcap a replay saved, or on captures taken from two devices.")
		fmt.Println("Reads the files only; no interface is opened and nothing is sent.")
		printFlags(fs, "json", flagDetails)
	}
	positional, err := parsePositionalArgs(fs, args, 2)
	if err != nil {
		return err
	}
	if handleAllFlags(fs, *allFlags, aliasSet{}) {
		return errAllFlags
	}
	if len(positional) != 2 {
		fs.Usage()
		return fmt.Errorf("give two captures: the recording and the actual traffic, e.g. livewire compare issue.pcap issue.actual.pcap")
	}
	if *udpIdle <= 0 || *udpIdle > time.Hour {
		return fmt.Errorf("-udp-idle must be greater than zero and at most 1h")
	}
	registry, err := registryWithRulePacks(rulePacks)
	if err != nil {
		return err
	}
	capture, digest, err := loadCaptureSnapshot(positional[0])
	if err != nil {
		return fmt.Errorf("recorded capture: %w", err)
	}
	actual, _, err := loadRecords(positional[1])
	if err != nil {
		return fmt.Errorf("actual capture: %w", err)
	}
	mode := replay.VerifyLenient
	if *strict {
		mode = replay.VerifyStrict
	}
	var scenario *replay.Scenario
	if *scenarioPath != "" {
		f, e := os.Open(*scenarioPath)
		if e != nil {
			return e
		}
		b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		ce := f.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
		scenario, e = replay.ParseScenario(b, digest)
		if e != nil {
			return e
		}
		if e = scenario.ValidateTrace(replay.ExtractTrace(capture.Records, replay.ExtractOptions{UDPIdle: *udpIdle}), registry); e != nil {
			return e
		}
	}
	report := compare.Captures(capture.Records, actual, compare.Options{Registry: registry, UDPIdle: *udpIdle, Verify: mode, Scenario: scenario})
	printComparison(os.Stdout, positional[0], positional[1], report, *details)
	if *jsonPath != "" {
		document := struct {
			Tool     string `json:"tool"`
			Version  string `json:"version"`
			Recorded string `json:"recorded"`
			Actual   string `json:"actual"`
			*compare.Report
		}{"livewire", version, positional[0], positional[1], report}
		b, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			return err
		}
		if err := securefile.WriteFileAtomic(*jsonPath, append(b, '\n')); err != nil {
			return fmt.Errorf("write comparison: %w", err)
		}
		fmt.Printf("\nComparison written to %s\n", *jsonPath)
	}
	return nil
}

// parsePositionalArgs accepts up to max bare arguments anywhere on the
// command line, so flags may follow the captures the way a reader expects.
func parsePositionalArgs(fs *flag.FlagSet, args []string, max int) ([]string, error) {
	var positional, flags []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !isFlagArg(arg) {
			positional = append(positional, arg)
			continue
		}
		flags = append(flags, arg)
		name, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if strings.Contains(arg, "=") {
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			continue
		}
		if boolean, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && boolean.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	if len(positional) > max {
		return nil, fmt.Errorf("unexpected extra argument %q; provide at most %d captures", positional[max], max)
	}
	if err := fs.Parse(flags); err != nil {
		return nil, err
	}
	return positional, nil
}

func comparisonLabel(status string) string {
	switch status {
	case compare.Matched:
		return "MATCHED THE CHECKED RESPONSES"
	case compare.Different:
		return "DIFFERENT FROM THE RECORDING"
	case compare.Missing:
		return "MISSING FROM THE ACTUAL CAPTURE"
	case compare.Incomplete:
		return "INCOMPLETE"
	}
	return strings.ToUpper(status)
}

func printComparison(w io.Writer, recordedPath, actualPath string, r *compare.Report, details bool) {
	fmt.Fprintf(w, "Comparing %s (recorded) with %s (actual)\n", filepath.Base(recordedPath), filepath.Base(actualPath))
	if len(r.Sessions) == 0 {
		fmt.Fprintln(w, "\nThe recorded capture holds no sessions to compare.")
	}
	for _, s := range r.Sessions {
		adapter := s.Adapter
		if adapter == "" {
			adapter = "bytes"
		}
		fmt.Fprintf(w, "\n%-10s %-14s fp %s  %s\n", s.RecordedID, adapter, s.Fingerprint, comparisonLabel(s.Status))
		if s.Status == compare.Missing {
			fmt.Fprintln(w, "  no session in the actual capture carried this exchange (same transport and server port)")
			continue
		}
		fmt.Fprintf(w, "  requests: %d recorded, %d actual; replies: %d recorded, %d actual\n",
			s.Recorded.Requests, s.Actual.Requests, s.Recorded.Replies, s.Actual.Replies)
		if d := s.FirstDivergence; d != nil {
			where := fmt.Sprintf("%s stream, byte %d", d.Direction, d.Offset)
			if d.Message > 0 {
				where = fmt.Sprintf("%s %d (byte %d)", d.Direction, d.Message, d.Offset)
			}
			fmt.Fprintf(w, "  first divergence: %s\n    expected  %s\n    actual    %s\n", where, d.Expected, d.Actual)
		}
		if t := s.Timing; t != nil {
			fmt.Fprintf(w, "  reply timing: %.1f ms recorded, %.1f ms actual", t.RecordedResponseMS, t.ActualResponseMS)
			if t.SlowdownFactor >= 2 {
				fmt.Fprintf(w, " (%.0fx slower)", t.SlowdownFactor)
			}
			fmt.Fprintln(w)
		}
		if details {
			for _, d := range s.Differences {
				kind := "value drift"
				if d.Structural {
					kind = "structural"
				}
				fmt.Fprintf(w, "  - %s %s: expected %s, actual %s\n", kind, d.Field, d.Expected, d.Actual)
			}
		}
	}
	if len(r.Unpaired) > 0 {
		fmt.Fprintf(w, "\nSessions only in the actual capture: %s\n", strings.Join(r.Unpaired, ", "))
	}
	fmt.Fprintf(w, "\nOVERALL: %s: %d same as the recording, %d different, %d missing.\n",
		comparisonLabel(r.Verdict), r.Summary.Matched, r.Summary.Different, r.Summary.Missing)
}
