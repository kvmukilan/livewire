package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kvmukilan/livewire/internal/iterate"
)

// The point of the shared vocabulary is that a name means the same thing
// everywhere. These cases assert each canonical flag is present on every command
// that should have it, and — just as important — that the older spelling is still
// accepted, because the docs and any script a peer has saved still use it.
//
// The assertions run against the real binary's -all-flags output rather than the
// private flag sets, so they check the surface a user actually sees.
var vocabulary = []struct {
	command   string
	canonical []string
	aliases   []string
}{
	{"reproduce",
		[]string{flagIn, flagIface, flagTarget, flagCount, flagDetails, "gap", "stop-when-different", "wire", "keylog", "user", "host-key", "cmd"},
		[]string{"on", "iface", "to", "target", "times", "iterations"}},
	{"check", []string{flagIn, flagDetails, "json"}, nil},
	{"capture", []string{flagIface, flagOut, flagCount}, []string{"iface", "out", "count"}},
	{"live",
		[]string{flagIn, flagIface, flagTarget, flagCount, flagOut, flagLive},
		[]string{"iface", "target", "out", "times", "iterations", "dry-run"}},
	{"replay", []string{flagIn, flagIface, flagCount}, []string{"iface", "loop"}},
	{"convert", []string{flagIn, flagOut}, []string{"out"}},
	{"rewrite", []string{flagIn, flagOut}, []string{"out"}},
	{"bundle", []string{flagOut, "report"}, []string{"out"}},
	{"tls-replay", []string{flagIn, flagTarget, "keylog"}, []string{"target"}},
	{"ssh-replay", []string{flagIn, flagTarget, "user"}, []string{"target"}},
	{"lab", []string{flagIn, "topology"}, nil},
	{"rstdrop", []string{flagTarget, "port"}, []string{"ip"}},
}

func TestFlagVocabulary(t *testing.T) {
	bin := buildBinary(t)
	for _, c := range vocabulary {
		t.Run(c.command, func(t *testing.T) {
			out, err := runBinary(t, bin, c.command, "-"+allFlagsName)
			if err != nil {
				t.Fatalf("%s -%s failed: %v\n%s", c.command, allFlagsName, err, out)
			}
			declared := declaredFlags(out)
			for _, name := range c.canonical {
				if !declared[name] {
					t.Errorf("%s is missing the canonical flag -%s\ngot: %v", c.command, name, sortedKeys(declared))
				}
			}
			for _, name := range c.aliases {
				if !declared[name] {
					t.Errorf("%s dropped the -%s alias; saved commands and older docs would break", c.command, name)
				}
			}
		})
	}
}

// declaredFlags pulls the flag names out of an -all-flags listing.
func declaredFlags(out string) map[string]bool {
	found := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-") {
			continue
		}
		name := strings.TrimPrefix(line, "-")
		if i := strings.IndexAny(name, " \t"); i >= 0 {
			name = name[:i]
		}
		if name != "" {
			found[name] = true
		}
	}
	return found
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// An alias that parses but writes a different variable is worse than no alias at
// all: the command runs and silently ignores what was asked. Each case below
// passes only the old spelling and asserts the command got past its
// required-argument check, which it can only do if the alias fed the canonical
// variable.
func TestAliasesFeedTheCanonicalFlag(t *testing.T) {
	bin := buildBinary(t)
	pcap := writeHandshakePcap(t, t.TempDir())
	dir := t.TempDir()

	cases := []struct {
		name string
		args []string
		// notWant is output the command would produce only if the alias were
		// ignored; want is output it can only produce if the alias was honoured.
		// Each case sets whichever one distinguishes the two outcomes.
		notWant string
		want    string
	}{
		// Without the alias, outPath stays empty and the command refuses to run.
		{name: "convert -out", args: []string{"convert", "-in", pcap, "-out", filepath.Join(dir, "a.pcap")}, notWant: "are required"},
		{name: "rewrite -out", args: []string{"rewrite", "-in", pcap, "-out", filepath.Join(dir, "b.pcap")}, notWant: "are required"},
		{name: "capture -iface and -out", args: []string{"capture", "-iface", "no-such-device-xyz", "-out", filepath.Join(dir, "c.pcap")}, notWant: "are required"},
		// Without the alias the address is empty and fails to parse.
		{name: "rstdrop -ip", args: []string{"rstdrop", "-ip", "192.0.2.1", "-port", "502"}, notWant: "invalid -t"},
		// Without the alias there is no interface, so it asks for one.
		{name: "replay -iface", args: []string{"replay", "-in", pcap, "-iface", "no-such-device-xyz"}, notWant: "-i is required"},
		// Without the alias -iface is ignored, live stays in dry-run mode and
		// prints its dry-run summary instead of trying to open the device.
		{name: "live -iface selects the on-wire path", args: []string{"live", "-in", pcap, "-iface", "no-such-device-xyz"}, notWant: "maintain sequence numbers coherently"},
		// A negative count is only reachable if -loop fed the same variable as -n;
		// if it were ignored the count would stay at its default of 1 and pass.
		{name: "replay -loop", args: []string{"replay", "-in", pcap, "-loop", "-1"}, want: "cannot be negative"},
		// Likewise for the two -n spellings on reproduce.
		{name: "reproduce -times", args: []string{"reproduce", pcap, "-times", "0"}, want: "-n must be at least 1"},
		{name: "reproduce -iterations", args: []string{"reproduce", pcap, "-iterations", "0"}, want: "-n must be at least 1"},
		{name: "live -times", args: []string{"live", "-in", pcap, "-times", "0"}, want: "-n must be at least 1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Several of these are expected to fail on a missing device or on
			// privileges; what matters is *which* outcome they reach.
			out, _ := runBinary(t, bin, c.args...)
			if c.notWant != "" && strings.Contains(out, c.notWant) {
				t.Errorf("the alias was ignored — output contained %q:\n%s", c.notWant, out)
			}
			if c.want != "" && !strings.Contains(out, c.want) {
				t.Errorf("the alias was ignored — output lacked %q:\n%s", c.want, out)
			}
		})
	}
}

// The front door must show exactly the two primary product commands.
func TestUsageShowsOnlyEverydayCommands(t *testing.T) {
	want := []string{"reproduce", "live"}
	var got []string
	for _, c := range commands {
		if c.group == groupEveryday {
			got = append(got, c.name)
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("everyday commands = %v, want %v", got, want)
	}
}

func TestEveryCommandHasSummaryAndRunner(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range commands {
		if c.name == "" || c.summary == "" || c.run == nil {
			t.Errorf("incomplete command entry: %q", c.name)
		}
		if seen[c.name] {
			t.Errorf("duplicate command name %q", c.name)
		}
		seen[c.name] = true
	}
	// The merged command and both older spellings must all dispatch.
	for _, name := range []string{"check", "info", "analyze"} {
		if !seen[name] {
			t.Errorf("%q is not dispatchable", name)
		}
	}
	for _, name := range []string{"info", "analyze"} {
		for _, c := range commands {
			if c.name == name && c.group != groupCompat {
				t.Errorf("%q should be a compatibility command so it stays off the front door", name)
			}
		}
	}
}

// A single run's report must serialise exactly as it did before iterations
// existed: no attempt numbers, no attempts count, no outcome object. Anything
// already consuming these reports keeps working.
func TestSingleRunReportHasNoIterationFields(t *testing.T) {
	rep := newReplayReport(liveOpts{})
	rep.Sessions = append(rep.Sessions, sessionResult{SessionID: "s1", Completed: true})
	rep.Flows = append(rep.Flows, flowResult{Flow: 0, Succeeded: true})

	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{`"attempt"`, `"attempts"`, `"outcome"`} {
		if bytes.Contains(b, []byte(forbidden)) {
			t.Errorf("a single run's report must not contain %s:\n%s", forbidden, b)
		}
	}
}

func TestRepeatedRunReportRecordsAttemptsAndOutcome(t *testing.T) {
	rep := newReplayReport(liveOpts{})
	rep.startAttempt(1)
	rep.Sessions = append(rep.Sessions, sessionResult{Attempt: rep.attempt, SessionID: "s1", Completed: true, Matched: true})
	rep.startAttempt(2)
	rep.Sessions = append(rep.Sessions, sessionResult{Attempt: rep.attempt, SessionID: "s1", Completed: true})
	rep.recordIterations(iterate.Summarize([]iterate.Tally{{Same: 1}, {Different: 1}}, 2))

	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Attempts int `json:"attempts"`
		Outcome  struct {
			Attempts     int    `json:"attempts"`
			Same         int    `json:"sameAsRecording"`
			Different    int    `json:"different"`
			Verdict      string `json:"verdict"`
			Intermittent bool   `json:"intermittent"`
		} `json:"outcome"`
		Sessions []struct {
			Attempt int `json:"attempt"`
		} `json:"sessions"`
		Transformations []string `json:"transformations"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Attempts != 2 {
		t.Errorf("attempts = %d, want 2", doc.Attempts)
	}
	if doc.Outcome.Same != 1 || doc.Outcome.Different != 1 {
		t.Errorf("outcome counts = %+v, want 1 same / 1 different", doc.Outcome)
	}
	if doc.Outcome.Verdict != "different" || !doc.Outcome.Intermittent {
		t.Errorf("outcome verdict=%q intermittent=%v, want \"different\" and true", doc.Outcome.Verdict, doc.Outcome.Intermittent)
	}
	if len(doc.Sessions) != 2 || doc.Sessions[0].Attempt != 1 || doc.Sessions[1].Attempt != 2 {
		t.Errorf("sessions did not record their attempt numbers: %+v", doc.Sessions)
	}
	// The reader needs to know the client port moved deliberately, or the
	// evidence pcap looks like it does not match the capture.
	found := false
	for _, tr := range doc.Transformations {
		if strings.Contains(tr, "fresh client port") {
			found = true
		}
	}
	if !found {
		t.Errorf("the per-attempt port change was not disclosed: %v", doc.Transformations)
	}
}

// End-to-end through the real binary: the front door, the merged command, both
// older spellings, and the guardrails on -n.
func TestBinarySurface(t *testing.T) {
	bin := buildBinary(t)
	pcap := writeHandshakePcap(t, t.TempDir())

	t.Run("no args opens the unified help hub", func(t *testing.T) {
		out, err := runBinary(t, bin)
		if err != nil {
			t.Fatalf("the help hub should exit successfully: %v\n%s", err, out)
		}
		for _, name := range []string{"reproduce", "live"} {
			if !strings.Contains(out, name) {
				t.Errorf("front door is missing %q:\n%s", name, out)
			}
		}
		for _, name := range []string{"rstdrop", "rewrite", "tls-replay", "livewire check", "livewire capture", "livewire web"} {
			if strings.Contains(out, name) {
				t.Errorf("front door should not list the advanced command %q:\n%s", name, out)
			}
		}
		for _, topic := range []string{"help examples", "help troubleshoot", "help protocols", "help diagnose", "help commands", "help <command>"} {
			if !strings.Contains(out, topic) {
				t.Errorf("help hub is missing topic %q:\n%s", topic, out)
			}
		}
	})

	t.Run("successful top-level help uses stdout only", func(t *testing.T) {
		stdout, stderr, err := runBinaryStreams(t, bin, "help")
		if err != nil {
			t.Fatalf("help failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
		}
		if stderr != "" {
			t.Errorf("successful help must not look like a PowerShell error; stderr was:\n%s", stderr)
		}
		if !strings.Contains(stdout, "Two commands cover the normal workflow:") {
			t.Errorf("stdout did not contain the help hub:\n%s", stdout)
		}
	})

	t.Run("unified help topics give workflows and recovery", func(t *testing.T) {
		cases := []struct {
			topic string
			want  []string
		}{
			{topic: "examples", want: []string{"-n 5", "-keylog", "--wire"}},
			{topic: "troubleshoot", want: []string{"livewire ifaces", "Administrator", "Npcap"}},
			{topic: "protocols", want: []string{"TLS and FTPS", "DNP3 Secure Authentication", "--wire"}},
			{topic: "diagnose", want: []string{"assessment.json", "-n 5", "support.zip"}},
			{topic: "commands", want: []string{"Primary commands:", "Advanced commands:", "tls-replay"}},
		}
		for _, tc := range cases {
			t.Run(tc.topic, func(t *testing.T) {
				out, err := runBinary(t, bin, "help", tc.topic)
				if err != nil {
					t.Fatalf("help %s failed: %v\n%s", tc.topic, err, out)
				}
				for _, want := range tc.want {
					if !strings.Contains(out, want) {
						t.Errorf("help %s is missing %q:\n%s", tc.topic, want, out)
					}
				}
			})
		}
	})

	t.Run("help --all lists everything", func(t *testing.T) {
		out, err := runBinary(t, bin, "help", "--all")
		if err != nil {
			t.Fatalf("help --all failed: %v\n%s", err, out)
		}
		for _, name := range []string{"live", "lab", "rewrite", "rstdrop", "info", "analyze"} {
			if !strings.Contains(out, name) {
				t.Errorf("help --all is missing %q:\n%s", name, out)
			}
		}
	})

	t.Run("check summarises and assesses", func(t *testing.T) {
		out, err := runBinary(t, bin, "check", pcap)
		if err != nil {
			t.Fatalf("check failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, "packets:") {
			t.Errorf("check did not print the capture summary:\n%s", out)
		}
	})

	t.Run("check accepts -in as well as a bare path", func(t *testing.T) {
		out, err := runBinary(t, bin, "check", "-in", pcap)
		if err != nil {
			t.Fatalf("check -in failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, "packets:") {
			t.Errorf("check -in did not print the summary:\n%s", out)
		}
	})

	t.Run("info still prints only the summary", func(t *testing.T) {
		out, err := runBinary(t, bin, "info", pcap)
		if err != nil {
			t.Fatalf("info failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, "packets:") {
			t.Errorf("info lost its summary:\n%s", out)
		}
		if strings.Contains(out, "Replay plan") {
			t.Errorf("info must not have grown the assessment output:\n%s", out)
		}
	})

	t.Run("analyze still prints only the assessment", func(t *testing.T) {
		out, err := runBinary(t, bin, "analyze", "-in", pcap)
		if err != nil {
			t.Fatalf("analyze failed: %v\n%s", err, out)
		}
		if strings.Contains(out, "file format:") {
			t.Errorf("analyze must not have grown the capture summary:\n%s", out)
		}
	})

	t.Run("check -json matches analyze -json", func(t *testing.T) {
		dir := t.TempDir()
		fromCheck := filepath.Join(dir, "check.json")
		fromAnalyze := filepath.Join(dir, "analyze.json")
		if out, err := runBinary(t, bin, "check", pcap, "-json", fromCheck); err != nil {
			t.Fatalf("check -json: %v\n%s", err, out)
		}
		if out, err := runBinary(t, bin, "analyze", "-in", pcap, "-json", fromAnalyze); err != nil {
			t.Fatalf("analyze -json: %v\n%s", err, out)
		}
		a, err := os.ReadFile(fromCheck)
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(fromAnalyze)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("check -json and analyze -json disagree:\n--- check ---\n%s\n--- analyze ---\n%s", a, b)
		}
	})

	t.Run("repeating a dry run is refused with a reason", func(t *testing.T) {
		out, err := runBinary(t, bin, "live", "-in", pcap, "-n", "3")
		if err == nil {
			t.Errorf("repeating a deterministic dry run should fail:\n%s", out)
		}
		if !strings.Contains(out, "-n only applies to an on-wire replay") {
			t.Errorf("unhelpful message for -n in dry-run mode:\n%s", out)
		}
	})

	t.Run("-n below 1 is rejected", func(t *testing.T) {
		if out, err := runBinary(t, bin, "reproduce", pcap, "-n", "0"); err == nil {
			t.Errorf("-n 0 should fail:\n%s", out)
		}
	})

	t.Run("asking for help is not a failure", func(t *testing.T) {
		for _, args := range [][]string{{"reproduce", "-h"}, {"help", "reproduce"}, {"help"}, {"help", "examples"}, {"help", "troubleshoot"}, {"help", "protocols"}, {"help", "diagnose"}, {"help", "commands"}, {"help", "--all"}} {
			if out, err := runBinary(t, bin, args...); err != nil {
				t.Errorf("%v should exit 0, got %v:\n%s", args, err, out)
			}
		}
	})

	t.Run("help names an unknown topic and points back to the hub", func(t *testing.T) {
		out, err := runBinary(t, bin, "help", "nonsense")
		if err == nil {
			t.Errorf("help for an unknown command should fail:\n%s", out)
		}
		if !strings.Contains(out, "nonsense") {
			t.Errorf("the error should name what was not found:\n%s", out)
		}
		if !strings.Contains(out, "livewire help") {
			t.Errorf("the error should point back to the unified hub:\n%s", out)
		}
	})

	t.Run("command and help typos get a useful suggestion", func(t *testing.T) {
		out, err := runBinary(t, bin, "reprodce")
		if err == nil || !strings.Contains(out, "livewire reproduce") {
			t.Errorf("command typo should suggest reproduce; err=%v\n%s", err, out)
		}
		out, err = runBinary(t, bin, "help", "reprodce")
		if err == nil || !strings.Contains(out, "livewire help reproduce") {
			t.Errorf("help typo should suggest help reproduce; err=%v\n%s", err, out)
		}
	})

	t.Run("reproduce help hides the expert flags", func(t *testing.T) {
		out, err := runBinary(t, bin, "reproduce", "-h")
		if err != nil {
			t.Fatal(err)
		}
		for _, shown := range []string{"-in", "-t", "-i", "-n", "-details"} {
			if !strings.Contains(out, shown) {
				t.Errorf("reproduce help should show %s:\n%s", shown, out)
			}
		}
		for _, hidden := range []string{"-udp-idle", "-no-rst-guard", "-rules"} {
			if strings.Contains(out, hidden) {
				t.Errorf("reproduce help should not show %s by default:\n%s", hidden, out)
			}
		}
		if !strings.Contains(out, "-"+allFlagsName) {
			t.Errorf("reproduce help should point at -%s:\n%s", allFlagsName, out)
		}
	})

	t.Run("all-flags lists the hidden ones and marks aliases", func(t *testing.T) {
		out, err := runBinary(t, bin, "reproduce", "-"+allFlagsName)
		if err != nil {
			t.Fatalf("reproduce -%s failed: %v\n%s", allFlagsName, err, out)
		}
		for _, name := range []string{"-udp-idle", "-no-rst-guard", "-rules", "-stop-when-different", "-gap"} {
			if !strings.Contains(out, name) {
				t.Errorf("-%s is missing %s:\n%s", allFlagsName, name, out)
			}
		}
		if !strings.Contains(out, "(alias)") {
			t.Errorf("-%s should mark the compatibility aliases:\n%s", allFlagsName, out)
		}
	})
}

// buildBinary compiles the CLI once per test run. Several tests shell out to it,
// and a fresh `go build` per subtest dominated the runtime.
var (
	binOnce sync.Once
	binPath string
	binErr  error
)

func buildBinary(t *testing.T) string {
	t.Helper()
	binOnce.Do(func() {
		dir, err := os.MkdirTemp("", "livewire-cli-test")
		if err != nil {
			binErr = err
			return
		}
		binPath = filepath.Join(dir, "livewire.exe")
		if out, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput(); err != nil {
			binErr = err
			t.Logf("build output:\n%s", out)
		}
	})
	if binErr != nil {
		t.Fatalf("building the CLI failed: %v", binErr)
	}
	return binPath
}

func runBinary(t *testing.T, bin string, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	return string(out), err
}

func runBinaryStreams(t *testing.T, bin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var stdoutBuffer, stderrBuffer bytes.Buffer
	cmd.Stdout = &stdoutBuffer
	cmd.Stderr = &stderrBuffer
	err = cmd.Run()
	return stdoutBuffer.String(), stderrBuffer.String(), err
}
