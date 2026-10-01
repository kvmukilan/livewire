package replaylab

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/buildinfo"
	"github.com/kvmukilan/livewire/internal/qualification"
)

func TestWholeBinaryDefaultFrontDoorsAgainstIndependentStreamPeers(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "livewire")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, "./cmd/livewire")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build actual CLI: %v\n%s", err, output)
	}
	for _, command := range []string{"live"} {
		t.Run(command, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			output := t.TempDir()
			cases := []string{"http1", "dns-tcp", "modbus-tcp", "http1-tls", "dns-tls", "modbus-tls", "dnp3", "dnp3-tls", "ftp", "ftps-explicit", "ftps-implicit", "ssh", "tls-handshake"}
			run, err := Run(ctx, Options{Binary: binary, SourceRoot: root, Output: output, Version: buildinfo.Version, Command: command, Repeat: 2, Cases: cases})
			if err != nil {
				t.Fatalf("whole binary smoke: %v (evidence %s)", err, output)
			}
			if run.Interrupted || !run.CleanupVerified || len(run.Cases) != len(cases) {
				t.Fatalf("incomplete smoke evidence: %+v", run)
			}
			for _, c := range run.Cases {
				if c.Name == "tls-handshake" {
					if c.Passes != 3 || c.Failures != 0 || c.RepeatedProcessPasses != 3 || c.RequestsObserved != 0 || c.ResponsesVerified != 0 || c.HandshakesObserved != 6 || !c.CleanupVerified {
						t.Fatalf("handshake observations mislabeled or incomplete: %+v", c)
					}
					continue
				}
				if c.Passes != 3 || c.Failures != 0 || c.RepeatedProcessPasses != 3 || c.RequestsObserved < 12 || c.ResponsesVerified < 12 || !c.CleanupVerified {
					t.Fatalf("insufficient independent checks: %+v", c)
				}
			}
			data, err := os.ReadFile(filepath.Join(output, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			var recorded qualification.LabRun
			if err = json.Unmarshal(data, &recorded); err != nil || recorded.BinarySHA256 != run.BinarySHA256 || recorded.SourceDigest != run.SourceDigest {
				t.Fatalf("recorded binding differs: %v", err)
			}
			for _, evidence := range recorded.Evidence {
				sum, err := qualification.FileSHA256(filepath.Join(output, filepath.FromSlash(evidence.Path)))
				if err != nil || sum != evidence.SHA256 {
					t.Fatalf("evidence changed: %s %v", evidence.Path, err)
				}
			}
		})
	}
	for _, mode := range []string{"during-process", "between-processes", "backward-clock"} {
		t.Run("host-suspend-"+mode, func(t *testing.T) {
			base, calls := time.Now().UTC(), 0
			clock := func() time.Time {
				calls++
				if mode == "during-process" && calls >= 2 || mode == "between-processes" && calls >= 3 {
					return base.Add(8 * time.Hour)
				}
				if mode == "backward-clock" && calls >= 2 {
					return base.Add(-time.Hour)
				}
				return base.Add(time.Duration(calls) * time.Second)
			}
			output := t.TempDir()
			run, err := Run(context.Background(), Options{Binary: binary, SourceRoot: root, Output: output, Version: buildinfo.Version, Command: "live", Repeat: 2, Cases: []string{"http1"}, clock: clock})
			if err == nil || !strings.Contains(err.Error(), "lab continuity") || !run.Interrupted || !run.CleanupVerified || len(run.Cases) != 1 || run.Cases[0].Failures != 1 {
				t.Fatalf("suspended run credited or not cleaned: result=%+v err=%v", run, err)
			}
			wantPasses := 0
			if mode == "between-processes" {
				wantPasses = 1
			}
			if run.Cases[0].Passes != wantPasses {
				t.Fatalf("resumed process credited: %+v", run.Cases[0])
			}
			data, err := os.ReadFile(filepath.Join(output, "transcript.jsonl"))
			if err != nil || !strings.Contains(string(data), "lab continuity") {
				t.Fatalf("failure diagnostic missing: %v", err)
			}
		})
	}
}

func TestLabValidationRejectsAmbiguousRuns(t *testing.T) {
	for _, options := range []Options{{Command: "unknown", Repeat: 2}, {Command: "reproduce", Version: "1.1.0", Repeat: 2}, {Command: "replay", Version: "1.1.0", Repeat: 2}, {Command: "live", Repeat: 1}, {Command: "live", Repeat: 2, Duration: -time.Second}, {Command: "live", Version: "1.1.0", Repeat: 2, Interval: 61 * time.Second}, {Command: "live", Version: "1.1.0", Repeat: 2, ProcessTimeout: 121 * time.Second}, {Command: "live", Repeat: 2, Cases: []string{"missing"}}, {Command: "live", Repeat: 2, Cases: []string{"http1", "http1"}}} {
		if _, err := Run(context.Background(), options); err == nil {
			t.Fatalf("invalid options accepted: %+v", options)
		}
	}
}

func TestLabOutputBoundsAndCredentialRedaction(t *testing.T) {
	var output limitedBuffer
	data := make([]byte, 256<<10)
	if n, err := output.Write(data); err != nil || n != len(data) || output.Len() != 128<<10 {
		t.Fatalf("output was not bounded: n=%d len=%d err=%v", n, output.Len(), err)
	}
	if got := redactOutput("password=synthetic-secret", []string{"-pass", "synthetic-secret"}); got != "password=<redacted>" {
		t.Fatalf("credential leaked: %q", got)
	}
}
