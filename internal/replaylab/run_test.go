package replaylab

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
			cases := []string{"http1", "dns-tcp", "modbus-tcp", "http1-tls", "dns-tls", "modbus-tls", "dnp3", "dnp3-tls", "ftp", "ftps-explicit", "ftps-implicit", "ssh"}
			run, err := Run(ctx, Options{Binary: binary, SourceRoot: root, Output: output, Version: buildinfo.Version, Command: command, Repeat: 2, Cases: cases})
			if err != nil {
				t.Fatalf("whole binary smoke: %v (evidence %s)", err, output)
			}
			if run.Interrupted || !run.CleanupVerified || len(run.Cases) != len(cases) {
				t.Fatalf("incomplete smoke evidence: %+v", run)
			}
			for _, c := range run.Cases {
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
}

func TestLabValidationRejectsAmbiguousRuns(t *testing.T) {
	for _, options := range []Options{{Command: "unknown", Repeat: 2}, {Command: "reproduce", Version: "1.1.0", Repeat: 2}, {Command: "replay", Version: "1.1.0", Repeat: 2}, {Command: "live", Repeat: 1}, {Command: "live", Repeat: 2, Duration: -time.Second}, {Command: "live", Repeat: 2, Cases: []string{"missing"}}, {Command: "live", Repeat: 2, Cases: []string{"http1", "http1"}}} {
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
