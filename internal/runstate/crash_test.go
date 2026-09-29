package runstate

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The parent kills an actual process without Close: this exercises OS lock
// release and journal durability, rather than only reopening a clean store.
func TestJournalCrashHelper(t *testing.T) {
	dir := os.Getenv("LIVEWIRE_JOURNAL_CRASH_DIR")
	if dir == "" {
		return
	}
	phase := os.Getenv("LIVEWIRE_JOURNAL_CRASH_PHASE")
	s, e := Open(dir, testManifest(), false, false)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Begin("1/s", false); e != nil {
		t.Fatal(e)
	}
	if phase != "before-send" {
		if e = s.Record("1/s", "intent", 1); e != nil {
			t.Fatal(e)
		}
	}
	if phase == "after-response" || phase == "completed" {
		if e = s.Record("1/s", "ack", 1); e != nil {
			t.Fatal(e)
		}
	}
	if phase == "completed" {
		if e = s.Finish("1/s", Result{Completed: true, Verified: true, Matched: true, Sent: 1, Received: 1}); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.WriteFile(filepath.Join(dir, "ready"), []byte("ready"), 0600); e != nil {
		t.Fatal(e)
	}
	time.Sleep(time.Hour)
}

func TestProcessTerminationResumeDecisions(t *testing.T) {
	for _, phase := range []string{"before-send", "after-send", "after-response", "completed"} {
		t.Run(phase, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "run")
			cmd := exec.Command(os.Args[0], "-test.run=^TestJournalCrashHelper$")
			cmd.Env = append(os.Environ(), "LIVEWIRE_JOURNAL_CRASH_DIR="+dir, "LIVEWIRE_JOURNAL_CRASH_PHASE="+phase)
			if e := cmd.Start(); e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() {
				if cmd.ProcessState == nil {
					cmd.Process.Kill()
					cmd.Wait()
				}
			})
			deadline := time.Now().Add(10 * time.Second)
			for {
				if _, e := os.Stat(filepath.Join(dir, "ready")); e == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("child did not reach crash point")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if e := cmd.Process.Kill(); e != nil {
				t.Fatal(e)
			}
			_ = cmd.Wait()
			s, e := Open(dir, testManifest(), true, false)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			saved, e := s.Begin("1/s", false)
			switch phase {
			case "after-send", "after-response":
				if e == nil || saved != nil {
					t.Fatalf("uncertain operation retried: %+v %v", saved, e)
				}
			case "before-send":
				if e != nil || saved != nil {
					t.Fatalf("unsent operation blocked: %+v %v", saved, e)
				}
			case "completed":
				if e != nil || saved == nil || !saved.Matched {
					t.Fatalf("confirmed operation lost: %+v %v", saved, e)
				}
			}
		})
	}
}

func TestOwnedResourceAndEvidenceReferencesSurviveCrash(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	s, e := Open(dir, testManifest(), false, false)
	if e != nil {
		t.Fatal(e)
	}
	owner := s.Owner()
	resource := Resource{Owner: owner, Target: "192.0.2.1", TargetPort: 502, LocalPort: 40000}
	if e = s.ResourceIntent("1/s", resource); e != nil {
		t.Fatal(e)
	}
	if e = s.EvidenceReference("partial.pcap", false); e != nil {
		t.Fatal(e)
	}
	if e = s.EvidenceReference("actual.pcap", true); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(dir, testManifest(), true, false)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if s.Owner() != owner || s.Resources()["1/s"] != resource || len(s.artifacts) != 2 {
		t.Fatal("lost owned resource or evidence references")
	}
	if e = s.ResourceReleased("1/s"); e != nil {
		t.Fatal(e)
	}
	if len(s.Resources()) != 0 {
		t.Fatal("released resource still pending")
	}
}
