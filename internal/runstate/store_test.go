package runstate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testManifest() Manifest {
	return Manifest{Version: Version, CaptureDigest: "capture", ConfigurationDigest: "config"}
}
func TestCrashResumeDoesNotRepeatUncertainWrites(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	s, e := Open(dir, testManifest(), false, false)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Begin("1/tcp-0", false); e != nil {
		t.Fatal(e)
	}
	if e = s.Record("1/tcp-0", "intent", 1); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(dir, testManifest(), true, false)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.Begin("1/tcp-0", false); e == nil || !strings.Contains(e.Error(), "uncertain") {
		t.Fatalf("unsafe resume: %v", e)
	}
	if _, e = s.Begin("1/tcp-0", true); e != nil {
		t.Fatal(e)
	}
	if e = s.Record("1/tcp-0", "ack", 1); e != nil {
		t.Fatal(e)
	}
	if e = s.Finish("1/tcp-0", Result{Completed: true, Verified: true, Matched: true, Sent: 1, Received: 1}); e != nil {
		t.Fatal(e)
	}
	r, e := s.Begin("1/tcp-0", false)
	if e != nil || r == nil || !r.Matched {
		t.Fatalf("lost completion %v %v", r, e)
	}
}
func TestJournalLockAndIdentity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	s, e := Open(dir, testManifest(), false, false)
	if e != nil {
		t.Fatal(e)
	}
	if other, e := Open(dir, testManifest(), true, false); e == nil {
		other.Close()
		t.Fatal("concurrent writer accepted")
	}
	s.Close()
	m := testManifest()
	m.ConfigurationDigest = "changed"
	if other, e := Open(dir, m, true, false); e == nil {
		other.Close()
		t.Fatal("changed configuration accepted")
	}
}
func TestJournalTailRecoveryAndCommittedCorruption(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "partial-tail", true: "committed-corruption"}[corrupt], func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "run")
			s, e := Open(dir, testManifest(), false, false)
			if e != nil {
				t.Fatal(e)
			}
			s.Begin("1/tcp", false)
			s.Close()
			path := filepath.Join(dir, "journal.jsonl")
			b, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			if corrupt {
				b = bytes.Replace(b, []byte("begin"), []byte("bogus"), 1)
			} else {
				b = append(b, []byte(`{"sequence":2`)...)
			}
			if e = os.WriteFile(path, b, 0600); e != nil {
				t.Fatal(e)
			}
			s, e = Open(dir, testManifest(), true, false)
			if corrupt {
				if e == nil {
					s.Close()
					t.Fatal("corruption accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if e = s.Record("1/tcp", "intent", 1); e != nil {
				t.Fatal(e)
			}
			s.Close()
			s, e = Open(dir, testManifest(), true, false)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			if !s.Progress()["1/tcp"].Uncertain {
				t.Fatal("lost tail replacement")
			}
		})
	}
}
func TestPreviewDoesNotMutateAndFailedWritesStop(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	s, e := Open(dir, testManifest(), false, false)
	if e != nil {
		t.Fatal(e)
	}
	s.Begin("1/tcp", false)
	s.Close()
	path := filepath.Join(dir, "journal.jsonl")
	before, _ := os.ReadFile(path)
	s, e = Open(dir, testManifest(), true, true)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Record("1/tcp", "intent", 1); e == nil {
		t.Fatal("preview wrote journal")
	}
	s.Close()
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("preview mutated progress")
	}
	s, e = Open(dir, testManifest(), true, false)
	if e != nil {
		t.Fatal(e)
	}
	s.journal.Close()
	if e = s.Record("1/tcp", "intent", 1); e == nil {
		t.Fatal("failed write ignored")
	}
	if _, e = s.Begin("1/other", true); e == nil {
		t.Fatal("continued after persistence failure")
	}
	s.Close()
}
