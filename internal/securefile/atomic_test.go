package securefile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWriteFileAtomicPublishesPrivateFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	target := filepath.Join(dir, "report.json")
	if err := WriteFileAtomic(target, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "secret" {
		t.Fatalf("data=%q err=%v", data, err)
	}
	if runtime.GOOS != "windows" {
		if mode := mustStat(t, target).Mode().Perm(); mode != 0o600 {
			t.Fatalf("file mode=%#o", mode)
		}
		if mode := mustStat(t, dir).Mode().Perm(); mode != 0o700 {
			t.Fatalf("directory mode=%#o", mode)
		}
	}
}

func TestWriteAtomicFailureLeavesNoArtifactOrTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "evidence.pcap")
	want := errors.New("short write")
	err := WriteAtomic(target, func(w io.Writer) error {
		if _, err := w.Write([]byte("partial")); err != nil {
			return err
		}
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("error=%v", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial target exists: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Fatalf("temporary file leaked: %s", entry.Name())
		}
	}
}

func TestAbortAndInvalidCommitAreIdempotent(t *testing.T) {
	a, err := Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Abort(); err != nil {
		t.Fatal(err)
	}
	if err := a.Abort(); err != nil {
		t.Fatal(err)
	}
	if err := a.Commit(); err == nil {
		t.Fatal("commit after abort succeeded")
	}
}

func TestCloseFailureDoesNotPublishArtifact(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "capture.pcap")
	a, err := Create(target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	if err := a.File().Close(); err != nil {
		t.Fatal(err)
	}
	if err := a.Commit(); err == nil {
		t.Fatal("commit unexpectedly ignored a closed output file")
	}
	if err := a.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial artifact was published: %v", err)
	}
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}
