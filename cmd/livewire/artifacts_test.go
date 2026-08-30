package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveOutputPathPreservesExplicitAndVersionsDefaults(t *testing.T) {
	dir := t.TempDir()
	preferred := filepath.Join(dir, "issue.report.json")
	if err := os.WriteFile(preferred, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveOutputPath("", preferred, "-report")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "issue.report-2.json"); got != want {
		t.Fatalf("default output=%q want %q", got, want)
	}
	if _, err := resolveOutputPath(preferred, "", "-report"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("explicit existing output error=%v", err)
	}
}

func TestSameOutputPathNormalizesPaths(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "sub", "..", "evidence.pcap")
	b := filepath.Join(dir, "evidence.pcap")
	if !sameOutputPath(a, b) {
		t.Fatalf("equivalent paths not recognized: %q %q", a, b)
	}
}
