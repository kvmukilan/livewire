package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestDoctorStructuredReadiness(t *testing.T) {
	for _, tc := range []struct {
		name     string
		findings []doctorFinding
		writeErr error
		blocked  bool
	}{
		{"ready", nil, nil, false},
		{"no-packet-privilege", []doctorFinding{{"privilege", "warning", "not elevated", "use doctor -i"}}, nil, false},
		{"missing-driver", []doctorFinding{{"driver", "blocker", "missing", "install driver"}}, nil, true},
		{"disk-full", nil, errors.New("no space left on device"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := runDoctor([]string{"--json"}, &out, doctorDeps{
				interfaces: func() ([]net.Interface, error) { return nil, nil },
				platform:   func(string) []doctorFinding { return tc.findings },
				writable:   func(string) error { return tc.writeErr },
			})
			var r doctorReport
			if e := json.Unmarshal(out.Bytes(), &r); e != nil {
				t.Fatal(e, out.String())
			}
			if (err != nil) != tc.blocked || r.Ready == tc.blocked {
				t.Fatalf("ready=%v error=%v", r.Ready, err)
			}
			for _, f := range r.Findings {
				if f.Code == "" || f.Severity == "" || f.Message == "" || f.NextAction == "" {
					t.Fatalf("incomplete finding: %+v", f)
				}
			}
		})
	}
}

func TestDoctorDownInterfaceAndOutputCleanup(t *testing.T) {
	dir := t.TempDir()
	if err := probeOutputDir(dir); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("probe left artifacts", entries)
	}
	missing := filepath.Join(dir, "missing")
	if err := probeOutputDir(missing); err == nil {
		t.Fatal("missing directory accepted")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("probe created directory")
	}
	var out bytes.Buffer
	err := runDoctor([]string{"-i", "test", "--json"}, &out, doctorDeps{
		interfaces: func() ([]net.Interface, error) { return []net.Interface{{Name: "test"}}, nil },
		platform:   func(string) []doctorFinding { return nil },
		writable:   func(string) error { return nil },
	})
	if err == nil || !bytes.Contains(out.Bytes(), []byte("interface-down")) {
		t.Fatal(err, out.String())
	}
}
