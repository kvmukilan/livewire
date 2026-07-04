//go:build linux

package hoststack

import (
	"net/netip"
	"strings"
	"testing"
)

// TestIptablesArmDisarmRunner runs the exec path with a fake runner (no root):
// Arm inserts, Disarm deletes the matching rule.
func TestIptablesArmDisarmRunner(t *testing.T) {
	var calls [][]string
	fake := func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	s := &iptablesSuppressor{
		rule: Rule{TargetIP: netip.MustParseAddr("10.0.0.1"), TargetPort: 502, LocalPort: 40000},
		bin:  "iptables",
		run:  fake,
	}
	// Arm calls LookPath for the binary; skip if iptables is absent on this host.
	if err := s.Arm(); err != nil {
		if strings.Contains(err.Error(), "not found in PATH") {
			t.Skip("iptables not installed; runner path still covered by Disarm")
		}
		t.Fatalf("Arm: %v", err)
	}
	if err := s.Disarm(); err != nil {
		t.Fatalf("Disarm: %v", err)
	}
	if len(calls) < 2 {
		t.Fatalf("expected insert+delete calls, got %v", calls)
	}
	if calls[0][1] != "-I" {
		t.Fatalf("first call should insert: %v", calls[0])
	}
	last := calls[len(calls)-1]
	if last[1] != "-D" {
		t.Fatalf("last call should delete: %v", last)
	}
}

func TestIptablesDisarmSwallowsMissing(t *testing.T) {
	fake := func(name string, args ...string) ([]byte, error) {
		return []byte("iptables: Bad rule (does a matching rule exist in that chain?)."), errFake{}
	}
	s := &iptablesSuppressor{
		rule: Rule{TargetIP: netip.MustParseAddr("10.0.0.1"), TargetPort: 502},
		bin:  "iptables",
		run:  fake,
	}
	if err := s.Disarm(); err != nil {
		t.Fatalf("Disarm should swallow 'no matching rule', got %v", err)
	}
}

type errFake struct{}

func (errFake) Error() string { return "exit status 1" }
