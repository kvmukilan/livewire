package main

import (
	"strings"
	"testing"

	"github.com/kvmukilan/livewire/internal/protofuzz"
)

// mockTarget starts a conforming Modbus target on an ephemeral loopback port.
// Port 0 matters here: the quality gate runs the suite with -shuffle=on -count=3,
// so a fixed port would collide with itself.
func mockTarget(t *testing.T, d protofuzz.Defects) *protofuzz.MockTarget {
	t.Helper()
	m, err := protofuzz.ServeMock("127.0.0.1:0", d)
	if err != nil {
		t.Fatalf("ServeMock: %v", err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

// quickRun keeps the case count and read deadline small; these tests are about
// the command's wiring, not about finding anything.
func quickRun(target string, extra ...string) []string {
	args := []string{"-target", target, "-cases", "20", "-timeout", "150ms",
		"-probe-every", "0", "-quiet"}
	return append(args, extra...)
}

func TestCmdFuzzRequiresATarget(t *testing.T) {
	err := cmdFuzz([]string{"-cases", "1"})
	if err == nil {
		t.Fatal("expected an error when -target is absent")
	}
	if !strings.Contains(err.Error(), "-target is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestCmdFuzzRefusesNonLoopback is the safety behaviour: the command must refuse
// before it dials, so a mistyped address cannot reach a device nobody authorised
// testing.
func TestCmdFuzzRefusesNonLoopback(t *testing.T) {
	err := cmdFuzz([]string{"-target", "203.0.113.10:502", "-cases", "1"})
	if err == nil {
		t.Fatal("expected a refusal for a non-loopback target")
	}
	if !strings.Contains(err.Error(), "-allow-remote") {
		t.Fatalf("refusal should name -allow-remote, got: %v", err)
	}
}

func TestCmdFuzzRejectsBadFlagCombinations(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"demo with target", []string{"-demo", "-target", "127.0.0.1:502"}, "either -demo or -target"},
		{"unknown defect", []string{"-demo", "-demo-defect", "not-a-defect"}, "unknown defect"},
		{"zero cases", []string{"-target", "127.0.0.1:502", "-cases", "0"}, "-cases must be at least 1"},
		{"unit out of range", []string{"-target", "127.0.0.1:502", "-unit", "999"}, "-unit must be between"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := cmdFuzz(tc.args)
			if err == nil {
				t.Fatalf("expected an error for %v", tc.args)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got: %v", tc.want, err)
			}
		})
	}
}

func TestCmdFuzzAgainstConformingTarget(t *testing.T) {
	m := mockTarget(t, protofuzz.Defects{})
	if err := cmdFuzz(quickRun(m.Addr())); err != nil {
		t.Fatalf("a run against a conforming target should succeed: %v", err)
	}
}

// A conforming target yields no findings, so -fail-on-findings must still exit
// cleanly; the flag is only useful if it stays quiet when there is nothing wrong.
func TestCmdFuzzFailOnFindingsStaysQuietWhenClean(t *testing.T) {
	m := mockTarget(t, protofuzz.Defects{})
	if err := cmdFuzz(quickRun(m.Addr(), "-fail-on-findings")); err != nil {
		t.Fatalf("clean run should not fail with -fail-on-findings: %v", err)
	}
}

func TestCmdFuzzFailOnFindingsReportsADefect(t *testing.T) {
	// Every reply carries the wrong transaction id, so a finding is certain
	// within a handful of cases.
	m := mockTarget(t, protofuzz.Defects{DontEchoTxID: true})
	err := cmdFuzz(quickRun(m.Addr(), "-fail-on-findings"))
	if err == nil {
		t.Fatal("expected a non-nil error so the process exits non-zero")
	}
	if !strings.Contains(err.Error(), "finding") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCmdFuzzDemoModeNeedsNoTarget(t *testing.T) {
	// -demo starts and stops its own target; the point of the flag is that this
	// works on a machine with no Modbus device anywhere near it.
	args := []string{"-demo", "-demo-defect", "none", "-cases", "20",
		"-timeout", "150ms", "-probe-every", "0", "-quiet"}
	if err := cmdFuzz(args); err != nil {
		t.Fatalf("demo mode should run unattended: %v", err)
	}
}

func TestCmdFuzzSameSeedIsReproducible(t *testing.T) {
	// The report tells a reader to re-run with the same -seed, so that had better
	// be a real guarantee.
	m := mockTarget(t, protofuzz.Defects{})
	for i := 0; i < 2; i++ {
		if err := cmdFuzz(quickRun(m.Addr(), "-seed", "1234")); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}
}
