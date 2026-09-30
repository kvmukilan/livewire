package hoststack

import (
	"errors"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestIptablesArgsSymmetry(t *testing.T) {
	r := Rule{TargetIP: netip.MustParseAddr("10.0.0.1"), TargetPort: 502, LocalPort: 40000}
	ins := iptablesArgs(r, "-I")
	del := iptablesArgs(r, "-D")

	if ins[0] != "-I" || del[0] != "-D" {
		t.Fatalf("op not first arg: %v / %v", ins[0], del[0])
	}
	// Disarm must match Arm exactly except for the op, or the rule leaks.
	if strings.Join(ins[1:], " ") != strings.Join(del[1:], " ") {
		t.Fatalf("insert/delete matches differ:\n  ins %v\n  del %v", ins, del)
	}
	joined := strings.Join(ins, " ")
	for _, want := range []string{"OUTPUT", "--tcp-flags RST RST", "-d 10.0.0.1", "--dport 502", "--sport 40000", "-j DROP"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("rule missing %q: %s", want, joined)
		}
	}
}

func TestIptablesArgsNoLocalPort(t *testing.T) {
	r := Rule{TargetIP: netip.MustParseAddr("10.0.0.1"), TargetPort: 502}
	joined := strings.Join(iptablesArgs(r, "-I"), " ")
	if strings.Contains(joined, "--sport") {
		t.Fatalf("no LocalPort should omit --sport: %s", joined)
	}
}

func TestIptablesBinByFamily(t *testing.T) {
	v4 := Rule{TargetIP: netip.MustParseAddr("10.0.0.1"), TargetPort: 502}
	v6 := Rule{TargetIP: netip.MustParseAddr("fd00::1"), TargetPort: 502}
	if iptablesBin(v4) != "iptables" {
		t.Fatalf("v4 should use iptables, got %s", iptablesBin(v4))
	}
	if iptablesBin(v6) != "ip6tables" {
		t.Fatalf("v6 should use ip6tables, got %s", iptablesBin(v6))
	}
}

func TestWinDivertFilter(t *testing.T) {
	r := Rule{TargetIP: netip.MustParseAddr("10.0.0.1"), TargetPort: 502, LocalPort: 40000}
	f := winDivertFilter(r)
	for _, want := range []string{"outbound", "tcp.Rst", "ip.DstAddr == 10.0.0.1", "tcp.DstPort == 502", "tcp.SrcPort == 40000"} {
		if !strings.Contains(f, want) {
			t.Fatalf("filter missing %q: %s", want, f)
		}
	}
	// IPv6 target must use the ipv6 address predicate.
	v6 := winDivertFilter(Rule{TargetIP: netip.MustParseAddr("fd00::1"), TargetPort: 502})
	if !strings.Contains(v6, "ipv6.DstAddr") {
		t.Fatalf("v6 filter should use ipv6.DstAddr: %s", v6)
	}
}

// fakeSuppressor records Arm/Disarm calls for Guard lifecycle tests.
type fakeSuppressor struct{ arms, disarms int }

func (f *fakeSuppressor) Arm() error       { f.arms++; return nil }
func (f *fakeSuppressor) Disarm() error    { f.disarms++; return nil }
func (f *fakeSuppressor) Describe() string { return "fake" }

func TestGuardReleaseIsIdempotent(t *testing.T) {
	f := &fakeSuppressor{}
	g := &Guard{s: f, armed: true}
	if err := g.Release(); err != nil {
		t.Fatal(err)
	}
	if err := g.Release(); err != nil { // second Release must be a no-op
		t.Fatal(err)
	}
	if f.disarms != 1 {
		t.Fatalf("expected exactly one Disarm, got %d", f.disarms)
	}
	// A nil guard Release must not panic.
	var nilG *Guard
	if err := nilG.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestRuleValidation(t *testing.T) {
	if _, err := Arm(Rule{TargetPort: 502}); err == nil {
		t.Fatal("expected error for missing target IP")
	}
	if _, err := Arm(Rule{TargetIP: netip.MustParseAddr("10.0.0.1")}); err == nil {
		t.Fatal("expected error for missing target port")
	}
}

type retrySuppressor struct {
	failed     error
	failures   int32
	calls      atomic.Int32
	active     atomic.Int32
	overlapped atomic.Bool
}

func (s *retrySuppressor) Arm() error       { return nil }
func (s *retrySuppressor) Describe() string { return "retry fixture" }
func (s *retrySuppressor) Disarm() error {
	if s.active.Add(1) != 1 {
		s.overlapped.Store(true)
	}
	defer s.active.Add(-1)
	call := s.calls.Add(1)
	runtime.Gosched()
	if call <= s.failures {
		return s.failed
	}
	return nil
}

func TestGuardReleaseRetriesFailuresAndSerializesConcurrentCallers(t *testing.T) {
	failure := errors.New("OS rule deletion failed")
	s := &retrySuppressor{failed: failure, failures: 3}
	g := &Guard{s: s, armed: true}
	if err := g.Release(); !errors.Is(err, failure) {
		t.Fatalf("first release: %v", err)
	}
	if !g.armed {
		t.Fatal("failed deletion was recorded as disarmed")
	}
	var wait sync.WaitGroup
	results := make(chan error, 64)
	for i := 0; i < cap(results); i++ {
		wait.Add(1)
		go func() { defer wait.Done(); results <- g.Release() }()
	}
	wait.Wait()
	close(results)
	failures := 1
	for err := range results {
		if errors.Is(err, failure) {
			failures++
		} else if err != nil {
			t.Fatalf("unexpected release error: %v", err)
		}
	}
	if failures != 3 || s.calls.Load() != 4 || s.overlapped.Load() || g.armed {
		t.Fatalf("failures=%d calls=%d concurrent=%v armed=%v", failures, s.calls.Load(), s.overlapped.Load(), g.armed)
	}
	if err := g.Release(); err != nil || s.calls.Load() != 4 {
		t.Fatalf("successful cleanup not idempotent: %v, %d", err, s.calls.Load())
	}
}
