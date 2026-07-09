package main

import (
	"bufio"
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/livereplay"
)

func TestSubnetHasTarget(t *testing.T) {
	tgt := netip.MustParseAddr("192.168.1.50")
	if !subnetHasTarget([]string{"192.168.1.10/24"}, tgt) {
		t.Fatal("192.168.1.10/24 should contain 192.168.1.50")
	}
	if subnetHasTarget([]string{"10.0.0.5/24", "127.0.0.1/8"}, tgt) {
		t.Fatal("neither 10.0.0.0/24 nor loopback should contain 192.168.1.50")
	}
	if subnetHasTarget([]string{"garbage"}, tgt) {
		t.Fatal("unparseable CIDR must not match")
	}
}

func TestParseHostIP(t *testing.T) {
	if ip, err := parseHostIP(" 192.168.1.50 "); err != nil || ip.String() != "192.168.1.50" {
		t.Fatalf("plain IP: %v %v", ip, err)
	}
	if ip, err := parseHostIP("192.168.1.50:502"); err != nil || ip.String() != "192.168.1.50" {
		t.Fatalf("ip:port should yield the host: %v %v", ip, err)
	}
	if _, err := parseHostIP("not-an-ip"); err == nil {
		t.Fatal("expected an error for a non-IP")
	}
}

func TestPromptChoiceDefaultAndValue(t *testing.T) {
	stdinReader = bufio.NewReader(strings.NewReader("\n")) // empty -> default
	if got := promptChoice("? ", 2, 5); got != 2 {
		t.Fatalf("empty input should take the default (2), got %d", got)
	}
	stdinReader = bufio.NewReader(strings.NewReader("bad\n3\n")) // reject then accept
	if got := promptChoice("? ", 0, 5); got != 2 {
		t.Fatalf("expected index 2 for input 3, got %d", got)
	}
}

func TestVerdictText(t *testing.T) {
	same := livereplay.Result{Outcome: engine.Outcome{Phase: engine.PhaseClosed}}
	var b bytes.Buffer
	fprintVerdict(&b, "", same)
	if !strings.Contains(b.String(), "SAME AS THE RECORDING") {
		t.Fatalf("clean match should read SAME, got:\n%s", b.String())
	}

	diff := livereplay.Result{Outcome: engine.Outcome{
		Phase: engine.PhaseClosed, ReplyMismatches: 1,
		Mismatches: []engine.Mismatch{{Structural: true, Detail: "txid 0x7: exception 0x83"}},
	}}
	b.Reset()
	fprintVerdict(&b, "Connection 1", diff)
	s := b.String()
	if !strings.Contains(s, "DIFFERENT FROM THE RECORDING") || !strings.Contains(s, "exception 0x83") {
		t.Fatalf("divergent run should read DIFFERENT and list the divergence, got:\n%s", s)
	}

	reset := livereplay.Result{Outcome: engine.Outcome{Phase: engine.PhaseAborted, Aborted: true, Reason: "peer sent RST"}}
	b.Reset()
	fprintVerdict(&b, "", reset)
	if !strings.Contains(b.String(), "reset") {
		t.Fatalf("RST abort should be explained as a reset, got:\n%s", b.String())
	}
}
