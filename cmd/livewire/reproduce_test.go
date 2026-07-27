package main

import (
	"bufio"
	"bytes"
	"flag"
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

// The capture may be written before the flags, after them, or passed as -in.
// A peer copies the command from an email, so all three have to work — and a
// flag written after the capture must not be silently dropped, which is what
// the bare flag package would do.
func TestParseCaptureArgsAcceptsCaptureAnywhere(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "capture first", args: []string{"issue.pcap", "-to", "192.0.2.50", "-strict"}},
		{name: "flags first", args: []string{"-to", "192.0.2.50", "-strict", "issue.pcap"}},
		{name: "in flag", args: []string{"-in", "issue.pcap", "-to", "192.0.2.50", "-strict"}},
		{name: "in flag last", args: []string{"-to", "192.0.2.50", "-strict", "-in", "issue.pcap"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("reproduce-test", flag.ContinueOnError)
			var in string
			fs.StringVar(&in, "in", "", "")
			to := fs.String("to", "", "")
			strict := fs.Bool("strict", false, "")
			capture, err := parseCaptureArgs(fs, tt.args, &in)
			if err != nil {
				t.Fatal(err)
			}
			if capture != "issue.pcap" || *to != "192.0.2.50" || !*strict {
				t.Fatalf("capture=%q to=%q strict=%v", capture, *to, *strict)
			}
		})
	}
}

func TestParseCaptureArgsRejectsTwoCaptures(t *testing.T) {
	cases := [][]string{
		{"one.pcap", "two.pcap"},
		{"one.pcap", "-in", "two.pcap"},
	}
	for _, args := range cases {
		fs := flag.NewFlagSet("reproduce-test", flag.ContinueOnError)
		var in string
		fs.StringVar(&in, "in", "", "")
		if _, err := parseCaptureArgs(fs, args, &in); err == nil {
			t.Fatalf("expected %v to fail", args)
		}
	}
}

// No capture is not an error here: the caller prints its own usage and a
// tailored message, which reads better than a parse failure.
func TestParseCaptureArgsWithNoCaptureReturnsEmpty(t *testing.T) {
	fs := flag.NewFlagSet("reproduce-test", flag.ContinueOnError)
	var in string
	fs.StringVar(&in, "in", "", "")
	capture, err := parseCaptureArgs(fs, nil, &in)
	if err != nil || capture != "" {
		t.Fatalf("capture=%q err=%v, want empty and nil", capture, err)
	}
}

// The same file named twice the same way is the operator being explicit, not a
// mistake, so it must not be rejected.
func TestParseCaptureArgsToleratesTheSameCaptureTwice(t *testing.T) {
	fs := flag.NewFlagSet("reproduce-test", flag.ContinueOnError)
	var in string
	fs.StringVar(&in, "in", "", "")
	capture, err := parseCaptureArgs(fs, []string{"issue.pcap", "-in", "issue.pcap"}, &in)
	if err != nil || capture != "issue.pcap" {
		t.Fatalf("capture=%q err=%v", capture, err)
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
	same := livereplay.Result{Outcome: engine.Outcome{Phase: engine.PhaseClosed}, Verified: true, Matched: true}
	var b bytes.Buffer
	fprintVerdict(&b, "", same)
	if !strings.Contains(b.String(), "SAME AS THE RECORDING") {
		t.Fatalf("clean match should read SAME, got:\n%s", b.String())
	}

	diff := livereplay.Result{Verified: true, Matched: false, Outcome: engine.Outcome{
		Phase: engine.PhaseClosed, ReplyMismatches: 1,
		Mismatches: []engine.Mismatch{{Structural: true, Detail: "txid 0x7: exception 0x83"}},
	}}
	b.Reset()
	fprintVerdict(&b, "Connection 1", diff)
	s := b.String()
	if !strings.Contains(s, "DIFFERENT FROM THE RECORDING") || !strings.Contains(s, "exception 0x83") {
		t.Fatalf("divergent run should read DIFFERENT and list the divergence, got:\n%s", s)
	}

	unverified := livereplay.Result{Outcome: engine.Outcome{Phase: engine.PhaseClosed}}
	b.Reset()
	fprintVerdict(&b, "", unverified)
	if strings.Contains(b.String(), "SAME AS THE RECORDING") || !strings.Contains(b.String(), "WAS NOT CHECKED") {
		t.Fatalf("unverified run must not claim a match, got:\n%s", b.String())
	}

	reset := livereplay.Result{Outcome: engine.Outcome{Phase: engine.PhaseAborted, Aborted: true, Reason: "peer sent RST"}}
	b.Reset()
	fprintVerdict(&b, "", reset)
	if !strings.Contains(b.String(), "reset") {
		t.Fatalf("RST abort should be explained as a reset, got:\n%s", b.String())
	}
}
