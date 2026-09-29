package main

import (
	"strings"
	"testing"
)

func TestFreshSessionDefaultsAndAdvancedCompatibility(t *testing.T) {
	for _, command := range []string{"live", "reproduce"} {
		for _, tc := range []struct {
			flags []string
			mode  string
		}{
			{nil, "application"},
			{[]string{"-under-load"}, "application"},
			{[]string{"-mode", "auto"}, "auto"},
			{[]string{"-exact-tcp"}, "transport"},
			{[]string{"-profile", "transport"}, "transport"},
			{[]string{"-wire"}, "wire"},
			{[]string{"-profile", "wire"}, "wire"},
		} {
			o, err := parseCaptureReplayFlags(command, append([]string{"issue.pcap", "-dry-run"}, tc.flags...))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := resolveReproduceIntent(&o); err != nil {
				t.Fatal(err)
			}
			if o.mode != tc.mode {
				t.Errorf("%s %v: mode=%s, want %s", command, tc.flags, o.mode, tc.mode)
			}
		}
	}
}

func TestLivePrimaryAndLegacyHelpRemainDistinct(t *testing.T) {
	bin := buildBinary(t)
	primary, err := runBinary(t, bin, "live", "-h")
	if err != nil || !strings.Contains(primary, "usage: livewire live <capture.pcap>") || !strings.Contains(primary, "fresh certificate-verified TLS") {
		t.Fatalf("primary help: %v\n%s", err, primary)
	}
	legacy, err := runBinary(t, bin, "live", "-in", "unused.pcap", "-all-flags")
	if err != nil {
		t.Fatalf("legacy help: %v\n%s", err, legacy)
	}
	flags := declaredFlags(legacy)
	for _, name := range []string{"live", "o", "out", "raw-l4", "flow", "seed", "all"} {
		if !flags[name] {
			t.Errorf("legacy help dropped -%s", name)
		}
	}
}

func TestFreshDefaultsDoNotFallBackToPacketEngine(t *testing.T) {
	capture := writeProtocolStub(t, t.TempDir(), "unknown", 4567, []byte("CUSTOM REQUEST\r\n"))
	bin := buildBinary(t)
	preview, err := runBinary(t, bin, "check", capture, "-details")
	if err != nil || !strings.Contains(preview, "no TCP application adapter") {
		t.Fatalf("check must expose the same default blocker before execution: %v\n%s", err, preview)
	}
	for _, command := range []string{"live", "reproduce"} {
		out, err := runBinary(t, bin, command, capture, "-dry-run")
		if err == nil || !strings.Contains(out, "application") || strings.Contains(out, "Injecting captured frames") {
			t.Fatalf("%s must reject a TCP-only capture without an application adapter: %v\n%s", command, err, out)
		}
	}
}
