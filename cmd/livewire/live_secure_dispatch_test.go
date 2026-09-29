package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLiveSecureInputsRejectLegacyControlsBeforeLoadingCapture(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.pcap")
	for _, secure := range []string{"keylog", "ca", "server-name", "user", "pass", "key", "host-key", "cmd", "expect", "insecure-skip-verify"} {
		t.Run(secure, func(t *testing.T) {
			value := "private-input-must-not-be-logged"
			if secure == "insecure-skip-verify" {
				value = "false"
			}
			err := cmdLive([]string{"--in=" + missing, "--" + secure + "=" + value, "-live=false"})
			if err == nil || !strings.Contains(err.Error(), "cannot be combined with legacy -live") || strings.Contains(err.Error(), value) {
				t.Fatalf("secure selector %s must reject legacy controls before capture or credential reads: %v", secure, err)
			}
		})
	}
	for _, legacy := range [][]string{
		{"-seed", "1"}, {"-o", "rewritten.pcap"}, {"-out", "rewritten.pcap"}, {"-flow", "0"},
		{"-v"}, {"-tui"}, {"-all"}, {"-verify", "strict"}, {"-adaptive=false"}, {"-pace"},
		{"-raw-l4"}, {"-sequential"}, {"-mode", "both"}, {"-mode=rewrite"}, {"-mode", "peer"},
	} {
		t.Run(strings.Join(legacy, " "), func(t *testing.T) {
			args := append([]string{"-in", missing}, legacy...)
			// New common options may precede the secure input in any order.
			args = append(args, "-session", "tcp-0", "-strict", "-under-load=false", "-keylog", "missing.keys")
			err := cmdLive(args)
			if err == nil || !strings.Contains(err.Error(), "cannot be combined with legacy") {
				t.Fatalf("legacy control must fail before loading missing capture: %v", err)
			}
		})
	}
}

func TestLiveLegacyDryRunAndFlagValuesKeepTheirMeaning(t *testing.T) {
	capture := writeHandshakePcap(t, t.TempDir())
	for _, flags := range [][]string{
		nil,
		{"-report", "-keylog"},
		{"-actual-out", "-ca"},
		{"-target", "-server-name"},
		{"--", "-keylog", "ignored.keys"},
		{"trailing-legacy-argument", "-keylog", "ignored.keys"},
	} {
		t.Run(strings.Join(flags, " "), func(t *testing.T) {
			// This capture contains no application messages. A fresh-session
			// route cannot accept it; legacy dry-run must still complete.
			args := append([]string{"-in", capture}, flags...)
			if err := cmdLive(args); err != nil {
				t.Fatalf("legacy dry-run or literal flag value changed meaning: %v", err)
			}
		})
	}
	rewritten := filepath.Join(t.TempDir(), "rewritten.pcap")
	if err := cmdLive([]string{"-in", capture, "-mode", "rewrite", "-o", rewritten}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(rewritten); err != nil {
		t.Fatalf("legacy rewrite did not retain its output behavior: %v", err)
	}
}
