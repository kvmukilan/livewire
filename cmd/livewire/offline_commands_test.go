package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvmukilan/livewire/internal/ftpreplay"
	"github.com/kvmukilan/livewire/internal/replay"
)

func TestOfflineCommandSuite(t *testing.T) {
	dir := t.TempDir()
	input := writeHandshakePcap(t, dir)
	assessment := filepath.Join(dir, "assessment.json")
	if err := cmdCheck([]string{input, "-details", "-json", assessment}); err != nil {
		t.Fatalf("check: %v", err)
	}
	if err := cmdAnalyze([]string{"-in", input, "-json", filepath.Join(dir, "analysis.json"), "-profile", "timing"}); err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if err := cmdReplay([]string{"-in", input, "-dry-run", "-pps", "1000", "-n", "2"}); err != nil {
		t.Fatalf("replay dry-run: %v", err)
	}
	rewritten := filepath.Join(dir, "live-rewritten.pcap")
	if err := cmdLive([]string{"-in", input, "-mode", "both", "-o", rewritten, "-v"}); err != nil {
		t.Fatalf("live dry-run: %v", err)
	}
	if _, err := os.Stat(rewritten); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(dir, "run.json")
	if err := os.WriteFile(report, []byte(`{"tool":"livewire","version":"0.7.0","captureDigest":"sha256:capture","replayPlan":{"entries":[]},"variables":{"ftp.password":"secret"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, "support.zip")
	if err := cmdBundle([]string{"-report", report, "-evidence", input, "-o", bundle}); err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if info, err := os.Stat(bundle); err != nil || info.Size() == 0 {
		t.Fatalf("bundle info=%v err=%v", info, err)
	}
	if err := cmdVersion(nil); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"check", "ftp-replay", "web", "version"} {
		if err := help([]string{command}); err != nil {
			t.Fatalf("help %s: %v", command, err)
		}
	}
}

func TestCommandValidationAndFTPHelpers(t *testing.T) {
	dir := t.TempDir()
	input := writeHandshakePcap(t, dir)
	cases := []struct {
		name string
		run  func() error
		want string
	}{
		{"capture required", func() error { return cmdCapture(nil) }, "required"},
		{"replay required", func() error { return cmdReplay(nil) }, "required"},
		{"replay count", func() error { return cmdReplay([]string{"-in", input, "-n", "-1"}) }, "negative"},
		{"replay interface", func() error { return cmdReplay([]string{"-in", input}) }, "required"},
		{"live count", func() error { return cmdLive([]string{"-in", input, "-n", "0"}) }, "at least"},
		{"live repeated dry", func() error { return cmdLive([]string{"-in", input, "-n", "2"}) }, "on-wire"},
		{"live gap", func() error { return cmdLive([]string{"-in", input, "-gap", "-1s"}) }, "negative"},
		{"lab required", func() error { return cmdLab(nil) }, "required"},
		{"ftp required", func() error { return cmdFTPReplay(nil) }, "required"},
		{"ftp timeout", func() error { return cmdFTPReplay([]string{"-in", input, "-t", "127.0.0.1:21", "-timeout", "0s"}) }, "timeout"},
		{"ftp verify", func() error { return cmdFTPReplay([]string{"-in", input, "-t", "127.0.0.1:21", "-verify", "wrong"}) }, "verify"},
		{"ftp target", func() error { return cmdFTPReplay([]string{"-in", input, "-t", "bad"}) }, "target"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Fatalf("error=%v want %q", err, tc.want)
			}
		})
	}

	for _, value := range []string{"", "on", "warn", "off", "none", "strict"} {
		if _, err := parseReplayVerify(value); err != nil {
			t.Fatalf("verify %q: %v", value, err)
		}
	}
	if _, err := parseReplayVerify("broken"); err == nil {
		t.Fatal("invalid verification accepted")
	}
	if cfg, err := ftpTLSConfig("[::1]:990", "", "", true); err != nil || cfg.ServerName != "::1" || !cfg.InsecureSkipVerify {
		t.Fatalf("TLS config=%+v err=%v", cfg, err)
	}
	badCA := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ftpTLSConfig("127.0.0.1:990", "localhost", badCA, false); err == nil {
		t.Fatal("invalid CA accepted")
	}
	if _, err := selectFTPControl(&replay.Trace{}); err == nil {
		t.Fatal("missing FTP control accepted")
	}
	for _, tc := range []struct {
		script ftpreplay.Script
		want   string
	}{
		{ftpreplay.Script{}, "FTP"},
		{ftpreplay.Script{Explicit: true}, "explicit"},
		{ftpreplay.Script{Implicit: true}, "implicit"},
	} {
		if got := ftpProtocolVersion(tc.script); !strings.Contains(got, tc.want) {
			t.Fatalf("protocol=%q want %q", got, tc.want)
		}
	}
	if !ftpResultMatched(ftpreplay.Result{Completed: true, Transfers: []ftpreplay.TransferResult{{Matched: true}}}) {
		t.Fatal("matching FTP result rejected")
	}
	if ftpResultMatched(ftpreplay.Result{Completed: true, Differences: []replay.Difference{{Field: "reply"}}}) || ftpResultMatched(ftpreplay.Result{Completed: true, Transfers: []ftpreplay.TransferResult{{Matched: false}}}) {
		t.Fatal("mismatching FTP result accepted")
	}
}
