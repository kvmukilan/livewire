package replaylab

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecureCLIReportsRequireEveryVerifiedAttempt(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "report.json")
	write := func(attempt int, matched, identity bool) {
		t.Helper()
		raw := fmt.Sprintf(`{"tool":"livewire","version":"1.0.0","kind":"tls","outcome":{"completed":true,"verified":true,"matched":%v,"comparedResponses":2,"responses":2,"mismatches":0,"cleanup":"complete","peerIdentityChecked":%v}}`, matched, identity)
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("report.attempt-%d.json", attempt)), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(1, true, true)
	if _, err := checkCLIReport(base, 2, "1.0.0"); err == nil {
		t.Fatal("missing secure attempt accepted")
	}
	write(2, true, true)
	if n, err := checkCLIReport(base, 2, "v1.0.0"); err != nil || n != 4 {
		t.Fatalf("compared=%d err=%v", n, err)
	}
	if paths, err := CLIReportPaths(base, 2); err != nil || len(paths) != 2 {
		t.Fatalf("paths=%v err=%v", paths, err)
	}
	write(2, false, true)
	if _, err := checkCLIReport(base, 2, "1.0.0"); err == nil {
		t.Fatal("mismatching secure attempt accepted")
	}
	write(2, true, false)
	if _, err := checkCLIReport(base, 2, "1.0.0"); err == nil {
		t.Fatal("unverified secure peer accepted")
	}
}

func TestFTPFixtureRequiresDataTransferProofAndFTPSIdentity(t *testing.T) {
	fixtureHash := fmt.Sprintf("sha256:%x", sha256.Sum256(ftpLabData))
	validTransfers := func() []map[string]any {
		var transfers []map[string]any
		for _, command := range []string{"RETR", "STOR"} {
			transfers = append(transfers, map[string]any{"command": command, "matched": true, "expectedBytes": len(ftpLabData), "actualBytes": len(ftpLabData), "expectedSha256": fixtureHash, "actualSha256": fixtureHash})
		}
		return transfers
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any, []map[string]any)
	}{
		{"missing transfers", func(o map[string]any, _ []map[string]any) { delete(o, "transfers") }},
		{"missing upload", func(o map[string]any, ts []map[string]any) { o["transfers"] = ts[:1] }},
		{"duplicate transfer", func(_ map[string]any, ts []map[string]any) { ts[1]["command"] = "RETR" }},
		{"unmatched transfer", func(_ map[string]any, ts []map[string]any) { ts[0]["matched"] = false }},
		{"empty transfer", func(_ map[string]any, ts []map[string]any) { ts[0]["expectedBytes"], ts[0]["actualBytes"] = 0, 0 }},
		{"short transfer", func(_ map[string]any, ts []map[string]any) { ts[0]["actualBytes"] = 1 }},
		{"hash mismatch", func(_ map[string]any, ts []map[string]any) {
			ts[0]["actualSha256"] = "sha256:" + strings.Repeat("0", 64)
		}},
		{"invalid hash", func(_ map[string]any, ts []map[string]any) {
			ts[0]["expectedSha256"], ts[0]["actualSha256"] = "sha256:invalid", "sha256:invalid"
		}},
		{"self consistent wrong data", func(_ map[string]any, ts []map[string]any) {
			ts[0]["expectedSha256"], ts[0]["actualSha256"] = "sha256:"+strings.Repeat("0", 64), "sha256:"+strings.Repeat("0", 64)
		}},
		{"unverified FTPS identity", func(o map[string]any, _ []map[string]any) { o["peerIdentityChecked"] = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			base := filepath.Join(dir, "report.json")
			transfers := validTransfers()
			outcome := map[string]any{"completed": true, "verified": true, "matched": true, "responses": 12, "peerIdentityChecked": true, "transfers": transfers}
			write := func() {
				t.Helper()
				data, err := json.Marshal(map[string]any{"tool": "livewire", "version": "1.0.0", "kind": "ftp", "outcome": outcome})
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, "report.attempt-1.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			write()
			for _, name := range []string{"ftp", "ftps-explicit", "ftps-implicit"} {
				if _, err := checkCLIReport(base, 1, "1.0.0", name); err != nil {
					t.Fatal(err)
				}
			}
			tc.change(outcome, transfers)
			write()
			if _, err := checkCLIReport(base, 1, "1.0.0", "ftps-explicit"); err == nil {
				t.Fatal("incomplete FTP proof accepted")
			}
			if tc.name == "unverified FTPS identity" {
				if _, err := checkCLIReport(base, 1, "1.0.0", "ftp"); err != nil {
					t.Fatalf("plaintext FTP unnecessarily required TLS identity: %v", err)
				}
			}
		})
	}
}

func TestGenericCLIReportStillRequiresAllAttempts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	raw := []byte(`{"tool":"livewire","version":"1.0.0","attempts":2,"sessions":[{"attempt":1,"completed":true,"verified":true,"matched":true,"comparedResponses":1,"cleanup":"complete"},{"attempt":2,"completed":true,"verified":true,"matched":true,"comparedResponses":1,"cleanup":"complete"}]}`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if n, err := checkCLIReport(path, 2, "1.0.0"); err != nil || n != 2 {
		t.Fatalf("compared=%d err=%v", n, err)
	}
	if _, err := checkCLIReport(path, 3, "1.0.0"); err == nil {
		t.Fatal("incorrect repeat count accepted")
	}
}
