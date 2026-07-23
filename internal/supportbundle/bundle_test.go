package supportbundle

import (
	"archive/zip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateRedactedMetadataOnlyBundle(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "run.json")
	evidencePath := filepath.Join(dir, "actual.pcapng")
	secret := "hunter2"
	report := map[string]any{
		"tool": "livewire", "version": "0.5.0", "captureDigest": "sha256:capture", "replayPlan": map[string]any{"entries": []any{}},
		"adapterVersions": map[string]string{"http/1": "1"}, "variables": map[string]string{"mqtt.password": secret},
		"sessions": []any{}, "error": "Authorization: BearerToken", "limitations": []any{},
	}
	b, _ := json.Marshal(report)
	if err := os.WriteFile(reportPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidencePath, []byte("packet bytes contain "+secret), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "support.zip")
	manifest, err := Create(Options{ReportPath: reportPath, EvidencePaths: []string{evidencePath}, OutputPath: out, Version: "0.5.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Evidence) != 1 || manifest.Evidence[0].Included {
		t.Fatalf("manifest=%+v", manifest)
	}
	zr, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var combined strings.Builder
	for _, file := range zr.File {
		r, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(r)
		_ = r.Close()
		combined.Write(data)
	}
	text := combined.String()
	if strings.Contains(text, secret) || strings.Contains(text, "BearerToken") || !strings.Contains(text, "[REDACTED]") {
		t.Fatalf("bundle redaction failed: %s", text)
	}
	if strings.Contains(text, "packet bytes contain") {
		t.Fatal("raw packet evidence was embedded")
	}
}

func TestCreateRejectsUntrustedOrSecretMaterial(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"foreign": `{"tool":"other","captureDigest":"x","plan":{}}`,
		"keylog":  `{"tool":"livewire","captureDigest":"x","plan":{},"note":"CLIENT_RANDOM abc def"}`,
	} {
		t.Run(name, func(t *testing.T) {
			report := filepath.Join(dir, name+".json")
			_ = os.WriteFile(report, []byte(body), 0o600)
			if _, err := Create(Options{ReportPath: report, OutputPath: filepath.Join(dir, name+".zip")}); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}
