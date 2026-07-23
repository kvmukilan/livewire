// Package supportbundle creates a deliberately data-minimal diagnostic archive
// from a Livewire JSON report. Packet evidence is represented by digest and
// size, never embedded, because plaintext application credentials can exist in
// a PCAP even when report fields are fully redacted.
package supportbundle

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/runvars"
)

const maxReportBytes = 16 << 20

type EvidenceReference struct {
	Name     string `json:"name"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Included bool   `json:"included"`
}

type Manifest struct {
	Tool                string              `json:"tool"`
	Version             string              `json:"version"`
	Created             time.Time           `json:"created"`
	ReportSHA256        string              `json:"reportSha256"`
	CaptureDigest       string              `json:"captureDigest"`
	Evidence            []EvidenceReference `json:"evidence,omitempty"`
	SecurityLimitations []string            `json:"securityLimitations"`
}

type Options struct {
	ReportPath    string
	EvidencePaths []string
	OutputPath    string
	Version       string
}

var inlineSecret = regexp.MustCompile(`(?i)(authorization|proxy-authorization|password|passwd|token|secret|cookie)(\s*[:=]\s*)([^,;\s"\\]+)`)

func Create(opts Options) (Manifest, error) {
	if opts.ReportPath == "" || opts.OutputPath == "" {
		return Manifest{}, fmt.Errorf("support bundle: report and output paths are required")
	}
	if _, err := os.Stat(opts.OutputPath); err == nil {
		return Manifest{}, fmt.Errorf("support bundle: output already exists: %s", opts.OutputPath)
	} else if !os.IsNotExist(err) {
		return Manifest{}, err
	}
	reportBytes, err := readLimited(opts.ReportPath, maxReportBytes)
	if err != nil {
		return Manifest{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(reportBytes))
	dec.UseNumber()
	var report map[string]any
	if err := dec.Decode(&report); err != nil {
		return Manifest{}, fmt.Errorf("support bundle: decode report: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return Manifest{}, fmt.Errorf("support bundle: report contains trailing JSON")
	}
	if fmt.Sprint(report["tool"]) != "livewire" {
		return Manifest{}, fmt.Errorf("support bundle: input is not a Livewire report")
	}
	if report["captureDigest"] == nil || fmt.Sprint(report["captureDigest"]) == "" {
		return Manifest{}, fmt.Errorf("support bundle: report has no capture digest")
	}
	if report["replayPlan"] == nil && report["plan"] == nil {
		return Manifest{}, fmt.Errorf("support bundle: report has no replay plan")
	}
	report = sanitizeMap(report)
	ensureReportSections(report)
	sanitized, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	sanitized = append(sanitized, '\n')
	if containsSecretMaterial(sanitized) {
		return Manifest{}, fmt.Errorf("support bundle: report still resembles key-log or private-key material after redaction")
	}
	reportDigest := sha256.Sum256(sanitized)
	manifest := Manifest{
		Tool: "livewire", Version: opts.Version, Created: time.Now().UTC(),
		ReportSHA256: fmt.Sprintf("sha256:%x", reportDigest), CaptureDigest: fmt.Sprint(report["captureDigest"]),
		SecurityLimitations: []string{"packet evidence is referenced by digest only and is not embedded because captures may contain application credentials"},
	}
	for _, path := range opts.EvidencePaths {
		ref, err := evidenceReference(path)
		if err != nil {
			return Manifest{}, err
		}
		manifest.Evidence = append(manifest.Evidence, ref)
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := writeArchive(opts.OutputPath, sanitized, manifestBytes); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("support bundle: report exceeds %d bytes", limit)
	}
	return b, nil
}

func sanitizeMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		if runvars.IsSecret(key) {
			out[key] = "[REDACTED]"
			continue
		}
		out[key] = sanitizeValue(value)
	}
	return out
}

func sanitizeValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		return sanitizeMap(v)
	case []any:
		out := make([]any, len(v))
		for i := range v {
			out[i] = sanitizeValue(v[i])
		}
		return out
	case string:
		return inlineSecret.ReplaceAllString(v, "$1$2[REDACTED]")
	default:
		return value
	}
}

func ensureReportSections(report map[string]any) {
	for _, key := range []string{"adapterVersions", "variables", "transformations", "limitations"} {
		if report[key] == nil {
			report[key] = []any{}
		}
	}
}

func containsSecretMaterial(data []byte) bool {
	text := strings.ToUpper(string(data))
	for _, marker := range []string{"-----BEGIN PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----", "CLIENT_RANDOM ", "_TRAFFIC_SECRET_0 "} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func evidenceReference(path string) (EvidenceReference, error) {
	f, err := os.Open(path)
	if err != nil {
		return EvidenceReference{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return EvidenceReference{}, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return EvidenceReference{}, err
	}
	return EvidenceReference{Name: filepath.Base(path), SHA256: fmt.Sprintf("sha256:%x", h.Sum(nil)), Size: info.Size(), Included: false}, nil
}

func writeArchive(path string, report, manifest []byte) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".livewire-support-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	zw := zip.NewWriter(tmp)
	for name, data := range map[string][]byte{"report.json": report, "manifest.json": manifest} {
		w, createErr := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
		if createErr != nil {
			return createErr
		}
		if _, writeErr := w.Write(data); writeErr != nil {
			return writeErr
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
