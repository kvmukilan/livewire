package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replayintent"
	"github.com/kvmukilan/livewire/internal/webui"
	"github.com/kvmukilan/livewire/internal/wire"
)

func writeIntentHTTP(t *testing.T, port uint16, body []byte, arp bool) string {
	t.Helper()
	dir := t.TempDir()
	req := []byte("GET /download HTTP/1.1\r\nHost: device.local\r\n\r\n")
	stub := writeProtocolStub(t, dir, "request", port, req)
	records, _, err := loadRecords(stub)
	if err != nil {
		t.Fatal(err)
	}
	response := append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", len(body))), body...)
	frames := make([]pcapio.Record, len(records))
	for i, r := range records {
		frames[i] = *r
	}
	frames = append(frames, pcapio.Record{Time: records[0].Time.Add(4 * time.Millisecond), Data: ethTCP("192.0.2.20", "192.0.2.10", port, 41000, 901, 101+uint32(len(req)), wire.FlagACK|wire.FlagPSH, response)})
	if arp {
		raw, _ := hex.DecodeString("ffffffffffff02000000000108060001080006040001020000000001c000020a000000000000c0000214")
		frames = append(frames, pcapio.Record{Time: records[0].Time.Add(5 * time.Millisecond), Data: raw})
	}
	path := filepath.Join(dir, "http.pcap")
	if err := writeFrames(path, frames, true); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDashboardReportIdentifiesLoadedCaptureAfterFileReplacement(t *testing.T) {
	body := gzipBody(t)
	var capture string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Change the source during replay, after the selected request was sent.
		if err := os.WriteFile(capture, []byte("replacement capture"), 0600); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body)
	}))
	defer server.Close()
	capture = writeIntentHTTP(t, uint16(server.Listener.Addr().(*net.TCPAddr).Port), body, false)
	original, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(original))
	dashboard := webui.NewServer(filepath.Dir(capture))
	defer dashboard.Shutdown(context.Background())
	requestBody, _ := json.Marshal(map[string]any{"pcap": filepath.Base(capture), "mode": "application", "targetIP": "127.0.0.1", "captureDigest": wantDigest})
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/run", bytes.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Livewire-CSRF", dashboard.CSRFToken())
	w := httptest.NewRecorder()
	dashboard.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("start %d: %s", w.Code, w.Body.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		w = httptest.NewRecorder()
		dashboard.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/status", nil))
		var status struct {
			Done, Running, OK bool
			Artifacts         []string
		}
		if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if status.Done && !status.Running {
			if !status.OK {
				t.Fatalf("job: %s", w.Body.String())
			}
			for _, artifact := range status.Artifacts {
				if !strings.HasSuffix(artifact, ".run.json") {
					continue
				}
				data, err := os.ReadFile(filepath.Join(filepath.Dir(capture), artifact))
				if err != nil {
					t.Fatal(err)
				}
				var report struct{ CaptureDigest string }
				if err := json.Unmarshal(data, &report); err != nil {
					t.Fatal(err)
				}
				if report.CaptureDigest != wantDigest {
					t.Fatalf("report names replacement file: %s", data)
				}
				return
			}
			t.Fatal("missing report")
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("dashboard job did not finish")
}

func gzipBody(t *testing.T) []byte {
	t.Helper()
	raw := make([]byte, 4096)
	_, _ = rand.New(rand.NewSource(42)).Read(raw)
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestGzipHTTPReplaysWithExplicitApplicationIntent(t *testing.T) {
	body := gzipBody(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body)
	}))
	defer server.Close()
	port := uint16(server.Listener.Addr().(*net.TCPAddr).Port)
	capture := writeIntentHTTP(t, port, body, true)
	bin := buildBinary(t)
	out, err := runBinary(t, bin, "reproduce", capture, "--mode", "application", "--session", "tcp-0", "-t", "127.0.0.1")
	if err != nil {
		t.Fatalf("gzip replay failed: %v\n%s", err, out)
	}
	if requests.Load() != 1 || !strings.Contains(out, "1 same as recording") {
		t.Fatalf("requests=%d output=%s", requests.Load(), out)
	}
	data, err := os.ReadFile(strings.TrimSuffix(capture, ".pcap") + ".report.json")
	if err != nil {
		t.Fatal(err)
	}
	var report replayReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.ExcludedPackets != 1 || report.SelectedPackets != 5 || len(report.Sessions) != 1 {
		t.Fatalf("wrong selection accounting: %+v", report)
	}
	if err := report.Plan.ValidateCoverage(); err != nil {
		t.Fatal(err)
	}
}

func TestIntentPreviewAndDashboardShareDecisions(t *testing.T) {
	capture := writeIntentHTTP(t, 80, gzipBody(t), true)
	records, _, err := loadRecords(capture)
	if err != nil {
		t.Fatal(err)
	}
	server := webui.NewServer(filepath.Dir(capture))
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	for _, mode := range []string{"application", "transport", "wire", "auto"} {
		for _, selected := range [][]string{nil, {"tcp-0"}} {
			t.Run(mode+fmt.Sprint(selected), func(t *testing.T) {
				in, err := replayintent.Inspect(records, replayintent.Options{Mode: mode, Sessions: selected}, nil)
				if err != nil {
					t.Fatal(err)
				}
				payload, _ := json.Marshal(map[string]any{"pcap": filepath.Base(capture), "mode": mode, "sessions": selected})
				req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/plan", bytes.NewReader(payload))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Livewire-CSRF", server.CSRFToken())
				w := httptest.NewRecorder()
				server.Handler().ServeHTTP(w, req)
				if w.Code != 200 {
					t.Fatalf("%d %s", w.Code, w.Body.String())
				}
				var actual replayintent.Inspection
				if err := json.Unmarshal(w.Body.Bytes(), &actual); err != nil {
					t.Fatal(err)
				}
				a, _ := json.Marshal(in.Readiness)
				b, _ := json.Marshal(actual.Readiness)
				if !bytes.Equal(a, b) {
					t.Fatalf("CLI/web readiness drift: %s != %s", a, b)
				}
				a, _ = json.Marshal(in.Plan)
				b, _ = json.Marshal(actual.Plan)
				if !bytes.Equal(a, b) {
					t.Fatalf("CLI/web plan drift: %s != %s", a, b)
				}
				if selected != nil && !in.Readiness.Supported {
					t.Fatalf("selected HTTP should be ready: %+v", in.Readiness)
				}
			})
		}
	}
}

func TestExplicitWireBypassesTLSInputsAndValidatesOptions(t *testing.T) {
	path := writeProtocolStub(t, t.TempDir(), "tls", 443, []byte{22, 3, 3, 0, 1, 0})
	bin := buildBinary(t)
	for _, flag := range [][]string{{"--wire"}, {"-profile", "wire"}, {"--mode", "wire"}} {
		args := append([]string{"reproduce", path}, flag...)
		args = append(args, "--dry-run")
		out, err := runBinary(t, bin, args...)
		if err != nil || !strings.Contains(out, "no packets sent") {
			t.Fatalf("%v: %v %s", flag, err, out)
		}
		if strings.Contains(out, "-keylog") {
			t.Fatalf("wire preview requested TLS inputs: %s", out)
		}
	}
	out, err := runBinary(t, bin, "reproduce", path, "--profile", "bad", "--dry-run")
	if err == nil || !strings.Contains(out, "unknown fidelity profile") {
		t.Fatalf("invalid profile bypassed: %v %s", err, out)
	}
	out, err = runBinary(t, bin, "reproduce", path, "--mode", "transport", "--dry-run")
	if err == nil || !strings.Contains(out, "encrypted sessions") {
		t.Fatalf("transport silently reterminated TLS: %v %s", err, out)
	}
}

func TestCheckNoLongerClaimsReplayConfidenceForBlockedCapture(t *testing.T) {
	path := writeIntentHTTP(t, 80, gzipBody(t), true)
	bin := buildBinary(t)
	out, err := runBinary(t, bin, "check", path, "-details")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "replay confidence") || !strings.Contains(out, "BLOCKED") || !strings.Contains(out, "--session") {
		t.Fatalf("misleading diagnosis: %s", out)
	}
	out, err = runBinary(t, bin, "live", "--mode", "application", path, "--session", "tcp-0", "--dry-run")
	if err != nil {
		t.Fatalf("flags-first live preview: %v %s", err, out)
	}
}

func TestDashboardTLSUsesSharedFreshSessionDriver(t *testing.T) {
	cert, ca := testTLSCertificate(t)
	events, keys := captureHTTPOverTLS(t, cert)
	capture, keyPath, caPath := writeTLSFixture(t, t.TempDir(), events, keys, ca)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2")
		_, _ = w.Write([]byte("ok"))
	}))
	target.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	target.StartTLS()
	defer target.Close()
	dashboard := webui.NewServer(filepath.Dir(capture))
	defer dashboard.Shutdown(context.Background())
	body, _ := json.Marshal(map[string]any{"pcap": filepath.Base(capture), "mode": "application", "targetIP": target.Listener.Addr().String(), "verify": "lenient", "secure": map[string]any{"keylog": filepath.Base(keyPath), "ca": filepath.Base(caPath), "serverName": "localhost", "timeoutSeconds": 2}})
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/run", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Livewire-CSRF", dashboard.CSRFToken())
	response := httptest.NewRecorder()
	dashboard.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("start %d: %s", response.Code, response.Body.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		w := httptest.NewRecorder()
		dashboard.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/status", nil))
		var status struct {
			Running, Done, OK bool
			Summary           string
			Artifacts         []string
		}
		if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if !status.Running && status.Done {
			if !status.OK || len(status.Artifacts) != 1 {
				t.Fatalf("status: %+v", status)
			}
			data, err := os.ReadFile(filepath.Join(filepath.Dir(capture), status.Artifacts[0]))
			if err != nil {
				t.Fatal(err)
			}
			var report reterminationReport
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			if !report.Outcome.Completed || !report.Outcome.Verified || !report.Outcome.Matched || !report.Outcome.PeerIdentityChecked {
				t.Fatalf("outcome: %+v", report.Outcome)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("secure dashboard job did not finish")
}

func TestBinaryProtocolHonorsExplicitTransportAndCustomAdapter(t *testing.T) {
	payload := make([]byte, 1024)
	_, _ = rand.New(rand.NewSource(92)).Read(payload)
	capture := writeProtocolStub(t, t.TempDir(), "binary", 4567, payload)
	bin := buildBinary(t)
	out, err := runBinary(t, bin, "reproduce", capture, "--mode", "auto", "--dry-run")
	if err == nil || !strings.Contains(out, "opaque") {
		t.Fatalf("auto did not flag uncertainty: %v %s", err, out)
	}
	out, err = runBinary(t, bin, "reproduce", capture, "--mode", "transport", "--dry-run")
	if err != nil || !strings.Contains(out, "unrecognized binary data") {
		t.Fatalf("explicit transport was overridden: %v %s", err, out)
	}
	rules := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(rules, []byte(`{"name":"device-binary","match":{"transport":"tcp","ports":[4567]},"framing":{"type":"fixed","size":1024}}`), 0600); err != nil {
		t.Fatal(err)
	}
	out, err = runBinary(t, bin, "reproduce", capture, "--mode", "application", "--rules", rules, "--dry-run")
	if err != nil || !strings.Contains(out, "device-binary") {
		t.Fatalf("custom adapter lost to entropy: %v %s", err, out)
	}
}
