package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/replayintent"
)

func TestIntentPreflightRejectsInvalidOrStaleRunsWithoutStarting(t *testing.T) {
	dir := t.TempDir()
	writeWebTestPcap(t, dir)
	writeBlockedTLSPcap(t, dir)
	s, h := testServerHandler(t, dir)
	cases := []struct {
		endpoint string
		body     map[string]any
		want     string
	}{
		{"/api/run", map[string]any{"pcap": "sample.pcap", "captureDigest": "sha256:old"}, "capture changed"},
		{"/api/run", map[string]any{"pcap": "sample.pcap", "shape": "lab"}, "/api/lab"},
		{"/api/run", map[string]any{"pcap": "sample.pcap", "mode": "wire"}, "iface"},
		{"/api/run", map[string]any{"pcap": "sample.pcap", "mode": "invalid"}, "unknown replay mode"},
		{"/api/run", map[string]any{"pcap": "sample.pcap", "sessions": []string{"tcp-999"}}, "unknown session"},
		{"/api/plan", map[string]any{"pcap": "sample.pcap", "shape": "invalid"}, "shape must"},
		{"/api/plan", map[string]any{"pcap": "sample.pcap", "shape": "lab", "sessions": []string{"udp-0"}}, "complete capture"},
		{"/api/plan", map[string]any{"pcap": "tls.pcap", "secure": map[string]any{"keylog": "../secrets.log"}}, "invalid"},
		{"/api/run", map[string]any{"pcap": "tls.pcap", "mode": "application", "targetIP": "127.0.0.1:443", "secure": map[string]any{"ca": "missing.pem"}}, ""},
		{"/api/run", map[string]any{"pcap": "tls.pcap", "mode": "application", "targetIP": "127.0.0.1:443", "secure": map[string]any{"privateKey": "missing.key"}}, ""},
		{"/api/run", map[string]any{"pcap": "tls.pcap", "mode": "application", "profile": "timing", "targetIP": "127.0.0.1:443"}, "functional profile"},
	}
	for _, tc := range cases {
		t.Run(tc.endpoint+tc.want, func(t *testing.T) {
			w := postJSON(t, h, tc.endpoint, tc.body)
			if w.Code < 400 || !strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("%d: %s", w.Code, w.Body.String())
			}
			if s.job != nil {
				t.Fatal("invalid input started a job")
			}
		})
	}
}

func TestTruncatedFTPDataCannotBecomeRunnableThroughCoordinator(t *testing.T) {
	dir := t.TempDir()
	writeFTPWebPcap(t, dir, 32000)
	s, _ := testServerHandler(t, dir)
	capture, _, err := s.loadCaptureSnapshot(filepath.Join(dir, "ftp.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := replayintent.Inspect(capture.Records, replayintent.Options{Mode: "application"}, nil)
	if err != nil || !before.Readiness.Supported {
		t.Fatalf("fixture: %v %+v", err, before)
	}
	for _, record := range capture.Records {
		if strings.Contains(string(record.Data), "hello ftp") {
			record.OrigLen++
		}
	}
	after, err := replayintent.Inspect(capture.Records, replayintent.Options{Mode: "application", Sessions: []string{"tcp-0"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if after.Readiness.Supported || !strings.Contains(after.Readiness.Blocker, "truncated") {
		t.Fatalf("truncated data accepted: %+v", after.Readiness)
	}
}

func TestLabPreviewDescribesActualActors(t *testing.T) {
	dir := t.TempDir()
	writeWebTestPcap(t, dir)
	h := testHandler(t, dir)
	w := postJSON(t, h, "/api/plan", map[string]any{"pcap": "sample.pcap", "shape": "lab", "mode": "wire"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "frame-injector") || !strings.Contains(w.Body.String(), "server-facing") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	w = postJSON(t, h, "/api/plan", map[string]any{"pcap": "sample.pcap", "shape": "lab", "mode": "application"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"supported":false`) {
		t.Fatalf("lab promised application equivalence: %d %s", w.Code, w.Body.String())
	}
}

func TestDashboardVersionComesFromBuildConfiguration(t *testing.T) {
	s, err := NewServerWithConfig(Config{Dir: t.TempDir(), Version: "0.9.0-dev"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(context.Background())
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil))
	if !strings.Contains(w.Body.String(), "Replay Studio 0.9.0-dev") || strings.Contains(w.Body.String(), "__LIVEWIRE_VERSION__") {
		t.Fatal("stale dashboard version")
	}
}

func TestExplicitZeroGapCompletesBothAttemptsWithoutDefaultWait(t *testing.T) {
	dir := t.TempDir()
	writeWebTestPcap(t, dir)
	s, _ := testServerHandler(t, dir)
	var req adaptiveRunReq
	if err := json.Unmarshal([]byte(`{"pcap":"sample.pcap","iface":"definitely-missing","targetIP":"192.0.2.2","profile":"functional","verify":"lenient","attempts":2,"gapMs":0}`), &req); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	j := &job{ctx: ctx}
	s.runAdaptiveJob(j, filepath.Join(dir, "sample.pcap"), req)
	if !strings.Contains(j.Summary, "2 attempts") {
		t.Fatalf("zero gap used default wait: %s", j.Summary)
	}
	if len(j.Artifacts) == 0 {
		t.Fatal("missing failed-attempt evidence")
	}
	if _, err := os.Stat(filepath.Join(dir, j.Artifacts[len(j.Artifacts)-1])); err != nil {
		t.Fatal(err)
	}
}
