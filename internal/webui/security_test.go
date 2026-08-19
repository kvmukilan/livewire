package webui

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDashboardRequestBoundary(t *testing.T) {
	s := NewServer(t.TempDir())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	h := s.Handler()

	request := func(method, contentType, origin, token, body string) int {
		r := httptest.NewRequest(method, "/api/stop", bytes.NewBufferString(body))
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if token != "" {
			r.Header.Set("X-Livewire-CSRF", token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if got := request(http.MethodGet, "", "", "", ""); got != http.StatusMethodNotAllowed {
		t.Fatalf("GET mutation status=%d", got)
	}
	if got := request(http.MethodPost, "text/plain", "", s.CSRFToken(), `{}`); got != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain status=%d", got)
	}
	if got := request(http.MethodPost, "application/json", "", "", `{}`); got != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d", got)
	}
	if got := request(http.MethodPost, "application/json", "http://evil.example", s.CSRFToken(), `{}`); got != http.StatusForbidden {
		t.Fatalf("cross-origin status=%d", got)
	}
	if got := request(http.MethodPost, "application/json", "", s.CSRFToken(), `{"unexpected":true}`); got != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d", got)
	}
	if got := request(http.MethodPost, "application/json", "", s.CSRFToken(), `{}`); got != http.StatusOK {
		t.Fatalf("valid request status=%d", got)
	}
}

func TestDashboardRejectsNonLoopbackHost(t *testing.T) {
	s, err := NewServerWithConfig(Config{Dir: t.TempDir(), ListenAddr: "127.0.0.1:8080"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(context.Background())
	r := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	r.Host = "attacker.example:8080"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestDashboardRejectsOversizedBodyAndRootEscape(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(dir)
	defer s.Shutdown(context.Background())
	r := httptest.NewRequest(http.MethodPost, "/api/stop", strings.NewReader(strings.Repeat(" ", (1<<20)+1)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Livewire-CSRF", s.CSRFToken())
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "exceeds") {
		t.Fatalf("oversized status=%d body=%s", w.Code, w.Body.String())
	}
	if _, err := s.pcapPath("notes.txt"); err == nil {
		t.Fatal("unsupported capture extension accepted")
	}
	outside := filepath.Join(t.TempDir(), "outside.pcap")
	if err := os.WriteFile(outside, []byte("capture"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "escape.pcap")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if _, err := s.pcapPath("escape.pcap"); err == nil {
		t.Fatal("root-escaping symlink accepted")
	}
}

func TestShutdownStopsAndJoinsActiveJobIdempotently(t *testing.T) {
	s := NewServer(t.TempDir())
	var stopped atomic.Bool
	j, err := s.startJob("blocking", func(j *job) {
		<-j.ctx.Done()
		stopped.Store(true)
		j.finish(false, "stopped")
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-j.done:
	default:
		t.Fatal("shutdown returned before the active job exited")
	}
	if !stopped.Load() {
		t.Fatal("active job did not observe cancellation")
	}
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("second shutdown: %v", err)
	}
}
