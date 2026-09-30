package webui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRSTAddAfterShutdownCannotArmRule(t *testing.T) {
	s := NewServer(t.TempDir())
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	// An HTTP request whose body finishes after shutdown must not acquire a
	// guard after Shutdown has already taken its snapshot of owned resources.
	r := httptest.NewRequest(http.MethodPost, "/api/rstrule", strings.NewReader(`{"action":"add","ip":"192.0.2.1","port":502}`))
	w := httptest.NewRecorder()
	s.handleRSTRule(w, r)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "shutting down") {
		t.Fatalf("late add status=%d body=%s", w.Code, w.Body.String())
	}
	if len(s.rstRuleKeys()) != 0 {
		t.Fatal("late request installed a rule")
	}
}
