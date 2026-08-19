package webui

import (
	"net/http"
	"strings"
	"testing"

	"github.com/kvmukilan/livewire/internal/iterate"
	"github.com/kvmukilan/livewire/internal/replay"
)

// The attempts field comes straight from a number box in the browser, so it has
// to be bounded and validated server-side rather than trusted.
func TestAdaptiveRunValidatesAttempts(t *testing.T) {
	cases := []struct {
		name     string
		attempts any
		gap      any
		wantCode int
		wantBody string
	}{
		{name: "negative attempts", attempts: -1, wantCode: http.StatusBadRequest, wantBody: "attempts must be between"},
		{name: "absurd attempts", attempts: 1001, wantCode: http.StatusBadRequest, wantBody: "attempts must be between"},
		{name: "at the ceiling", attempts: maxWebAttempts, wantCode: http.StatusOK},
		{name: "one past the ceiling", attempts: maxWebAttempts + 1, wantCode: http.StatusBadRequest, wantBody: "attempts must be between"},
		{name: "negative gap", attempts: 2, gap: -5, wantCode: http.StatusBadRequest, wantBody: "gapMs must not be negative"},
		{name: "zero gap is allowed", attempts: 2, gap: 0, wantCode: http.StatusOK},
		{name: "omitted attempts means one run", attempts: nil, wantCode: http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeWebTestPcap(t, dir)
			h := testHandler(t, dir)
			body := map[string]any{
				"pcap": "sample.pcap", "iface": "test0", "targetIP": "192.0.2.2",
				"profile": "functional", "verify": "lenient",
			}
			if c.attempts != nil {
				body["attempts"] = c.attempts
			}
			if c.gap != nil {
				body["gapMs"] = c.gap
			}
			w := postJSON(t, h, "/api/run", body)
			if w.Code != c.wantCode {
				t.Fatalf("status=%d want %d body=%s", w.Code, c.wantCode, w.Body.String())
			}
			if c.wantBody != "" && !strings.Contains(w.Body.String(), c.wantBody) {
				t.Fatalf("body=%s want it to mention %q", w.Body.String(), c.wantBody)
			}
		})
	}
}

// The dashboard and the CLI must agree on what a result means, which is why both
// route through iterate.Classify rather than each deciding for itself.
func TestWebSessionResultVerdict(t *testing.T) {
	cases := []struct {
		name string
		res  webSessionResult
		want iterate.Verdict
	}{
		{"completed and matched", webSessionResult{Completed: true, Matched: true}, iterate.Same},
		{"completed but different", webSessionResult{Completed: true}, iterate.Different},
		{"did not complete", webSessionResult{}, iterate.Incomplete},
		{"an error outranks the flags", webSessionResult{Completed: true, Matched: true, Error: "boom"}, iterate.Incomplete},
		{"wire mode claims nothing", webSessionResult{Completed: true, Matched: true, Entry: replay.PlanEntry{Mode: replay.ModeWire}}, iterate.WireOnly},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.res.verdict(); got != c.want {
				t.Fatalf("verdict() = %v, want %v", got, c.want)
			}
		})
	}
}
