package main

import (
	"strings"
	"testing"

	"github.com/kvmukilan/livewire/internal/engine"
)

func TestDiagnose(t *testing.T) {
	cases := []struct {
		name string
		out  engine.Outcome
		mode string
		want string // substring expected ("" = empty diagnosis)
	}{
		{"faithful", engine.Outcome{Phase: engine.PhaseClosed}, "stateful", ""},
		{"answered-differently",
			engine.Outcome{Phase: engine.PhaseClosed, Mismatches: []engine.Mismatch{{Structural: true}}, ReplyMismatches: 1},
			"stateful", "differently"},
		{"reset", engine.Outcome{Phase: engine.PhaseAborted, Aborted: true, Reason: "peer sent RST"}, "stateful", "reset"},
		{"stalled", engine.Outcome{Phase: engine.PhaseAborted, Aborted: true, Reason: "stalled in phase established"}, "stateful", "stopped responding"},
		{"stateless", engine.Outcome{Phase: engine.PhaseClosed}, "stateless", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := diagnose(tc.out, tc.mode)
			if tc.want == "" {
				if got != "" {
					t.Fatalf("expected no diagnosis, got %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("diagnosis %q does not contain %q", got, tc.want)
			}
		})
	}
}
