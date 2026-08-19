package orchestration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/runvars"
)

func TestExecutePlanAndRedactedArtifact(t *testing.T) {
	trace := &replay.Trace{Sessions: []*replay.Session{{ID: "one"}, {ID: "two"}}}
	plan := replay.ReplayPlan{Profile: replay.ProfileTiming, Entries: []replay.PlanEntry{{SessionID: "one"}, {SessionID: "two"}}}
	var calls atomic.Int32
	results := ExecutePlan(context.Background(), trace, plan, func(_ context.Context, _ int, _ replay.PlanEntry, session *replay.Session, _ time.Time) string {
		calls.Add(1)
		return session.ID
	})
	if calls.Load() != 2 || strings.Join(results, ",") != "one,two" {
		t.Fatalf("calls=%d results=%v", calls.Load(), results)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	secret := "quoted\" secret"
	if err := WriteJSON(path, map[string]string{"error": secret}, runvars.NewRedactor(nil, secret)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(b), "quoted") {
		t.Fatalf("report=%q err=%v", b, err)
	}
}
