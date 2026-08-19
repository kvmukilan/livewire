// Package orchestration owns the execution mechanics shared by the CLI and
// dashboard: bounded capture loading, exact plan scheduling, and atomic
// redacted artifact publication.
package orchestration

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/runvars"
	"github.com/kvmukilan/livewire/internal/securefile"
)

func LoadFile(path string) (pcapio.Capture, error) {
	return pcapio.LoadFile(path, pcapio.DefaultLimits())
}

func Load(reader io.Reader) (pcapio.Capture, error) {
	return pcapio.Load(reader, pcapio.DefaultLimits())
}

// ExecutePlan runs functional entries in order and timing/transport/wire
// entries against one shared start instant. Coordinated entries already own
// every related session, so the scheduler invokes each plan entry exactly once.
func ExecutePlan[T any](ctx context.Context, trace *replay.Trace, plan replay.ReplayPlan, run func(context.Context, int, replay.PlanEntry, *replay.Session, time.Time) T) []T {
	if ctx == nil {
		ctx = context.Background()
	}
	sessions := make(map[string]*replay.Session, len(trace.Sessions))
	for _, session := range trace.Sessions {
		sessions[session.ID] = session
	}
	results := make([]T, len(plan.Entries))
	started := time.Now()
	invoke := func(i int) { results[i] = run(ctx, i, plan.Entries[i], sessions[plan.Entries[i].SessionID], started) }
	concurrent := plan.Profile == replay.ProfileTiming || plan.Profile == replay.ProfileTransport || plan.Profile == replay.ProfileWire
	if !concurrent {
		for i := range plan.Entries {
			invoke(i)
		}
		return results
	}
	var wg sync.WaitGroup
	for i := range plan.Entries {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			invoke(i)
		}(i)
	}
	wg.Wait()
	return results
}

func CreateArtifact(path string) (*securefile.AtomicFile, error) {
	return securefile.Create(path)
}

func WriteJSON(path string, value any, redactor *runvars.Redactor) error {
	if redactor == nil {
		redactor = runvars.NewRedactor(nil)
	}
	b, err := redactor.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return securefile.WriteFileAtomic(path, append(b, '\n'))
}
