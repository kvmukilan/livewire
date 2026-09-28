package orchestration

import (
	"context"
	"github.com/kvmukilan/livewire/internal/replay"
	"sync/atomic"
	"testing"
	"time"
)

func TestBoundedWorkersLimitAndAccountForEveryTask(t *testing.T) {
	ctx := replay.WithExecution(context.Background(), replay.ExecutionConfig{Concurrency: 3})
	var active, peak, completed atomic.Int32
	RunBounded(ctx, 70, func(int) {
		n := active.Add(1)
		for {
			old := peak.Load()
			if old >= n || peak.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		active.Add(-1)
		completed.Add(1)
	})
	if peak.Load() > 3 || completed.Load() != 70 {
		t.Fatalf("peak=%d completed=%d", peak.Load(), completed.Load())
	}
}
