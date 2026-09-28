package orchestration

import (
	"context"
	"sync"

	"github.com/kvmukilan/livewire/internal/replay"
)

// RunBounded invokes each index exactly once; cancelled tasks still produce
// explicit results through their callback instead of disappearing from reports.
func RunBounded(ctx context.Context, count int, run func(int)) {
	workers := replay.Execution(ctx).Concurrency
	if workers <= 0 {
		workers = 32
	}
	workers = min(workers, count)
	var wg sync.WaitGroup
	jobs := make(chan int)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				run(i)
			}
		}()
	}
	for i := 0; i < count; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
}
