package tlsreplay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// The deadline is already elapsed, but Err has not been set: this models the
// socket timer winning the race against the context timer without a flaky sleep.
type pendingDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (c pendingDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestReplayContextErrorClassifiesSocketDeadlineBeforeContextTimer(t *testing.T) {
	ctx := pendingDeadlineContext{Context: context.Background(), deadline: time.Now().Add(-time.Second)}
	timeout := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	for _, err := range []error{timeout, fmt.Errorf("wrapped read: %w", timeout)} {
		if ctx.Err() != nil {
			t.Fatal("regression requires the context timer to remain pending")
		}
		if got := replayContextError(ctx, err); !errors.Is(got, context.DeadlineExceeded) {
			t.Fatalf("elapsed context deadline returned %v", got)
		}
	}
}

func TestReplayContextErrorPreservesIndependentIOErrors(t *testing.T) {
	timeout := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	early := pendingDeadlineContext{Context: context.Background(), deadline: time.Now().Add(time.Hour)}
	elapsed := pendingDeadlineContext{Context: context.Background(), deadline: time.Now().Add(-time.Second)}
	for _, test := range []struct {
		name string
		ctx  context.Context
		err  error
	}{
		{"earlier exchange timeout", early, timeout},
		{"timeout without context deadline", context.Background(), timeout},
		{"non-timeout after deadline", elapsed, io.ErrUnexpectedEOF},
		{"success after deadline", elapsed, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := replayContextError(test.ctx, test.err); got != test.err {
				t.Fatalf("changed independent I/O result %v to %v", test.err, got)
			}
		})
	}
}

func TestReplayContextErrorPreservesExplicitCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := replayContextError(ctx, os.ErrDeadlineExceeded); !errors.Is(got, context.Canceled) {
		t.Fatalf("explicit cancellation returned %v", got)
	}
}
