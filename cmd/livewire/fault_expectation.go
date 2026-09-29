package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"syscall"

	"github.com/kvmukilan/livewire/internal/replay"
)

// Fault evidence is separate from exchange equivalence. Seeing a reset or a
// response timeout never marks an incomplete exchange as completed or matched.
type faultObservation struct {
	Expected     string `json:"expected"`
	Observed     string `json:"observed,omitempty"`
	Stage        string `json:"stage"`
	RequestsSent int    `json:"requestsSent"`
	Matched      bool   `json:"matched"`
}

func observeExpectedFault(ctx context.Context, expected string, sent int, cleanup string, err error) *faultObservation {
	if expected == "" {
		return nil
	}
	o := &faultObservation{Expected: expected, Stage: "expected-response-read", RequestsSent: sent}
	if sent == 0 || cleanup != "complete" || ctx.Err() != nil {
		return o
	}
	// Additional errors (journal publication, cleanup, etc.) invalidate a pass.
	for err != nil {
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			if len(joined.Unwrap()) != 1 {
				return o
			}
			err = joined.Unwrap()[0]
			continue
		}
		if response, ok := err.(*replay.ResponseReadError); ok {
			var nerr net.Error
			switch {
			case errors.Is(response.Err, context.DeadlineExceeded) || (errors.As(response.Err, &nerr) && nerr.Timeout()):
				o.Observed = "timeout"
			case errors.Is(response.Err, syscall.ECONNRESET) || (runtime.GOOS == "windows" && errors.Is(response.Err, syscall.Errno(10054))):
				o.Observed = "reset"
			}
			o.Matched = o.Observed == expected
			return o
		}
		err = errors.Unwrap(err)
	}
	return o
}

func faultExpectationError(ctx context.Context, expected string, observations []*faultObservation) error {
	if expected == "" {
		return nil
	}
	matched := 0
	for _, o := range observations {
		if o != nil && o.Matched {
			matched++
		}
	}
	fmt.Printf("Expected %s observed in %d of %d exchanges. This records the fault; it does not assert response equivalence.\n", expected, matched, len(observations))
	if ctx.Err() != nil || matched == 0 || matched != len(observations) {
		return fmt.Errorf("expected %s was not positively observed in every selected exchange", expected)
	}
	return nil
}
