package replay

import (
	"context"
	"fmt"
	"testing"
)

func TestResultStatusNeverUpgradesFailureOrUnverifiedSend(t *testing.T) {
	for _, tc := range []struct {
		completed, verified, matched, wire bool
		err                                error
		want                               string
	}{
		{true, true, true, false, nil, "matched"},
		{true, true, false, false, nil, "different"},
		{true, false, true, false, nil, "unverified"},
		{false, true, true, false, nil, "incomplete"},
		{true, true, true, false, fmt.Errorf("cleanup: %w", context.Canceled), "cancelled"},
		{true, true, true, false, context.DeadlineExceeded, "incomplete"},
		{true, false, false, true, nil, "wire"},
		{false, false, false, true, context.Canceled, "cancelled"},
	} {
		if got := ResultStatus(tc.completed, tc.verified, tc.matched, tc.wire, tc.err); got != tc.want {
			t.Fatalf("got %s want %s", got, tc.want)
		}
	}
}
