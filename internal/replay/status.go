package replay

import (
	"context"
	"errors"
)

// ResultStatus is additive report vocabulary. Existing booleans and exit codes
// remain compatible; cancellation and failed cleanup take priority over a match.
func ResultStatus(completed, verified, matched, wire bool, err error) string {
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if err != nil || !completed {
		return "incomplete"
	}
	if wire {
		return "wire"
	}
	if !verified {
		return "unverified"
	}
	if matched {
		return "matched"
	}
	return "different"
}
