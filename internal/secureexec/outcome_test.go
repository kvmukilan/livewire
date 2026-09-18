package secureexec

import (
	"context"
	"errors"
	"testing"
)

func TestPreparedCancellationPreventsDialAndErrorClearsMatch(t *testing.T) {
	called := false
	p := &Prepared{run: func(context.Context) (Outcome, error) {
		called = true
		return Outcome{Completed: true, Verified: true, Matched: true}, errors.New("cleanup failed")
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o, err := p.Run(ctx)
	if called || !errors.Is(err, context.Canceled) || o.Status != "cancelled" {
		t.Fatal(o, err, called)
	}
	o, err = p.Run(context.Background())
	if err == nil || o.Completed || o.Matched || o.Status != "incomplete" {
		t.Fatal(o, err)
	}
}

func TestSecureOutcomeRequiresResponseEvidence(t *testing.T) {
	o := Outcome{Completed: true, Verified: true, Matched: true}
	o.Finalize(context.Background(), nil)
	if o.Verified || o.Matched || o.Status != "unverified" {
		t.Fatal(o)
	}
}
