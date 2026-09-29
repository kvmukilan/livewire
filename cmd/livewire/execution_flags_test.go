package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/iterate"
	"github.com/kvmukilan/livewire/internal/replay"
)

func TestStrictExitRequiresEverySelectedExchange(t *testing.T) {
	for _, v := range []iterate.Verdict{iterate.Same, iterate.Different, iterate.Unverified, iterate.WireOnly, iterate.Incomplete} {
		var tally iterate.Tally
		tally.Add(iterate.Same)
		tally.Add(v)
		summary := iterate.SummarizeContext(context.Background(), []iterate.Tally{tally}, 1)
		e := strictExitError(true, context.Background(), summary)
		if (e == nil) != (v == iterate.Same) {
			t.Fatalf("verdict %v: %v", v, e)
		}
		if strictExitError(false, context.Background(), summary) != nil {
			t.Fatal("legacy exit changed")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if strictExitError(true, ctx, iterate.Summary{}) == nil {
		t.Fatal("cancelled run succeeded")
	}
}

func TestDurableCLIOptionsAndPreview(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	o := executionFlags{concurrency: 32, stateDir: dir, runTimeout: time.Second}
	if e := o.validate(); e != nil {
		t.Fatal(e)
	}
	if e := o.openState("capture", map[string]string{"target": "device"}, false); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := o.context(context.Background())
	defer cancel()
	if replay.Execution(ctx).Journal != o.journal {
		t.Fatal("runtime lost journal")
	}
	if _, ok := ctx.Deadline(); !ok {
		t.Fatal("missing run timeout")
	}
	if e := o.journal.Close(); e != nil {
		t.Fatal(e)
	}
	preview := executionFlags{concurrency: 32, resumeDir: dir}
	if e := preview.openState("capture", map[string]string{"target": "device"}, true); e != nil {
		t.Fatal(e)
	}
	if e := preview.journal.Close(); e != nil {
		t.Fatal(e)
	}
	if e := preview.openState("capture", map[string]string{"target": "changed"}, false); e == nil {
		t.Fatal("changed target accepted")
	}
	for _, bad := range []executionFlags{{concurrency: 0}, {concurrency: 1025}, {concurrency: 32, runTimeout: -1}, {concurrency: 32, stateDir: "a", resumeDir: "b"}} {
		if bad.validate() == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}
