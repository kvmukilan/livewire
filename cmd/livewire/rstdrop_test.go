package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/kvmukilan/livewire/internal/hoststack"
)

type testRSTGuard struct {
	releases int
	err      error
}

func (g *testRSTGuard) Release() error { g.releases++; return g.err }
func (*testRSTGuard) Describe() string { return "test rule" }

type rstTestWriter func([]byte) (int, error)

func (w rstTestWriter) Write(p []byte) (int, error) { return w(p) }

func TestRSTDropReleasesGuardOnOutputFailure(t *testing.T) {
	writeErr, releaseErr := errors.New("output closed"), errors.New("delete failed")
	guard := &testRSTGuard{err: releaseErr}
	err := holdRSTDrop(context.Background(), rstTestWriter(func([]byte) (int, error) {
		return 0, writeErr
	}), hoststack.Rule{}, func(hoststack.Rule) (rstDropGuard, error) { return guard, nil })
	if !errors.Is(err, writeErr) || !errors.Is(err, releaseErr) || guard.releases != 1 {
		t.Fatalf("error=%v releases=%d; require output and cleanup failures", err, guard.releases)
	}
}

func TestRSTDropReleasesBeforeFinalOutput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := &testRSTGuard{}
	writes := 0
	err := holdRSTDrop(ctx, rstTestWriter(func(p []byte) (int, error) {
		writes++
		if writes == 1 {
			cancel()
		} else if guard.releases != 1 || !strings.Contains(string(p), "rule removed") {
			t.Fatalf("final status before release: releases=%d output=%q", guard.releases, p)
		}
		return len(p), nil
	}), hoststack.Rule{}, func(hoststack.Rule) (rstDropGuard, error) { return guard, nil })
	if err != nil || writes != 2 || guard.releases != 1 {
		t.Fatalf("error=%v writes=%d releases=%d", err, writes, guard.releases)
	}
}

func TestRSTDropCancelledBeforeArm(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := holdRSTDrop(ctx, io.Discard, hoststack.Rule{}, func(hoststack.Rule) (rstDropGuard, error) {
		t.Fatal("cancelled command armed a rule")
		return nil, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func TestRSTDropCleanupFailureDoesNotClaimRemoval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deleteErr := errors.New("delete failed")
	guard := &testRSTGuard{err: deleteErr}
	var output strings.Builder
	err := holdRSTDrop(ctx, rstTestWriter(func(p []byte) (int, error) {
		cancel()
		return output.Write(p)
	}), hoststack.Rule{}, func(hoststack.Rule) (rstDropGuard, error) { return guard, nil })
	if !errors.Is(err, deleteErr) || guard.releases != 2 || strings.Contains(output.String(), "rule removed") {
		t.Fatalf("error=%v releases=%d output=%q; require failed cleanup plus deferred retry", err, guard.releases, output.String())
	}
}

func TestProgressOutputFailureCancelsReplay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writeCommandProgress(rstTestWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe }), cancel, "guard armed\n")
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("output failure left replay running")
	}
}
