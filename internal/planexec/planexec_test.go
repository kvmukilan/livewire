package planexec

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/flow"
	"github.com/kvmukilan/livewire/internal/replay"
)

func TestWaitOffsetHonorsCancellationAndPastTargets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitOffset(ctx, time.Now(), time.Second) {
		t.Fatal("cancelled wait reported success")
	}
	if !waitOffset(context.Background(), time.Now(), -time.Millisecond) {
		t.Fatal("past target did not complete")
	}
}

func TestFindFlowUsesCompleteTuple(t *testing.T) {
	client, server := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.20")
	flow := &engine.Flow{Client: flow.Endpoint{Addr: client, Port: 41000}, Server: flow.Endpoint{Addr: server, Port: 443}}
	session := &replay.Session{Client: replay.Endpoint{IP: client, Port: 41000}, Server: replay.Endpoint{IP: server, Port: 443}}
	if got := findFlow([]*engine.Flow{flow}, session); got != flow {
		t.Fatalf("flow lookup=%p want %p", got, flow)
	}
	session.Server.Port++
	if got := findFlow([]*engine.Flow{flow}, session); got != nil {
		t.Fatalf("mismatched tuple returned flow %p", got)
	}
}

func TestBlockedEntryWithoutReasonCannotPanic(t *testing.T) {
	entry := replay.PlanEntry{SessionID: "blocked-0", Mode: replay.ModeBlocked}
	result := ExecuteEntry(Config{Trace: &replay.Trace{}}, entry, nil, time.Now())
	if result.Err == nil {
		t.Fatal("blocked entry without a reason was accepted")
	}
}
