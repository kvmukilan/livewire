package lab

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/wire"
)

type countedLabBackend struct {
	backend.PacketBackend
	closes   atomic.Int32
	failSend bool
}

func (b *countedLabBackend) Send(frame []byte) error {
	if b.failSend {
		return errors.New("injected send failure")
	}
	return b.PacketBackend.Send(frame)
}

func (b *countedLabBackend) Close() error {
	b.closes.Add(1)
	return b.PacketBackend.Close()
}

func (b *countedLabBackend) LinkType() wire.LinkType { return b.PacketBackend.LinkType() }

func TestRunContextClosesOwnedLabBackendsOnEveryExit(t *testing.T) {
	tests := []struct {
		name      string
		ctx       func() context.Context
		failSend  bool
		panicRun  bool
		wantError bool
	}{
		{name: "success", ctx: context.Background},
		{name: "send error", ctx: context.Background, failSend: true, wantError: true},
		{name: "cancellation", ctx: func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }, wantError: true},
		{name: "progress panic", ctx: context.Background, panicRun: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sim, err := NewDUTSimulator(SimulatorConfig{Mode: "pass"})
			if err != nil {
				t.Fatal(err)
			}
			base := sim.Backends()
			all := []*countedLabBackend{
				{PacketBackend: base.ClientTX, failSend: tt.failSend},
				{PacketBackend: base.ClientRX},
				{PacketBackend: base.ServerTX},
				{PacketBackend: base.ServerRX},
			}
			previous := acquireBackends
			acquireBackends = func(Topology) (Backends, error) {
				return Backends{ClientTX: all[0], ClientRX: all[1], ServerTX: all[2], ServerRX: all[3]}, nil
			}
			defer func() { acquireBackends = previous }()

			cfg := Config{
				Trace: twoWayUDPTrace(), Topology: labTopology(), Scenario: Scenario{Version: 1, Seed: 1},
				Profile: replay.ProfileTiming, Drain: time.Millisecond, ActorTimeout: 20 * time.Millisecond,
			}
			if tt.panicRun {
				cfg.Progress = func(Progress) { panic("progress panic") }
				func() {
					defer func() {
						if recover() == nil {
							t.Fatal("expected progress panic")
						}
					}()
					_, _ = RunContext(tt.ctx(), cfg)
				}()
			} else {
				_, runErr := RunContext(tt.ctx(), cfg)
				if (runErr != nil) != tt.wantError {
					t.Fatalf("run error=%v wantError=%v", runErr, tt.wantError)
				}
			}
			for i, candidate := range all {
				if got := candidate.closes.Load(); got != 1 {
					t.Fatalf("backend %d closes=%d", i, got)
				}
			}
		})
	}
}
