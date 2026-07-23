package livereplay

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/flow"
	"github.com/kvmukilan/livewire/internal/hoststack"
	"github.com/kvmukilan/livewire/internal/wire"
)

type lifecycleBackend struct{ closes int }

func (*lifecycleBackend) Send([]byte) error                             { return nil }
func (*lifecycleBackend) Recv([]byte, time.Duration) (int, bool, error) { return 0, false, nil }
func (*lifecycleBackend) Now() time.Time                                { return time.Now() }
func (*lifecycleBackend) LinkType() wire.LinkType                       { return wire.LinkEthernet }
func (*lifecycleBackend) Caps() backend.Capabilities {
	return backend.CanReceive | backend.StatefulSafe | backend.Layer2
}
func (b *lifecycleBackend) Close() error { b.closes++; return nil }

type lifecycleGuard struct{ releases int }

func (g *lifecycleGuard) Release() error { g.releases++; return nil }
func (*lifecycleGuard) Describe() string { return "test guard" }

func lifecycleConfig() Config {
	return Config{
		Flow: &engine.Flow{
			Client: flow.Endpoint{Addr: netip.MustParseAddr("192.0.2.10"), Port: 40000},
			Server: flow.Endpoint{Addr: netip.MustParseAddr("192.0.2.20"), Port: 80},
			HasSyn: true, HasSynAck: true,
		},
		Iface: "test", TargetIP: netip.MustParseAddr("198.51.100.20"), TargetPort: 80,
	}
}

func lifecycleDependencies(b *lifecycleBackend, g *lifecycleGuard, drive func(context.Context) error) runDependencies {
	return runDependencies{
		openLive: func(backend.LiveConfig) (*backend.LiveBackend, error) {
			return &backend.LiveBackend{Backend: b, LocalIP: netip.MustParseAddr("198.51.100.10")}, nil
		},
		armGuard: func(hoststack.Rule) (replayGuard, error) { return g, nil },
		drive: func(ctx context.Context, _ *engine.Flow, _ engine.Options, _ engine.ConvConfig, _ backend.PacketBackend) (engine.Outcome, uint32, error) {
			err := drive(ctx)
			return engine.Outcome{Phase: engine.PhaseClosed}, 123, err
		},
	}
}

func assertLifecycleReleased(t *testing.T, b *lifecycleBackend, g *lifecycleGuard) {
	t.Helper()
	if b.closes != 1 || g.releases != 1 {
		t.Fatalf("backend closes=%d guard releases=%d", b.closes, g.releases)
	}
}

func TestRunContextReleasesBackendAndGuardOnSuccessErrorAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ctx   func() context.Context
		drive func(context.Context) error
	}{
		{name: "success", ctx: context.Background, drive: func(context.Context) error { return nil }},
		{name: "error", ctx: context.Background, drive: func(context.Context) error { return errors.New("drive failed") }},
		{name: "cancellation", ctx: func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }, drive: func(ctx context.Context) error { return ctx.Err() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, g := &lifecycleBackend{}, &lifecycleGuard{}
			_, _ = runContextWithDependencies(tc.ctx(), lifecycleConfig(), nil, lifecycleDependencies(b, g, tc.drive))
			assertLifecycleReleased(t, b, g)
		})
	}
}

func TestRunContextReleasesBackendAndGuardOnPanic(t *testing.T) {
	b, g := &lifecycleBackend{}, &lifecycleGuard{}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected progress callback panic")
			}
		}()
		_, _ = runContextWithDependencies(context.Background(), lifecycleConfig(), func(line string) {
			if line == "host-RST suppression armed: test guard" {
				panic("test panic")
			}
		}, lifecycleDependencies(b, g, func(context.Context) error { return nil }))
	}()
	assertLifecycleReleased(t, b, g)
}

func TestRunContextVerificationOffNeverClaimsMatch(t *testing.T) {
	for _, tc := range []struct {
		name       string
		verify     engine.VerifyMode
		wantVerify bool
		wantMatch  bool
	}{
		{name: "off", verify: engine.VerifyOff},
		{name: "strict-clean", verify: engine.VerifyStrict, wantVerify: true, wantMatch: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := lifecycleConfig()
			cfg.Verify = tc.verify
			b, g := &lifecycleBackend{}, &lifecycleGuard{}
			result, err := runContextWithDependencies(context.Background(), cfg, nil, lifecycleDependencies(b, g, func(context.Context) error { return nil }))
			if err != nil || result.Verified != tc.wantVerify || result.Matched != tc.wantMatch {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			assertLifecycleReleased(t, b, g)
		})
	}
}
