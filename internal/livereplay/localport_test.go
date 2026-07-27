package livereplay

import (
	"context"
	"net/netip"
	"testing"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/hoststack"
)

// capturingDependencies records the three places a local port must reach: the
// live backend (which filters on it), the host-RST guard rule (which suppresses
// the kernel's reset for it), and the tuple rewriter (which stamps it onto every
// outgoing frame). Missing any one of them silently sends the captured port
// instead, so they are asserted together.
func capturingDependencies(t *testing.T, gotLive *backend.LiveConfig, gotRule *hoststack.Rule, gotSent *[]byte) runDependencies {
	t.Helper()
	b := &lifecycleBackend{}
	return runDependencies{
		openLive: func(c backend.LiveConfig) (*backend.LiveBackend, error) {
			*gotLive = c
			return &backend.LiveBackend{Backend: b, LocalIP: netip.MustParseAddr("198.51.100.10")}, nil
		},
		armGuard: func(r hoststack.Rule) (replayGuard, error) {
			*gotRule = r
			return &lifecycleGuard{}, nil
		},
		drive: func(_ context.Context, f *engine.Flow, _ engine.Options, _ engine.ConvConfig, pb backend.PacketBackend) (engine.Outcome, uint32, error) {
			// Push one captured client frame through the rewriter stack and keep
			// what actually went out, so the assertion is on the wire bytes
			// rather than on configuration alone.
			frame := clientFrame(f)
			if err := pb.Send(frame); err != nil {
				return engine.Outcome{}, 0, err
			}
			*gotSent = frame
			return engine.Outcome{Phase: engine.PhaseClosed}, 123, nil
		},
	}
}

// clientFrame builds a minimal Ethernet/IPv4/TCP frame from the flow's captured
// client endpoint, which is what the tuple rewriter expects to translate.
func clientFrame(f *engine.Flow) []byte {
	frame := make([]byte, 14+20+20)
	// Ethernet: IPv4.
	frame[12], frame[13] = 0x08, 0x00
	ip := frame[14:]
	ip[0] = 0x45 // version 4, 5-word header
	ip[9] = 6    // TCP
	putUint16(ip[2:], 40)
	copy(ip[12:16], f.Client.Addr.AsSlice())
	copy(ip[16:20], f.Server.Addr.AsSlice())
	tcp := frame[34:]
	putUint16(tcp[0:], f.Client.Port)
	putUint16(tcp[2:], f.Server.Port)
	tcp[12] = 5 << 4 // 5-word TCP header
	return frame
}

func putUint16(b []byte, v uint16) {
	b[0], b[1] = byte(v>>8), byte(v)
}

func TestLocalPortOverrideReachesBackendGuardAndWire(t *testing.T) {
	const override = 45123
	cfg := lifecycleConfig()
	cfg.LocalPort = override
	captured := cfg.Flow.Client.Port
	if captured == override {
		t.Fatal("test needs an override that differs from the captured port")
	}

	var live backend.LiveConfig
	var rule hoststack.Rule
	var sent []byte
	if _, err := runContextWithDependencies(context.Background(), cfg, nil,
		capturingDependencies(t, &live, &rule, &sent)); err != nil {
		t.Fatalf("replay failed: %v", err)
	}

	if live.LocalPort != override {
		t.Errorf("backend.LiveConfig.LocalPort = %d, want %d", live.LocalPort, override)
	}
	if rule.LocalPort != override {
		t.Errorf("hoststack.Rule.LocalPort = %d, want %d", rule.LocalPort, override)
	}
	if got := uint16(sent[34])<<8 | uint16(sent[35]); got != override {
		t.Errorf("frame source port = %d, want %d (the tuple rewriter dropped the override)", got, override)
	}
}

func TestZeroLocalPortKeepsTheCapturedPort(t *testing.T) {
	cfg := lifecycleConfig() // LocalPort unset
	captured := cfg.Flow.Client.Port

	var live backend.LiveConfig
	var rule hoststack.Rule
	var sent []byte
	if _, err := runContextWithDependencies(context.Background(), cfg, nil,
		capturingDependencies(t, &live, &rule, &sent)); err != nil {
		t.Fatalf("replay failed: %v", err)
	}

	if live.LocalPort != captured {
		t.Errorf("backend.LiveConfig.LocalPort = %d, want the captured %d", live.LocalPort, captured)
	}
	if rule.LocalPort != captured {
		t.Errorf("hoststack.Rule.LocalPort = %d, want the captured %d", rule.LocalPort, captured)
	}
	if got := uint16(sent[34])<<8 | uint16(sent[35]); got != captured {
		t.Errorf("frame source port = %d, want the captured %d", got, captured)
	}
}

func TestLocalPortOverrideIsLogged(t *testing.T) {
	cfg := lifecycleConfig()
	cfg.LocalPort = 45123
	var lines []string
	var live backend.LiveConfig
	var rule hoststack.Rule
	var sent []byte
	if _, err := runContextWithDependencies(context.Background(), cfg,
		func(l string) { lines = append(lines, l) },
		capturingDependencies(t, &live, &rule, &sent)); err != nil {
		t.Fatalf("replay failed: %v", err)
	}
	for _, l := range lines {
		if len(l) > 16 && l[:16] == "using local port" {
			return
		}
	}
	t.Fatalf("the port substitution was not reported to the operator; log was %q", lines)
}
