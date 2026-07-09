package engine

import (
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
)

// A mid-stream capture (handshake dropped) is made replayable by synthesizing a
// handshake, and the resulting flow replays to a clean close against a peer.
func TestSynthesizeHandshakeReplays(t *testing.T) {
	full := session("10.0.0.9", "10.0.0.1", 5000, 502, mbReq, mbResp)
	mid := full[3:] // drop SYN, SYN-ACK, and the handshake ACK
	flows := ExtractFlows(mid)
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	f := flows[0]
	if f.HasSyn || f.HasSynAck {
		t.Fatal("test setup wrong: flow still has a handshake")
	}

	g, err := SynthesizeHandshake(f)
	if err != nil {
		t.Fatalf("SynthesizeHandshake: %v", err)
	}
	if !g.HasSyn || !g.HasSynAck {
		t.Fatal("synthesized flow still lacks a handshake")
	}
	if len(g.Packets) != len(f.Packets)+2 {
		t.Fatalf("expected 2 synthetic packets prepended, got %d extra", len(g.Packets)-len(f.Packets))
	}

	opts := Options{Seed: 42}
	peer := NewMockPeer(g, BehaviorCompliant, opts)
	b := backend.NewMock(peer, g.Packets[0].Rec.LinkType, time.Unix(1700000000, 0))
	c, err := NewConversation(g, opts, ConvConfig{})
	if err != nil {
		t.Fatalf("NewConversation on synthesized flow: %v", err)
	}
	out, err := Drive(c, b, 1000)
	if err != nil {
		t.Fatalf("Drive: %v", err)
	}
	if !out.Succeeded() {
		t.Fatalf("synthesized replay did not complete: phase=%s reason=%q", out.Phase, out.Reason)
	}
}

// A flow with only one direction can't be anchored, so synthesis refuses.
func TestSynthesizeHandshakeNeedsBothDirections(t *testing.T) {
	full := session("10.0.0.9", "10.0.0.1", 5000, 502, mbReq, mbResp)
	flows := ExtractFlows(full[3:])
	f := flows[0]
	// Keep only client-to-server packets.
	var c2s []CapturedPacket
	for _, p := range f.Packets {
		if p.Dir == C2S {
			c2s = append(c2s, p)
		}
	}
	f.Packets = c2s
	if _, err := SynthesizeHandshake(f); err == nil {
		t.Fatal("expected synthesis to fail without any server packet")
	}
}
