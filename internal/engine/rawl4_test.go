package engine

import (
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/wire"
)

// Raw-L4 replay fires every client packet in order (waiting only for the
// SYN-ACK) and still drives the flow to a clean close against a live peer.
func TestRawL4ReplaysClientFrames(t *testing.T) {
	recs := session("10.0.0.9", "10.0.0.1", 5000, 502, []byte("req"), []byte("resp"))
	f := ExtractFlows(recs)[0]
	// Count client-to-server packets in the capture.
	wantSent := 0
	for _, p := range f.Packets {
		if p.Dir == C2S {
			wantSent++
		}
	}
	opts := Options{Seed: 42}
	peer := NewMockPeer(f, BehaviorCompliant, opts)
	b := backend.NewMock(peer, f.Packets[0].Rec.LinkType, time.Unix(1700000000, 0))
	c, err := NewConversation(f, opts, ConvConfig{RawL4: true})
	if err != nil {
		t.Fatalf("NewConversation: %v", err)
	}
	out, err := Drive(c, b, 1000)
	if err != nil {
		t.Fatalf("Drive: %v", err)
	}
	if !out.Succeeded() {
		t.Fatalf("raw-L4 replay did not complete: phase=%s reason=%q", out.Phase, out.Reason)
	}
	if out.Sent != wantSent {
		t.Fatalf("raw-L4 sent %d client frames, want %d", out.Sent, wantSent)
	}
}

// A synthesized SYN carries the MSS and SACK-permitted options a real SYN would,
// so a device that branches on them sees a realistic handshake.
func TestSynthesizedSYNHasOptions(t *testing.T) {
	full := session("10.0.0.9", "10.0.0.1", 5000, 502, mbReq, mbResp)
	flows := ExtractFlows(full[3:]) // mid-stream, no handshake
	g, err := SynthesizeHandshake(flows[0])
	if err != nil {
		t.Fatalf("SynthesizeHandshake: %v", err)
	}
	syn := g.Packets[0]
	p, err := wire.Parse(syn.Rec.Data, syn.Rec.LinkType)
	if err != nil {
		t.Fatalf("parse synthetic SYN: %v", err)
	}
	if _, ok := p.MSS(); !ok {
		t.Fatal("synthetic SYN is missing the MSS option")
	}
	if !p.SACKPermitted() {
		t.Fatal("synthetic SYN is missing the SACK-permitted option")
	}
	if !p.HasFlags(wire.FlagSYN) {
		t.Fatal("synthetic SYN does not have the SYN flag set")
	}
}
