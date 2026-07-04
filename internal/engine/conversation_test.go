package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
)

// driveFlow runs a single-flow replay against a scripted peer to completion.
func driveFlow(t *testing.T, sport, dport uint16, behavior PeerBehavior, req, resp []byte) (Outcome, *Conversation, *MockPeer) {
	t.Helper()
	recs := session("10.0.0.9", "10.0.0.1", sport, dport, req, resp)
	flows := ExtractFlows(recs)
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	f := flows[0]
	opts := Options{Seed: 42}

	peer := NewMockPeer(f, behavior, opts)
	b := backend.NewMock(peer, f.Packets[0].Rec.LinkType, time.Unix(1700000000, 0))
	c, err := NewConversation(f, opts, ConvConfig{})
	if err != nil {
		t.Fatalf("NewConversation: %v", err)
	}
	out, err := Drive(c, b, 1000)
	if err != nil {
		t.Fatalf("Drive: %v", err)
	}
	return out, c, peer
}

// TestConversationCompliant: full replay against a compliant peer, recovering the hidden ISN.
func TestConversationCompliant(t *testing.T) {
	out, c, peer := driveFlow(t, 5000, 502, BehaviorCompliant, []byte("modbus-req"), []byte("modbus-response"))
	if !out.Succeeded() {
		t.Fatalf("expected success, got phase=%s aborted=%v reason=%q", out.Phase, out.Aborted, out.Reason)
	}
	if !c.serverKnown {
		t.Fatal("engine never learned the server ISN")
	}
	if got, want := c.sess.LiveServerISN.Uint32(), peer.HiddenISN(); got != want {
		t.Fatalf("learned server ISN %#x, peer chose %#x", got, want)
	}
	if out.Retransmits != 0 {
		t.Fatalf("compliant peer should need no retransmits, got %d", out.Retransmits)
	}
}

// TestConversationReSegment: byte-count tracking stays in sync when the peer
// re-segments differently than the capture (where packet-index tracking desyncs).
func TestConversationReSegment(t *testing.T) {
	out, c, _ := driveFlow(t, 5001, 502, BehaviorReSegment, []byte("read-holding-regs"), []byte("values-0102030405060708"))
	if !out.Succeeded() {
		t.Fatalf("re-segmenting peer broke sync: phase=%s reason=%q", out.Phase, out.Reason)
	}
	if !c.serverKnown {
		t.Fatal("engine never learned the server ISN")
	}
}

// TestConversationDropRecovers: a lost server response is recovered by retransmission.
func TestConversationDropRecovers(t *testing.T) {
	out, _, _ := driveFlow(t, 5002, 20000, BehaviorDropFirstResponse, []byte("dnp3-read"), []byte("dnp3-class-data"))
	if !out.Succeeded() {
		t.Fatalf("expected recovery, got phase=%s reason=%q", out.Phase, out.Reason)
	}
	if out.Retransmits < 1 {
		t.Fatalf("expected at least one retransmit to recover the drop, got %d", out.Retransmits)
	}
}

// TestConversationResetAborts: a peer RST ends the conversation cleanly.
func TestConversationResetAborts(t *testing.T) {
	out, _, _ := driveFlow(t, 5003, 502, BehaviorResetOnData, []byte("modbus-req"), []byte("never-arrives"))
	if !out.Aborted {
		t.Fatalf("expected abort on RST, got phase=%s", out.Phase)
	}
	if !strings.Contains(out.Reason, "RST") {
		t.Fatalf("abort reason should mention RST, got %q", out.Reason)
	}
	if out.Phase != PhaseAborted {
		t.Fatalf("expected phase aborted, got %s", out.Phase)
	}
}

// TestConversationMultiFlow: independent flows replay with their own learned
// ISNs (no cross-flow global state).
func TestConversationMultiFlow(t *testing.T) {
	cases := []struct {
		sport, dport uint16
		proto        string
	}{
		{6000, 502, "Modbus"},
		{6001, 20000, "DNP3"},
		{6002, 80, "HTTP"},
	}
	for _, tc := range cases {
		out, c, peer := driveFlow(t, tc.sport, tc.dport, BehaviorCompliant, []byte("req-"+tc.proto), []byte("resp-"+tc.proto))
		if !out.Succeeded() {
			t.Fatalf("%s flow failed: phase=%s reason=%q", tc.proto, out.Phase, out.Reason)
		}
		if c.sess.LiveServerISN.Uint32() != peer.HiddenISN() {
			t.Fatalf("%s flow: ISN recovery mismatch", tc.proto)
		}
	}
}

// TestConversationNoHandshakeRejected: replay refuses a capture missing the SYN/SYN-ACK.
func TestConversationNoHandshakeRejected(t *testing.T) {
	recs := session("10.0.0.9", "10.0.0.1", 7000, 502, []byte("x"), []byte("y"))
	flows := ExtractFlows(recs[3:]) // drop the handshake
	if len(flows) == 0 {
		t.Skip("no flow extracted without handshake")
	}
	if _, err := NewConversation(flows[0], Options{Seed: 1}, ConvConfig{}); err == nil {
		t.Fatal("expected NewConversation to reject a handshake-less flow")
	}
}
