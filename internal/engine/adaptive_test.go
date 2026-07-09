package engine

import (
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

// twoTurn builds a TCP flow with two request/response exchanges then a clean
// close, so a test can verify the adaptive clock stays correct across turns
// after an earlier reply changed length.
func twoTurn(req1, resp1, req2, resp2 []byte) []*pcapio.Record {
	const cli, srv = "10.0.0.9", "10.0.0.1"
	const sp, dp = uint16(5000), uint16(502)
	const C, S = 1000, 500000
	r1, p1, r2, p2 := uint32(len(req1)), uint32(len(resp1)), uint32(len(req2)), uint32(len(resp2))
	frames := [][]byte{
		frameTS(cli, srv, sp, dp, C, 0, wire.FlagSYN, 100, 0, nil),
		frameTS(srv, cli, dp, sp, S, C+1, wire.FlagSYN|wire.FlagACK, 900, 100, nil),
		frameTS(cli, srv, sp, dp, C+1, S+1, wire.FlagACK, 101, 900, nil),
		// turn 1
		frameTS(cli, srv, sp, dp, C+1, S+1, wire.FlagACK|wire.FlagPSH, 102, 900, req1),
		frameTS(srv, cli, dp, sp, S+1, C+1+r1, wire.FlagACK|wire.FlagPSH, 901, 102, resp1),
		frameTS(cli, srv, sp, dp, C+1+r1, S+1+p1, wire.FlagACK, 103, 901, nil),
		// turn 2
		frameTS(cli, srv, sp, dp, C+1+r1, S+1+p1, wire.FlagACK|wire.FlagPSH, 104, 901, req2),
		frameTS(srv, cli, dp, sp, S+1+p1, C+1+r1+r2, wire.FlagACK|wire.FlagPSH, 902, 104, resp2),
		frameTS(cli, srv, sp, dp, C+1+r1+r2, S+1+p1+p2, wire.FlagACK, 105, 902, nil),
		// close
		frameTS(cli, srv, sp, dp, C+1+r1+r2, S+1+p1+p2, wire.FlagFIN|wire.FlagACK, 106, 902, nil),
		frameTS(srv, cli, dp, sp, S+1+p1+p2, C+2+r1+r2, wire.FlagFIN|wire.FlagACK, 903, 106, nil),
		frameTS(cli, srv, sp, dp, C+2+r1+r2, S+2+p1+p2, wire.FlagACK, 107, 903, nil),
	}
	recs := make([]*pcapio.Record, len(frames))
	base := time.Unix(1700000000, 0)
	for i, fr := range frames {
		recs[i] = &pcapio.Record{Time: base.Add(time.Duration(i) * time.Millisecond), Data: fr, LinkType: wire.LinkEthernet}
	}
	return recs
}

// driveModes runs the same flow against the same (possibly length-changing)
// device under both the exact byte-clock and the adaptive clock, so a test can
// contrast their outcomes.
func driveModes(t *testing.T, mode VerifyMode, transform func([]byte) []byte) (exact, adaptive Outcome) {
	t.Helper()
	run := func(adaptiveOn bool) Outcome {
		recs := session("10.0.0.9", "10.0.0.1", 5000, 502, mbReq, mbResp)
		f := ExtractFlows(recs)[0]
		opts := Options{Seed: 42}
		peer := NewMockPeer(f, BehaviorCompliant, opts)
		peer.RespTransform = transform
		b := backend.NewMock(peer, f.Packets[0].Rec.LinkType, time.Unix(1700000000, 0))
		c, err := NewConversation(f, opts, ConvConfig{Verify: mode, Adaptive: adaptiveOn})
		if err != nil {
			t.Fatalf("NewConversation: %v", err)
		}
		out, err := Drive(c, b, 1000)
		if err != nil {
			t.Fatalf("Drive: %v", err)
		}
		return out
	}
	return run(false), run(true)
}

// The headline improvement: a device that answers with a shorter Modbus
// exception stalls the exact byte-clock (it waits forever for bytes that never
// come) but completes cleanly under the adaptive clock, which re-anchors on what
// the server actually sent.
func TestAdaptiveCompletesShorterReply(t *testing.T) {
	except := func(p []byte) []byte {
		m, _, err := dissect.ParseMBAP(p)
		if err != nil {
			t.Fatalf("fixture not Modbus: %v", err)
		}
		m.Function |= 0x80
		m.Data = []byte{0x02} // illegal data address — a 9-byte ADU vs the 13-byte reply
		return dissect.EncodeMBAP(m)
	}
	exact, adaptive := driveModes(t, VerifyLenient, except)

	if exact.Succeeded() {
		t.Fatal("exact byte-clock should stall on a shorter reply (this is the limitation adaptive fixes)")
	}
	if !adaptive.Succeeded() {
		t.Fatalf("adaptive clock should complete the flow despite the shorter reply: phase=%s reason=%q",
			adaptive.Phase, adaptive.Reason)
	}
	// The divergence is still reported under either clock.
	if adaptive.ReplyMismatches == 0 {
		t.Fatal("adaptive replay should still report the exception as a divergence")
	}
}

// Adaptive mode is faithful on a compliant device: same success, no retransmits,
// no divergences.
func TestAdaptiveCompliantUnchanged(t *testing.T) {
	_, adaptive := driveModes(t, VerifyLenient, nil)
	if !adaptive.Succeeded() {
		t.Fatalf("adaptive replay of a compliant device should succeed: phase=%s reason=%q",
			adaptive.Phase, adaptive.Reason)
	}
	if adaptive.ReplyMismatches != 0 {
		t.Fatalf("compliant device should show no divergences, got %d", adaptive.ReplyMismatches)
	}
	if adaptive.Retransmits != 0 {
		t.Fatalf("compliant device should need no retransmits, got %d", adaptive.Retransmits)
	}
}

// Drift immunity: when the first of two responses comes back short, the adaptive
// clock measures each turn relative to its own request, so the *second* turn
// still completes even though the live server's byte layout no longer matches
// the capture after the first divergence.
func TestAdaptiveMultiTurnAfterDrift(t *testing.T) {
	recs := twoTurn([]byte("REQ1"), []byte("RESPONSE-ONE"), []byte("REQ2"), []byte("RESPONSE-TWO"))
	f := ExtractFlows(recs)[0]
	opts := Options{Seed: 42}
	peer := NewMockPeer(f, BehaviorCompliant, opts)
	// Shorten only the first response; the peer drifts its later sequence numbers.
	first := true
	peer.RespTransform = func(p []byte) []byte {
		if first {
			first = false
			return p[:len(p)/2] // half-length reply on turn 1
		}
		return p
	}
	b := backend.NewMock(peer, f.Packets[0].Rec.LinkType, time.Unix(1700000000, 0))
	c, err := NewConversation(f, opts, ConvConfig{Adaptive: true})
	if err != nil {
		t.Fatalf("NewConversation: %v", err)
	}
	out, err := Drive(c, b, 1000)
	if err != nil {
		t.Fatalf("Drive: %v", err)
	}
	if !out.Succeeded() {
		t.Fatalf("adaptive clock should complete both turns after a first-reply shortfall: phase=%s reason=%q",
			out.Phase, out.Reason)
	}
}

// A device that answers with a longer reply (extra registers) also completes
// under the adaptive clock, acking the real byte count.
func TestAdaptiveCompletesLongerReply(t *testing.T) {
	longer := func(p []byte) []byte {
		m, _, err := dissect.ParseMBAP(p)
		if err != nil {
			t.Fatalf("fixture not Modbus: %v", err)
		}
		m.Data = append(append([]byte(nil), m.Data...), 0xde, 0xad, 0xbe, 0xef) // two extra registers
		return dissect.EncodeMBAP(m)
	}
	_, adaptive := driveModes(t, VerifyLenient, longer)
	if !adaptive.Succeeded() {
		t.Fatalf("adaptive replay should complete with a longer reply: phase=%s reason=%q",
			adaptive.Phase, adaptive.Reason)
	}
}
