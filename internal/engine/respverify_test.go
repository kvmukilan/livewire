package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/dissect"
)

// Modbus read-holding-registers request/response used across the verify tests.
var (
	mbReq  = []byte{0x00, 0x07, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02}
	mbResp = []byte{0x00, 0x07, 0x00, 0x00, 0x00, 0x07, 0x01, 0x03, 0x04, 0x01, 0x40, 0x00, 0x00}
)

// driveVerify runs a replay with a chosen verify mode against a peer whose
// server replies are optionally transformed to differ from the capture.
func driveVerify(t *testing.T, mode VerifyMode, transform func([]byte) []byte) (Outcome, *Conversation) {
	t.Helper()
	recs := session("10.0.0.9", "10.0.0.1", 5000, 502, mbReq, mbResp)
	f := ExtractFlows(recs)[0]
	opts := Options{Seed: 42}
	peer := NewMockPeer(f, BehaviorCompliant, opts)
	peer.RespTransform = transform
	b := backend.NewMock(peer, f.Packets[0].Rec.LinkType, time.Unix(1700000000, 0))
	c, err := NewConversation(f, opts, ConvConfig{Verify: mode})
	if err != nil {
		t.Fatalf("NewConversation: %v", err)
	}
	out, err := Drive(c, b, 1000)
	if err != nil {
		t.Fatalf("Drive: %v", err)
	}
	return out, c
}

// A faithful device passes strict verification with no divergences.
func TestVerifyCompliantMatches(t *testing.T) {
	out, _ := driveVerify(t, VerifyStrict, nil)
	if !out.Succeeded() {
		t.Fatalf("compliant replay should succeed: phase=%s reason=%q", out.Phase, out.Reason)
	}
	if !out.RepliesMatched() || len(out.Mismatches) != 0 {
		t.Fatalf("expected a clean match, got %d mismatch(es): %+v", len(out.Mismatches), out.Mismatches)
	}
}

// A device that returns the same Modbus function with different register values
// is a value drift: lenient mode reports it but the flow still completes, and it
// is not counted as a structural divergence.
func TestVerifyValueDriftLenient(t *testing.T) {
	drift := func(p []byte) []byte {
		q := append([]byte(nil), p...)
		q[len(q)-1] ^= 0xff // change a register value byte; length unchanged
		q[len(q)-2] ^= 0xff
		return q
	}
	out, _ := driveVerify(t, VerifyLenient, drift)
	if !out.Succeeded() {
		t.Fatalf("value drift should not stop a same-length replay: phase=%s reason=%q", out.Phase, out.Reason)
	}
	if !out.RepliesMatched() {
		t.Fatalf("value drift must not count as a structural divergence (got %d)", out.ReplyMismatches)
	}
	if len(out.Mismatches) == 0 {
		t.Fatal("lenient mode should still report the value drift")
	}
	if !strings.Contains(out.Mismatches[0].Detail, "data differs") {
		t.Fatalf("drift detail should mention data, got %q", out.Mismatches[0].Detail)
	}
}

// A device that returns a Modbus exception where the capture had a normal reply
// is a structural divergence: strict mode aborts the flow immediately.
func TestVerifyExceptionStrictAborts(t *testing.T) {
	except := func(p []byte) []byte {
		m, _, err := dissect.ParseMBAP(p)
		if err != nil {
			t.Fatalf("test fixture not Modbus: %v", err)
		}
		m.Function |= 0x80
		m.Data = []byte{0x02} // illegal data address
		return dissect.EncodeMBAP(m)
	}
	out, _ := driveVerify(t, VerifyStrict, except)
	if !out.Aborted {
		t.Fatalf("strict mode should abort on an exception reply, phase=%s", out.Phase)
	}
	if out.ReplyMismatches == 0 {
		t.Fatal("expected a structural mismatch to be recorded")
	}
	if !strings.Contains(out.Reason, "diverged") || !strings.Contains(out.Reason, "exception") {
		t.Fatalf("abort reason should explain the exception, got %q", out.Reason)
	}
}

// Even in lenient mode the exception is detected and reported (the flow may not
// complete because the shorter reply stalls the byte clock, but the cause is
// captured rather than surfacing as an opaque timeout).
func TestVerifyExceptionLenientDetected(t *testing.T) {
	except := func(p []byte) []byte {
		m, _, _ := dissect.ParseMBAP(p)
		m.Function |= 0x80
		m.Data = []byte{0x02}
		return dissect.EncodeMBAP(m)
	}
	out, _ := driveVerify(t, VerifyLenient, except)
	if out.ReplyMismatches == 0 {
		t.Fatal("lenient mode should still detect the exception as structural")
	}
	if !strings.Contains(out.Mismatches[0].Detail, "exception") {
		t.Fatalf("mismatch should name the exception, got %q", out.Mismatches[0].Detail)
	}
}

// Verification is off by default: a bare ConvConfig{} records nothing.
func TestVerifyOffByDefault(t *testing.T) {
	drift := func(p []byte) []byte { q := append([]byte(nil), p...); q[len(q)-1] ^= 0xff; return q }
	recs := session("10.0.0.9", "10.0.0.1", 5000, 502, mbReq, mbResp)
	f := ExtractFlows(recs)[0]
	opts := Options{Seed: 42}
	peer := NewMockPeer(f, BehaviorCompliant, opts)
	peer.RespTransform = drift
	b := backend.NewMock(peer, f.Packets[0].Rec.LinkType, time.Unix(1700000000, 0))
	c, _ := NewConversation(f, opts, ConvConfig{}) // no Verify set
	out, err := Drive(c, b, 1000)
	if err != nil {
		t.Fatalf("Drive: %v", err)
	}
	if len(out.Mismatches) != 0 {
		t.Fatalf("verification should be off by default, got %d mismatch(es)", len(out.Mismatches))
	}
}

func TestCompareADU(t *testing.T) {
	want, _, _ := dissect.ParseMBAP(mbResp)

	// Identical -> no diffs.
	if d := dissect.CompareADU(want, want); len(d) != 0 {
		t.Fatalf("identical ADUs should not differ, got %+v", d)
	}

	// Exception -> structural.
	exc := want
	exc.Function |= 0x80
	exc.Data = []byte{0x02}
	d := dissect.CompareADU(want, exc)
	if len(d) == 0 || !d[0].Structural || !strings.Contains(d[0].Detail, "exception") {
		t.Fatalf("exception should be a structural diff, got %+v", d)
	}

	// Same function, different data -> non-structural value drift.
	drift := want
	drift.Data = append([]byte(nil), want.Data...)
	drift.Data[0] ^= 0xff
	d = dissect.CompareADU(want, drift)
	if len(d) != 1 || d[0].Structural {
		t.Fatalf("value drift should be a single non-structural diff, got %+v", d)
	}

	// Transaction id not echoed -> structural.
	badID := want
	badID.TransactionID = want.TransactionID + 1
	d = dissect.CompareADU(want, badID)
	if len(d) == 0 || !d[0].Structural || !strings.Contains(d[0].Detail, "transaction id") {
		t.Fatalf("txid mismatch should be structural, got %+v", d)
	}
}
