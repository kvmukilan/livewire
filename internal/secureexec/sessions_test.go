package secureexec

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kvmukilan/livewire/internal/replay"
)

func fakeSession(id string, outcome Outcome, err error) preparedSession {
	return preparedSession{id: id, prepared: &Prepared{sessionID: id, restartSafe: true, run: func(context.Context) (Outcome, error) { return outcome, err }}}
}

func TestCombineSessionsAggregatesInCaptureOrder(t *testing.T) {
	matched := Outcome{Completed: true, Verified: true, Matched: true, Adapter: "iec104", Requests: 4, Responses: 3, ProtocolVersion: "TLS 1.2", PeerIdentityChecked: true, VerificationEvidence: replay.VerificationEvidence{Cleanup: "complete", Compared: 3}}
	different := matched
	different.Matched, different.Mismatches = false, 1
	different.Differences = []replay.Difference{{Field: "cot", Expected: "4", Actual: "7 negative"}}
	handshake := Outcome{Adapter: "tls-handshake", HandshakeCompleted: true, PeerIdentityChecked: true}
	p, err := combineSessions([]preparedSession{
		fakeSession("tcp-0", different, nil),
		{id: "tcp-4", skipped: "stream does not begin with a TLS handshake record"},
		fakeSession("tcp-15", matched, nil),
		fakeSession("tcp-75", handshake, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	o, err := p.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Sessions) != 4 || o.Sessions[1].Skipped == "" || o.Sessions[1].Status != "skipped" || !o.Sessions[2].Matched {
		t.Fatalf("sessions: %+v", o.Sessions)
	}
	if !o.Completed || !o.Verified || o.Matched || o.Requests != 8 || o.Responses != 6 || o.Mismatches != 1 || o.Adapter != "iec104" || o.ProtocolVersion != "TLS 1.2" {
		t.Fatalf("aggregate: %+v", o)
	}
	if len(o.Differences) != 1 || o.Differences[0].Field != "tcp-0 cot" {
		t.Fatalf("differences keep their session: %+v", o.Differences)
	}
	if !strings.Contains(o.Scope, "3 of 4") || !o.PeerIdentityChecked || o.Status != "different" {
		t.Fatalf("scope/status: %q %q", o.Scope, o.Status)
	}
	joined := strings.Join(o.Transformations, "\n")
	if !strings.Contains(joined, "tcp-4: skipped") || !strings.Contains(joined, "tcp-75: fresh TLS handshake only") {
		t.Fatalf("transformations: %v", o.Transformations)
	}
}

func TestCombineSessionsContinuesAfterFailureAndReportsIt(t *testing.T) {
	ok := Outcome{Completed: true, Verified: true, Matched: true, Adapter: "iec104", Responses: 1, VerificationEvidence: replay.VerificationEvidence{Cleanup: "complete"}}
	broken := Outcome{Adapter: "iec104", VerificationEvidence: replay.VerificationEvidence{Cleanup: "complete"}}
	p, err := combineSessions([]preparedSession{fakeSession("tcp-1", broken, errors.New("fresh handshake failed")), fakeSession("tcp-2", ok, nil)})
	if err != nil {
		t.Fatal(err)
	}
	o, err := p.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "tcp-1: fresh handshake failed") {
		t.Fatalf("error: %v", err)
	}
	if len(o.Sessions) != 2 || o.Sessions[0].Error == "" || !o.Sessions[1].Matched || o.Completed || o.Matched {
		t.Fatalf("outcome: %+v", o)
	}
	if _, err := combineSessions([]preparedSession{{id: "tcp-9", skipped: "no keylog entry"}}); err == nil || !strings.Contains(err.Error(), "none of the 1 selected") {
		t.Fatalf("all skipped must fail before any network use: %v", err)
	}
}
