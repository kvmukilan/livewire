package replayintent

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/kvmukilan/livewire/internal/replay"
)

func selectionTrace() *replay.Trace {
	session := func(id string, port uint16, request string) *replay.Session {
		return &replay.Session{ID: id, Transport: replay.TransportUDP,
			Client: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.10"), Port: 40000},
			Server: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.20"), Port: port},
			Events: []replay.Event{
				{PacketIndex: 0, Direction: replay.ClientToServer, Payload: []byte(request)},
				{PacketIndex: 1, Direction: replay.ServerToClient, Payload: []byte("reply")},
			}}
	}
	return &replay.Trace{Packets: 4, Sessions: []*replay.Session{session("udp-0", 4000, "first"), session("udp-1", 4000, "second")}}
}

func TestSelectAcceptsFingerprintsAndUniquePrefixes(t *testing.T) {
	trace := selectionTrace()
	want := trace.Sessions[1]
	fingerprint := want.Fingerprint()
	for _, selector := range []string{fingerprint, fingerprint[:6]} {
		selected, err := Select(trace, []string{selector}, nil)
		if err != nil {
			t.Fatalf("select %q: %v", selector, err)
		}
		if len(selected.Sessions) != 1 || selected.Sessions[0].ID != want.ID {
			t.Fatalf("select %q chose %+v", selector, selected.Sessions)
		}
		if len(selected.Excluded) != 1 || selected.Excluded[0].SessionID != "udp-0" || selected.Excluded[0].Fingerprint != trace.Sessions[0].Fingerprint() {
			t.Fatalf("excluded entry lost its identity: %+v", selected.Excluded)
		}
	}
}

func TestSelectRejectsUnknownAndAmbiguousFingerprints(t *testing.T) {
	trace := selectionTrace()
	if _, err := Select(trace, []string{"ffffff"}, nil); err == nil || !strings.Contains(err.Error(), "no session") {
		t.Fatalf("unknown fingerprint accepted: %v", err)
	}
	a, b := trace.Sessions[0].Fingerprint(), trace.Sessions[1].Fingerprint()
	common := 0
	for common < len(a) && a[common] == b[common] {
		common++
	}
	if common >= 4 {
		if _, err := Select(trace, []string{a[:common]}, nil); err == nil || !strings.Contains(err.Error(), "matches") {
			t.Fatalf("ambiguous prefix accepted: %v", err)
		}
	}
	if _, err := Select(trace, []string{"tcp-9"}, nil); err == nil || !strings.Contains(err.Error(), "unknown session") {
		t.Fatalf("unknown ID accepted: %v", err)
	}
}

func TestPlanEntriesCarryFingerprints(t *testing.T) {
	trace := selectionTrace()
	plan := replay.BuildPlan(trace, replay.ProfileFunctional, nil)
	for i, entry := range plan.Entries {
		if entry.Fingerprint != trace.Sessions[i].Fingerprint() {
			t.Fatalf("entry %d fingerprint %q, want %q", i, entry.Fingerprint, trace.Sessions[i].Fingerprint())
		}
	}
}
