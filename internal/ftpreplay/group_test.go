package ftpreplay

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/replay"
)

func TestCapturedFTPEndpointSyntaxes(t *testing.T) {
	if port, ok := capturedPassivePort("227 Entering Passive Mode (192,0,2,1,195,80)\r\n"); !ok || port != 50000 {
		t.Fatalf("PASV port=%d ok=%v", port, ok)
	}
	if port, ok := capturedPassivePort("229 Entering Extended Passive Mode (|||49152|)\r\n"); !ok || port != 49152 {
		t.Fatalf("EPSV port=%d ok=%v", port, ok)
	}
	if endpoint, ok := capturedPORT("192,0,2,10,195,81"); !ok || endpoint != netip.MustParseAddrPort("192.0.2.10:50001") {
		t.Fatalf("PORT endpoint=%v ok=%v", endpoint, ok)
	}
	if endpoint, ok := capturedEPRT("|2|2001:db8::10|50002|"); !ok || endpoint != netip.MustParseAddrPort("[2001:db8::10]:50002") {
		t.Fatalf("EPRT endpoint=%v ok=%v", endpoint, ok)
	}
	for _, invalid := range []string{"", "1,2,3", "1,2,3,4,999,1"} {
		if _, ok := capturedPORT(invalid); ok {
			t.Fatalf("invalid PORT %q accepted", invalid)
		}
	}
	for _, invalid := range []string{"", "|2|bad|21|", "|2|::1|0|"} {
		if _, ok := capturedEPRT(invalid); ok {
			t.Fatalf("invalid EPRT %q accepted", invalid)
		}
	}
}

func TestMatchDataSessionsRejectsAmbiguityAndMissingNegotiation(t *testing.T) {
	control := ftpControlSession(50000)
	script, err := BuildScript(control, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := ftpDataSession(50000, "a")
	b := ftpDataSession(50000, "b")
	a.ID, b.ID = "tcp-1", "tcp-2"
	a.Events[0].PacketIndex, b.Events[0].PacketIndex = 20, 20
	trace := &replay.Trace{Sessions: []*replay.Session{control, a, b}}
	if _, err := MatchDataSessions(trace, control, script); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguity error=%v", err)
	}
	if _, err := MatchDataSessions(&replay.Trace{Sessions: []*replay.Session{control}}, control, script); err == nil || !strings.Contains(err.Error(), "mapped 0") {
		t.Fatalf("missing mapping error=%v", err)
	}
	if _, err := MatchDataSessions(nil, control, script); err == nil {
		t.Fatal("nil trace accepted")
	}
}

func TestMatchMultipleTransfersByChronology(t *testing.T) {
	control := ftpControlSession(50000)
	control.Events = append(control.Events[:len(control.Events)-2],
		replay.Event{PacketIndex: 30, At: 20 * time.Millisecond, Direction: replay.ClientToServer, Payload: []byte("EPSV\r\n")},
		replay.Event{PacketIndex: 31, At: 21 * time.Millisecond, Direction: replay.ServerToClient, Payload: []byte("229 Entering Extended Passive Mode (|||50001|)\r\n")},
		replay.Event{PacketIndex: 32, At: 22 * time.Millisecond, Direction: replay.ClientToServer, Payload: []byte("STOR second.bin\r\n")},
		replay.Event{PacketIndex: 33, At: 23 * time.Millisecond, Direction: replay.ServerToClient, Payload: []byte("150 opening\r\n")},
		replay.Event{PacketIndex: 34, At: 24 * time.Millisecond, Direction: replay.ServerToClient, Payload: []byte("226 done\r\n")},
	)
	first := ftpDataSession(50000, "first")
	second := ftpDataSession(50001, "second")
	second.ID = "tcp-2"
	first.Events[0].PacketIndex, second.Events[0].PacketIndex = 20, 35
	script, err := BuildScript(control, nil)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := MatchDataSessions(&replay.Trace{Sessions: []*replay.Session{control, second, first}}, control, script)
	if err != nil || len(mapped) != 2 || mapped[0].Server.Port != 50000 || mapped[1].Server.Port != 50001 {
		t.Fatalf("mapped=%v err=%v turns=%v", mapped, err, script.Turns)
	}
}
