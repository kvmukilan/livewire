package replay

import (
	"net/netip"
	"testing"
	"time"
)

func fingerprintSession(clientPort uint16, at time.Duration, payloads ...string) *Session {
	s := &Session{ID: "tcp-0", Transport: TransportTCP,
		Client: Endpoint{IP: netip.MustParseAddr("192.0.2.10"), Port: clientPort},
		Server: Endpoint{IP: netip.MustParseAddr("192.0.2.20"), Port: 502}}
	for i, p := range payloads {
		dir := ClientToServer
		if i%2 == 1 {
			dir = ServerToClient
		}
		s.Events = append(s.Events, Event{PacketIndex: i, At: at + time.Duration(i)*time.Millisecond, Direction: dir, Payload: []byte(p)})
	}
	return s
}

func TestFingerprintNamesContentNotPosition(t *testing.T) {
	a := fingerprintSession(40000, 0, "req", "rep")
	b := fingerprintSession(51234, time.Hour, "req", "rep")
	b.ID = "tcp-9"
	b.Client.IP = netip.MustParseAddr("10.0.0.1")
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatalf("same exchange, different fingerprints: %s vs %s", a.Fingerprint(), b.Fingerprint())
	}
	if len(a.Fingerprint()) != FingerprintLength {
		t.Fatalf("fingerprint length %d", len(a.Fingerprint()))
	}
	c := fingerprintSession(40000, 0, "req", "rep!")
	if c.Fingerprint() == a.Fingerprint() {
		t.Fatal("a different reply produced the same fingerprint")
	}
	d := fingerprintSession(40000, 0, "req", "rep")
	d.Server.Port = 503
	if d.Fingerprint() == a.Fingerprint() {
		t.Fatal("a different service produced the same fingerprint")
	}
	e := fingerprintSession(40000, 0, "req", "rep")
	e.Events[0].Direction, e.Events[1].Direction = ServerToClient, ClientToServer
	if e.Fingerprint() == a.Fingerprint() {
		t.Fatal("swapping directions produced the same fingerprint")
	}
	var nilSession *Session
	if nilSession.Fingerprint() != "" {
		t.Fatal("nil session has a fingerprint")
	}
}

func TestLooksLikeFingerprint(t *testing.T) {
	for selector, want := range map[string]bool{
		"a1b2c3d4e5f6": true, "a1b2": true, "tcp-0": false, "raw-0": false, "A1B2": false, "abc": false, "a1b2c3d4e5f6a": false,
	} {
		if got := LooksLikeFingerprint(selector); got != want {
			t.Errorf("LooksLikeFingerprint(%q) = %v, want %v", selector, got, want)
		}
	}
}
