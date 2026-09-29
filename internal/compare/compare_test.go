package compare

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/replay"
)

// exchange builds a session from alternating request and reply payloads. Each
// request is stamped at 10 ms intervals and each reply replyDelay after it.
func exchange(id string, transport replay.Transport, port uint16, replyDelay time.Duration, turns ...[2]string) *replay.Session {
	s := &replay.Session{ID: id, Transport: transport,
		Client: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.10"), Port: 40000},
		Server: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.20"), Port: port}}
	at := time.Duration(0)
	for i, turn := range turns {
		s.Events = append(s.Events,
			replay.Event{PacketIndex: 2 * i, At: at, Direction: replay.ClientToServer, Payload: []byte(turn[0])},
			replay.Event{PacketIndex: 2*i + 1, At: at + replyDelay, Direction: replay.ServerToClient, Payload: []byte(turn[1])})
		at += 10 * time.Millisecond
	}
	return s
}

func trace(sessions ...*replay.Session) *replay.Trace {
	return &replay.Trace{Sessions: sessions, Packets: 2 * len(sessions)}
}

func TestIdenticalCapturesMatch(t *testing.T) {
	recorded := exchange("udp-0", replay.TransportUDP, 4000, time.Millisecond, [2]string{"ping", "pong"}, [2]string{"ping2", "pong2"})
	actual := exchange("udp-7", replay.TransportUDP, 4000, time.Millisecond, [2]string{"ping", "pong"}, [2]string{"ping2", "pong2"})
	actual.Client.Port = 51000
	report := Traces(trace(recorded), trace(actual), Options{})
	if report.Verdict != Matched || len(report.Sessions) != 1 {
		t.Fatalf("report=%+v", report)
	}
	s := report.Sessions[0]
	if s.Status != Matched || s.ActualID != "udp-7" || s.Fingerprint != recorded.Fingerprint() || s.FirstDivergence != nil {
		t.Fatalf("session=%+v", s)
	}
	if s.Recorded.Requests != 2 || s.Actual.Replies != 2 || s.Recorded.RequestBytes != 9 {
		t.Fatalf("counts=%+v/%+v", s.Recorded, s.Actual)
	}
	if s.Timing == nil || s.Timing.Turns != 2 || s.Timing.RecordedResponseMS != 1 || s.Timing.SlowdownFactor != 1 {
		t.Fatalf("timing=%+v", s.Timing)
	}
}

func TestRawReplyDivergenceIsLocated(t *testing.T) {
	recorded := exchange("udp-0", replay.TransportUDP, 4000, time.Millisecond, [2]string{"ping", "pong-ok"})
	actual := exchange("udp-0", replay.TransportUDP, 4000, time.Millisecond, [2]string{"ping", "pong-ERR"})
	report := Traces(trace(recorded), trace(actual), Options{})
	if report.Verdict != Different || report.Summary.Different != 1 {
		t.Fatalf("report=%+v", report)
	}
	s := report.Sessions[0]
	if s.Status != Different || s.FirstDivergence == nil {
		t.Fatalf("session=%+v", s)
	}
	if s.FirstDivergence.Direction != "reply" || s.FirstDivergence.Offset != 5 || s.FirstDivergence.Expected != fmt.Sprintf("2 bytes, sha256:%x", sha256.Sum256([]byte("ok"))) || s.FirstDivergence.Actual != fmt.Sprintf("3 bytes, sha256:%x", sha256.Sum256([]byte("ERR"))) {
		t.Fatalf("divergence=%+v", s.FirstDivergence)
	}
	if len(s.Differences) != 1 || s.Differences[0].Field != "reply-bytes" || !s.Differences[0].Structural {
		t.Fatalf("differences=%+v", s.Differences)
	}
}

func TestMissingSessionMakesTheReportIncomplete(t *testing.T) {
	recorded := trace(
		exchange("udp-0", replay.TransportUDP, 4000, time.Millisecond, [2]string{"a", "b"}),
		exchange("udp-1", replay.TransportUDP, 5000, time.Millisecond, [2]string{"c", "d"}),
	)
	actual := trace(
		exchange("udp-0", replay.TransportUDP, 4000, time.Millisecond, [2]string{"a", "b"}),
		exchange("udp-9", replay.TransportUDP, 6000, time.Millisecond, [2]string{"x", "y"}),
	)
	report := Traces(recorded, actual, Options{})
	if report.Verdict != Incomplete || report.Summary.Missing != 1 || report.Summary.Matched != 1 {
		t.Fatalf("report=%+v", report)
	}
	if report.Sessions[1].Status != Missing || report.Sessions[1].ActualID != "" {
		t.Fatalf("missing session=%+v", report.Sessions[1])
	}
	if len(report.Unpaired) != 1 || report.Unpaired[0] != "udp-9" {
		t.Fatalf("unpaired=%v", report.Unpaired)
	}
}

func TestFramedComparisonUsesTheProtocolAdapter(t *testing.T) {
	request := "GET /status HTTP/1.1\r\nHost: device\r\n\r\n"
	ok := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	failed := "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 2\r\n\r\nno"
	recorded := exchange("tcp-0", replay.TransportTCP, 80, 2*time.Millisecond, [2]string{request, ok})
	actual := exchange("tcp-0", replay.TransportTCP, 80, 20*time.Millisecond, [2]string{request, failed})
	report := Traces(trace(recorded), trace(actual), Options{})
	s := report.Sessions[0]
	if s.Adapter != "http/1" || s.Status != Different {
		t.Fatalf("session=%+v", s)
	}
	if s.FirstDivergence == nil || s.FirstDivergence.Direction != "reply" || s.FirstDivergence.Message != 1 {
		t.Fatalf("divergence=%+v", s.FirstDivergence)
	}
	if s.Recorded.Replies != 1 || s.Actual.Requests != 1 {
		t.Fatalf("counts=%+v/%+v", s.Recorded, s.Actual)
	}
	if s.Timing == nil || s.Timing.SlowdownFactor < 9.9 || s.Timing.SlowdownFactor > 10.1 {
		t.Fatalf("timing=%+v", s.Timing)
	}
	same := Traces(trace(recorded), trace(exchange("tcp-3", replay.TransportTCP, 80, time.Millisecond, [2]string{request, ok})), Options{})
	if same.Verdict != Matched || same.Sessions[0].Adapter != "http/1" {
		t.Fatalf("identical HTTP exchange reported %+v", same.Sessions[0])
	}
}

func TestPairingPrefersIdenticalContentOverOrder(t *testing.T) {
	first := exchange("udp-0", replay.TransportUDP, 4000, time.Millisecond, [2]string{"one", "1"})
	second := exchange("udp-1", replay.TransportUDP, 4000, time.Millisecond, [2]string{"two", "2"})
	swappedSecond := exchange("udp-0", replay.TransportUDP, 4000, time.Millisecond, [2]string{"two", "2"})
	swappedFirst := exchange("udp-1", replay.TransportUDP, 4000, time.Millisecond, [2]string{"one", "1"})
	report := Traces(trace(first, second), trace(swappedSecond, swappedFirst), Options{})
	if report.Verdict != Matched {
		t.Fatalf("report=%+v", report)
	}
	if report.Sessions[0].ActualID != "udp-1" || report.Sessions[1].ActualID != "udp-0" {
		t.Fatalf("pairing=%s,%s", report.Sessions[0].ActualID, report.Sessions[1].ActualID)
	}
}

func TestExcerptShowsWhereDataEnds(t *testing.T) {
	if got := excerpt([]byte("abc"), 3); got != "(end of data)" {
		t.Fatalf("excerpt past end = %q", got)
	}
	if got := excerpt(make([]byte, 40), 0); got != fmt.Sprintf("40 bytes, sha256:%x", sha256.Sum256(make([]byte, 40))) {
		t.Fatalf("long excerpt = %q", got)
	}
}
