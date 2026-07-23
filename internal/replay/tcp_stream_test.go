package replay

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

func TestTCPPayloadStreamsSequenceAware(t *testing.T) {
	tests := []struct {
		name     string
		segments []tcpStreamTestSegment
		want     string
		wantErr  string
	}{
		{name: "out of order", segments: []tcpStreamTestSegment{{104, 0, "ef"}, {100, 0, "abcd"}}, want: "abcdef"},
		{name: "partial retransmission", segments: []tcpStreamTestSegment{{100, 0, "abcd"}, {102, 0, "cdef"}}, want: "abcdef"},
		{name: "sequence wrap", segments: []tcpStreamTestSegment{{0xfffffffc, 0, "abcd"}, {0, 0, "ef"}}, want: "abcdef"},
		{name: "SYN consumes sequence", segments: []tcpStreamTestSegment{{100, wire.FlagSYN, "a"}, {102, 0, "b"}}, want: "ab"},
		{name: "gap", segments: []tcpStreamTestSegment{{100, 0, "abcd"}, {105, 0, "f"}}, wantErr: "missing 1 byte"},
		{name: "conflicting retransmission", segments: []tcpStreamTestSegment{{100, 0, "abcd"}, {102, 0, "XX"}}, wantErr: "conflicting overlap"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := tcpStreamTestSession(tt.segments)
			client, server, err := TCPPayloadStreams(session)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error=%v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(client) != tt.want || len(server) != 0 {
				t.Fatalf("client=%q server=%q, want client=%q", client, server, tt.want)
			}
		})
	}
}

func TestSemanticTurnsOrdersSegmentsWithinCaptureTurn(t *testing.T) {
	session := tcpStreamTestSession([]tcpStreamTestSegment{{104, 0, "ef"}, {100, 0, "abcd"}})
	turns, err := semanticTurns(session)
	if err != nil {
		t.Fatal(err)
	}
	if len(turns) != 1 || string(turns[0].data) != "abcdef" {
		t.Fatalf("turns=%+v", turns)
	}
}

func TestTCPStreamTimelineUsesEarliestCompleteCoverage(t *testing.T) {
	session := tcpStreamTestSession([]tcpStreamTestSegment{{104, 0, "ef"}, {100, 0, "abcd"}, {100, 0, "abcd"}})
	session.Events[0].At = time.Millisecond
	session.Events[1].At = 3 * time.Millisecond
	session.Events[2].At = 8 * time.Millisecond // late retransmission must not delay completion
	client, _, err := TCPPayloadTimelines(session)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := client.CompletionTime(4, 6); !ok || got != time.Millisecond {
		t.Fatalf("tail completion=%s ok=%v", got, ok)
	}
	if got, ok := client.CompletionTime(0, 6); !ok || got != 3*time.Millisecond {
		t.Fatalf("stream completion=%s ok=%v", got, ok)
	}
}

func TestPlanBlocksBrokenAdaptiveTCPButAllowsExplicitWire(t *testing.T) {
	session := tcpStreamTestSession([]tcpStreamTestSegment{{100, 0, "abcd"}, {105, 0, "f"}})
	trace := &Trace{Packets: 2, Sessions: []*Session{session}}
	functional := BuildPlan(trace, ProfileFunctional, nil)
	if functional.Entries[0].Mode != ModeBlocked || !strings.Contains(strings.Join(functional.Entries[0].Blockers, " "), "missing 1 byte") {
		t.Fatalf("functional entry=%+v", functional.Entries[0])
	}
	wirePlan := BuildPlan(trace, ProfileWire, nil)
	if wirePlan.Entries[0].Mode != ModeWire || len(wirePlan.Entries[0].Blockers) != 0 {
		t.Fatalf("wire entry=%+v", wirePlan.Entries[0])
	}
}

type tcpStreamTestSegment struct {
	seq     uint32
	flags   uint8
	payload string
}

func tcpStreamTestSession(segments []tcpStreamTestSegment) *Session {
	client := netip.MustParseAddr("192.0.2.10")
	server := netip.MustParseAddr("198.51.100.20")
	session := &Session{ID: "tcp-test", Transport: TransportTCP, Client: Endpoint{IP: client, Port: 41000}, Server: Endpoint{IP: server, Port: 80}}
	for i, segment := range segments {
		payload := []byte(segment.payload)
		frame := tcpStreamTestFrame(client.As4(), server.As4(), 41000, 80, segment.seq, segment.flags, payload)
		session.Events = append(session.Events, Event{
			PacketIndex: i,
			Direction:   ClientToServer,
			Payload:     payload,
			Record:      &pcapio.Record{Data: frame, CapLen: len(frame), OrigLen: len(frame), LinkType: wire.LinkEthernet},
		})
	}
	return session
}

func tcpStreamTestFrame(src, dst [4]byte, sport, dport uint16, seq uint32, flags uint8, payload []byte) []byte {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = 5 << 4
	tcp[13] = flags
	copy(tcp[20:], payload)
	return ipv4Frame(wire.ProtoTCP, src, dst, tcp)
}
