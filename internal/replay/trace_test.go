package replay

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

func ipv4Frame(proto byte, src, dst [4]byte, l4 []byte) []byte {
	f := make([]byte, 14+20+len(l4))
	binary.BigEndian.PutUint16(f[12:14], 0x0800)
	ip := f[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, proto
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(l4)))
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	copy(f[34:], l4)
	p, _ := wire.Parse(f, wire.LinkEthernet)
	p.RecalcChecksums()
	return f
}

func udp(srcPort, dstPort uint16, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(b[0:2], srcPort)
	binary.BigEndian.PutUint16(b[2:4], dstPort)
	binary.BigEndian.PutUint16(b[4:6], uint16(len(b)))
	copy(b[8:], payload)
	return b
}

func icmp(typ byte, id, seq uint16, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	b[0] = typ
	binary.BigEndian.PutUint16(b[4:6], id)
	binary.BigEndian.PutUint16(b[6:8], seq)
	copy(b[8:], payload)
	return b
}

func TestExtractTraceCoversUDPICMPAndRaw(t *testing.T) {
	base := time.Unix(100, 0)
	a, b := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}
	recs := []*pcapio.Record{
		{Time: base, Data: ipv4Frame(wire.ProtoUDP, a, b, udp(50000, 53, []byte("q"))), LinkType: wire.LinkEthernet},
		{Time: base.Add(time.Millisecond), Data: ipv4Frame(wire.ProtoUDP, b, a, udp(53, 50000, []byte("a"))), LinkType: wire.LinkEthernet},
		{Time: base.Add(2 * time.Millisecond), Data: ipv4Frame(wire.ProtoICMPv4, a, b, icmp(8, 7, 1, []byte("x"))), LinkType: wire.LinkEthernet},
		{Time: base.Add(3 * time.Millisecond), Data: ipv4Frame(wire.ProtoICMPv4, b, a, icmp(0, 7, 1, []byte("x"))), LinkType: wire.LinkEthernet},
		{Time: base.Add(4 * time.Millisecond), Data: []byte{1, 2, 3}, LinkType: wire.LinkEthernet},
	}
	tr := ExtractTrace(recs, ExtractOptions{})
	if len(tr.Sessions) != 2 || len(tr.Raw) != 1 {
		t.Fatalf("sessions=%d raw=%d", len(tr.Sessions), len(tr.Raw))
	}
	if tr.Sessions[0].Transport != TransportUDP || tr.Sessions[0].Server.Port != 53 {
		t.Fatalf("unexpected UDP session: %+v", tr.Sessions[0])
	}
	if tr.Sessions[1].Transport != TransportICMP4 || tr.Sessions[1].Client.IP != netip.AddrFrom4(a) {
		t.Fatalf("unexpected ICMP session: %+v", tr.Sessions[1])
	}
	plan := BuildPlan(tr, ProfileFunctional, nil)
	if err := plan.ValidateCoverage(); err != nil {
		t.Fatal(err)
	}
}

func TestUDPSessionsSplitOnIdle(t *testing.T) {
	base := time.Unix(200, 0)
	a, b := [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}
	recs := []*pcapio.Record{
		{Time: base, Data: ipv4Frame(wire.ProtoUDP, a, b, udp(50000, 53, nil)), LinkType: wire.LinkEthernet},
		{Time: base.Add(31 * time.Second), Data: ipv4Frame(wire.ProtoUDP, a, b, udp(50000, 53, nil)), LinkType: wire.LinkEthernet},
	}
	tr := ExtractTrace(recs, ExtractOptions{UDPIdle: 30 * time.Second})
	if len(tr.Sessions) != 2 {
		t.Fatalf("got %d sessions", len(tr.Sessions))
	}
}

func TestWireProfileNeverClaimsStateful(t *testing.T) {
	tr := &Trace{Packets: 1, Raw: []Event{{PacketIndex: 0}}}
	p := BuildPlan(tr, ProfileWire, nil)
	if p.Entries[0].Driver != "frame-injector" || p.Entries[0].Mode != ModeWire || p.Entries[0].Fidelity != FidelityWire {
		t.Fatalf("%+v", p.Entries[0])
	}
}

func TestPlanNamesConcreteDrivers(t *testing.T) {
	client := netip.MustParseAddr("192.0.2.10")
	server := netip.MustParseAddr("192.0.2.20")
	for transport, want := range map[Transport]string{
		TransportTCP:   "tcp-state-machine",
		TransportUDP:   "udp-turns",
		TransportICMP4: "icmp-echo",
	} {
		trace := &Trace{Packets: 1, Sessions: []*Session{{
			ID: string(transport) + "-0", Transport: transport,
			Client: Endpoint{IP: client, Port: 1000}, Server: Endpoint{IP: server, Port: 2000},
			Events: []Event{{PacketIndex: 0}},
		}}}
		entry := BuildPlan(trace, ProfileFunctional, nil).Entries[0]
		if entry.Driver != want {
			t.Fatalf("%s driver=%q want=%q", transport, entry.Driver, want)
		}
	}
}

func ipv6Fragment(id uint32, offset int, more bool, payload []byte) []byte {
	ip := make([]byte, 40)
	ip[0], ip[6], ip[7] = 0x60, 44, 64
	binary.BigEndian.PutUint16(ip[4:6], uint16(8+len(payload)))
	src := netip.MustParseAddr("2001:db8::1").As16()
	dst := netip.MustParseAddr("2001:db8::2").As16()
	copy(ip[8:24], src[:])
	copy(ip[24:40], dst[:])
	fh := make([]byte, 8)
	fh[0] = wire.ProtoUDP
	word := uint16(offset/8) << 3
	if more {
		word |= 1
	}
	binary.BigEndian.PutUint16(fh[2:4], word)
	binary.BigEndian.PutUint32(fh[4:8], id)
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x86dd)
	return append(append(append(eth, ip...), fh...), payload...)
}

func TestExtractTraceReassemblesIPv6FragmentsWithCoverage(t *testing.T) {
	full := udp(1200, 53, []byte("fragmented-dns-like-payload"))
	f0 := ipv6Fragment(0x10203040, 0, true, full[:16])
	f1 := ipv6Fragment(0x10203040, 16, false, full[16:])
	base := time.Unix(300, 0)
	recs := []*pcapio.Record{
		{Time: base, Data: f1, LinkType: wire.LinkEthernet},
		{Time: base.Add(time.Millisecond), Data: f0, LinkType: wire.LinkEthernet},
	}
	tr := ExtractTrace(recs, ExtractOptions{})
	if len(tr.Raw) != 0 || len(tr.Sessions) != 1 {
		t.Fatalf("raw=%d sessions=%d", len(tr.Raw), len(tr.Sessions))
	}
	s := tr.Sessions[0]
	if !s.Fragmented || s.Transport != TransportUDP || len(s.Events) != 2 {
		t.Fatalf("fragmented session=%+v", s)
	}
	var payload []byte
	for _, e := range s.Events {
		payload = append(payload, e.Payload...)
	}
	if !bytes.Equal(payload, []byte("fragmented-dns-like-payload")) {
		t.Fatalf("reassembled payload=%q", payload)
	}
	functional := BuildPlan(tr, ProfileFunctional, nil)
	if err := functional.ValidateCoverage(); err != nil {
		t.Fatal(err)
	}
	if functional.Entries[0].Mode != ModeStateful {
		t.Fatalf("functional fragmented UDP plan=%+v", functional.Entries[0])
	}
	transport := BuildPlan(tr, ProfileTransport, nil)
	if transport.Entries[0].Mode != ModeWire || transport.Entries[0].Fidelity != FidelityWire {
		t.Fatalf("transport fragmented UDP plan=%+v", transport.Entries[0])
	}
}

func TestIncompleteIPv6FragmentsRemainRaw(t *testing.T) {
	full := udp(1200, 53, []byte("incomplete-payload"))
	recs := []*pcapio.Record{{Time: time.Unix(400, 0), Data: ipv6Fragment(9, 0, true, full[:16]), LinkType: wire.LinkEthernet}}
	tr := ExtractTrace(recs, ExtractOptions{})
	if len(tr.Sessions) != 0 || len(tr.Raw) != 1 {
		t.Fatalf("incomplete fragments: sessions=%d raw=%d", len(tr.Sessions), len(tr.Raw))
	}
	if err := BuildPlan(tr, ProfileFunctional, nil).ValidateCoverage(); err != nil {
		t.Fatal(err)
	}
}

func TestTruncatedFramesAreBlockedPerLane(t *testing.T) {
	frame := []byte{1, 2, 3}
	rec := &pcapio.Record{Data: frame, CapLen: len(frame), OrigLen: 100, LinkType: wire.LinkEthernet}
	plan := BuildPlan(ExtractTrace([]*pcapio.Record{rec}, ExtractOptions{}), ProfileWire, nil)
	if len(plan.Entries) != 1 || plan.Entries[0].Mode != ModeBlocked || plan.Entries[0].Fidelity != FidelityBlocked {
		t.Fatalf("truncated plan=%+v", plan)
	}
}

func TestUnsolicitedUDPOneSidedPlanIsExplicitWire(t *testing.T) {
	session := &Session{ID: "udp-0", Transport: TransportUDP, Events: []Event{{PacketIndex: 0, Direction: ServerToClient}}}
	trace := &Trace{Packets: 1, Sessions: []*Session{session}}
	plan := BuildPlan(trace, ProfileFunctional, NewRegistry(fourByteAdapter{}))
	if err := plan.ValidateCoverage(); err != nil {
		t.Fatal(err)
	}
	entry := plan.Entries[0]
	if entry.Mode != ModeWire || entry.Fidelity != FidelityWire || entry.Driver != "frame-injector" {
		t.Fatalf("receive-only UDP must not select a request/response or semantic driver: %+v", entry)
	}
	if len(entry.Warnings) == 0 || !strings.Contains(entry.Warnings[len(entry.Warnings)-1], "receive-only UDP") {
		t.Fatalf("wire limitation was not explicit: %+v", entry.Warnings)
	}
}
