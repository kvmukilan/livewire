package replay

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

type responseBackend struct {
	sent      []byte
	response  []byte
	delivered bool
}

func (r *responseBackend) Send(b []byte) error { r.sent = append([]byte(nil), b...); return nil }
func (r *responseBackend) Recv(b []byte, _ time.Duration) (int, bool, error) {
	if r.delivered || len(r.response) == 0 {
		return 0, false, nil
	}
	r.delivered = true
	copy(b, r.response)
	return len(r.response), true, nil
}
func (r *responseBackend) Now() time.Time             { return time.Now() }
func (r *responseBackend) LinkType() wire.LinkType    { return wire.LinkEthernet }
func (r *responseBackend) Caps() backend.Capabilities { return backend.CanReceive | backend.Layer2 }
func (r *responseBackend) Close() error               { return nil }

func TestRunUDPWithBackend(t *testing.T) {
	capClient := netip.MustParseAddr("192.0.2.10")
	capServer := netip.MustParseAddr("192.0.2.20")
	liveClient := netip.MustParseAddr("10.0.0.10")
	liveServer := netip.MustParseAddr("10.0.0.20")
	base := time.Now()
	req := ipv4Frame(wire.ProtoUDP, capClient.As4(), capServer.As4(), udp(50000, 53, []byte("q")))
	resp := ipv4Frame(wire.ProtoUDP, capServer.As4(), capClient.As4(), udp(53, 50000, []byte("a")))
	tr := ExtractTrace(recordsAt(base, req, resp), ExtractOptions{})
	s := tr.Sessions[0]
	stub := &responseBackend{response: ipv4Frame(wire.ProtoUDP, liveServer.As4(), liveClient.As4(), udp(53, 50000, []byte("a")))}
	lb := &backend.LiveBackend{Backend: stub, LocalIP: liveClient}
	r, err := RunTransportWithBackendContext(context.Background(), TransportRunConfig{Session: s, TargetIP: liveServer, Profile: ProfileFunctional, Verify: VerifyStrict}, lb)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Completed || !r.Matched || r.Sent != 1 || r.Received != 1 {
		t.Fatalf("%+v", r)
	}
	p, _ := wire.Parse(stub.sent, wire.LinkEthernet)
	if p.SrcIP() != liveClient || p.DstIP() != liveServer {
		t.Fatalf("on wire %s -> %s", p.SrcIP(), p.DstIP())
	}
}

func TestRunUDPVerificationOffNeverClaimsMatch(t *testing.T) {
	client := netip.MustParseAddr("192.0.2.10")
	server := netip.MustParseAddr("192.0.2.20")
	liveClient := netip.MustParseAddr("198.51.100.10")
	liveServer := netip.MustParseAddr("198.51.100.20")
	req := ipv4Frame(wire.ProtoUDP, client.As4(), server.As4(), udp(40000, 53, []byte("q")))
	resp := ipv4Frame(wire.ProtoUDP, server.As4(), client.As4(), udp(53, 40000, []byte("a")))
	session := ExtractTrace(recordsAt(time.Now(), req, resp), ExtractOptions{}).Sessions[0]
	stub := &responseBackend{response: ipv4Frame(wire.ProtoUDP, liveServer.As4(), liveClient.As4(), udp(53, 40000, []byte("a")))}
	result, err := RunTransportWithBackendContext(context.Background(), TransportRunConfig{
		Session: session, TargetIP: liveServer, Profile: ProfileFunctional, Verify: VerifyOff,
	}, &backend.LiveBackend{Backend: stub, LocalIP: liveClient})
	if err != nil || !result.Completed || result.Verified || result.Matched {
		t.Fatalf("unverified UDP result overclaimed fidelity: result=%+v err=%v", result, err)
	}
}

func TestRunUDPWithBackendCancellation(t *testing.T) {
	client := netip.MustParseAddr("192.0.2.10")
	server := netip.MustParseAddr("192.0.2.20")
	req := udp(1000, 2000, []byte("request"))
	resp := udp(2000, 1000, []byte("response"))
	s := &Session{ID: "udp-0", Transport: TransportUDP, Client: Endpoint{IP: client, Port: 1000}, Server: Endpoint{IP: server, Port: 2000}, Events: []Event{
		{PacketIndex: 0, Direction: ClientToServer, Record: &pcapio.Record{Data: ipv4Frame(wire.ProtoUDP, client.As4(), server.As4(), req), LinkType: wire.LinkEthernet}},
		{PacketIndex: 1, Direction: ServerToClient, Record: &pcapio.Record{Data: ipv4Frame(wire.ProtoUDP, server.As4(), client.As4(), resp), LinkType: wire.LinkEthernet}},
	}}
	b := &responseBackend{}
	lb := &backend.LiveBackend{Backend: b, LocalIP: netip.MustParseAddr("198.51.100.10")}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := RunTransportWithBackendContext(ctx, TransportRunConfig{Session: s, TargetIP: netip.MustParseAddr("198.51.100.20"), Timeout: time.Second}, lb); err == nil {
		t.Fatal("expected cancellation")
	}
	if time.Since(start) > 250*time.Millisecond {
		t.Fatal("receive cancellation was not prompt")
	}
}

func TestICMPVerificationMatchesIdentifierAndSequence(t *testing.T) {
	server := [4]byte{192, 0, 2, 20}
	client := [4]byte{192, 0, 2, 10}
	expectedFrame := ipv4Frame(wire.ProtoICMPv4, server, client, icmp(0, 77, 4, []byte("payload")))
	actualFrame := ipv4Frame(wire.ProtoICMPv4, server, client, icmp(0, 77, 5, []byte("payload")))
	event := Event{Record: &pcapio.Record{Data: expectedFrame, LinkType: wire.LinkEthernet}}
	diffs := compareFramePayload(event, actualFrame, nil, &RuntimeState{}, VerifyStrict)
	if len(diffs) != 1 || diffs[0].Field != "icmp.sequence" {
		t.Fatalf("wrong-sequence differences=%+v", diffs)
	}
}

func TestRunICMPEchoWithBackend(t *testing.T) {
	capClient := netip.MustParseAddr("192.0.2.10")
	capServer := netip.MustParseAddr("192.0.2.20")
	liveClient := netip.MustParseAddr("10.0.0.10")
	liveServer := netip.MustParseAddr("10.0.0.20")
	request := ipv4Frame(wire.ProtoICMPv4, capClient.As4(), capServer.As4(), icmp(8, 91, 3, []byte("echo")))
	response := ipv4Frame(wire.ProtoICMPv4, capServer.As4(), capClient.As4(), icmp(0, 91, 3, []byte("echo")))
	trace := ExtractTrace(recordsAt(time.Now(), request, response), ExtractOptions{})
	if len(trace.Sessions) != 1 {
		t.Fatalf("sessions=%d", len(trace.Sessions))
	}
	liveResponse := ipv4Frame(wire.ProtoICMPv4, liveServer.As4(), liveClient.As4(), icmp(0, 91, 3, []byte("echo")))
	stub := &responseBackend{response: liveResponse}
	result, err := RunTransportWithBackendContext(context.Background(), TransportRunConfig{
		Session: trace.Sessions[0], TargetIP: liveServer, Profile: ProfileFunctional, Verify: VerifyStrict,
	}, &backend.LiveBackend{Backend: stub, LocalIP: liveClient})
	if err != nil || !result.Completed || !result.Matched || result.Sent != 1 || result.Received != 1 {
		t.Fatalf("ICMP result=%+v err=%v", result, err)
	}
}

func recordsAt(base time.Time, frames ...[]byte) []*pcapio.Record {
	out := make([]*pcapio.Record, len(frames))
	for i, f := range frames {
		out[i] = &pcapio.Record{Time: base.Add(time.Duration(i) * time.Millisecond), Data: f, LinkType: wire.LinkEthernet}
	}
	return out
}
