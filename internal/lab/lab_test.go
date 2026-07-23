package lab

import (
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/ipreasm"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/units"
	"github.com/kvmukilan/livewire/internal/wire"
)

func reverseUDPFrame(frame []byte) []byte {
	p, _ := wire.Parse(append([]byte(nil), frame...), wire.LinkEthernet)
	src, dst, sport, dport := p.SrcIP(), p.DstIP(), p.SrcPort(), p.DstPort()
	p.SetSrcIP(dst)
	p.SetDstIP(src)
	p.SetSrcPort(dport)
	p.SetDstPort(sport)
	p.RecalcChecksums()
	return p.Buf
}

func labUDP(payload int, df bool) []byte {
	data := make([]byte, payload)
	for i := range data {
		data[i] = byte(i)
	}
	u := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(u[0:2], 1200)
	binary.BigEndian.PutUint16(u[2:4], 5300)
	binary.BigEndian.PutUint16(u[4:6], uint16(len(u)))
	copy(u[8:], data)
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 64, wire.ProtoUDP
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(u)))
	if df {
		binary.BigEndian.PutUint16(ip[6:8], 0x4000)
	}
	src, dst := netip.MustParseAddr("192.0.2.1").As4(), netip.MustParseAddr("192.0.2.2").As4()
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	f := append(append(eth, ip...), u...)
	p, _ := wire.Parse(f, wire.LinkEthernet)
	p.RecalcChecksums()
	return f
}

func labTrace(frames ...[]byte) *replay.Trace {
	t := &replay.Trace{Packets: len(frames), Started: time.Unix(0, 0)}
	s := &replay.Session{ID: "udp-0", Transport: replay.TransportUDP, Client: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.1"), Port: 1200}, Server: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.2"), Port: 5300}}
	for i, f := range frames {
		s.Events = append(s.Events, replay.Event{PacketIndex: i, At: time.Duration(i) * time.Millisecond, Direction: replay.ClientToServer, Record: &pcapio.Record{Data: f, LinkType: wire.LinkEthernet}})
	}
	t.Sessions = []*replay.Session{s}
	return t
}

func TestTopologyValidationAndMapping(t *testing.T) {
	top := Topology{Version: 1, Client: Side{Interface: "left", MTU: 1500}, Server: Side{Interface: "right", VLAN: 7}, Mappings: []EndpointMapping{
		{Role: "client", Captured: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.1")}, Live: replay.Endpoint{IP: netip.MustParseAddr("10.0.0.1")}},
		{Role: "server", Captured: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.2")}, Live: replay.Endpoint{IP: netip.MustParseAddr("10.0.1.2")}},
	}}
	if err := top.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := top.ValidateTrace(labTrace(labUDP(8, false))); err != nil {
		t.Fatal(err)
	}
	mapped, ok := top.Map("server", replay.Endpoint{IP: netip.MustParseAddr("192.0.2.2"), Port: 5300})
	if !ok || mapped.Port != 5300 || mapped.IP != netip.MustParseAddr("10.0.1.2") {
		t.Fatalf("mapping=%+v ok=%v", mapped, ok)
	}
}

func TestTopologyRejectsAmbiguousMappingsAndGatewayFamily(t *testing.T) {
	base := Topology{Version: 1, Client: Side{Interface: "left"}, Server: Side{Interface: "right"}, Mappings: []EndpointMapping{
		{Role: "client", Captured: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.1")}, Live: replay.Endpoint{IP: netip.MustParseAddr("10.0.0.1")}},
		{Role: "server", Captured: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.2")}, Live: replay.Endpoint{IP: netip.MustParseAddr("10.0.1.2")}},
	}}
	ambiguous := base
	ambiguous.Mappings = append(append([]EndpointMapping(nil), base.Mappings...), EndpointMapping{
		Role: "client", Captured: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.1"), Port: 1234}, Live: replay.Endpoint{IP: netip.MustParseAddr("10.0.0.3"), Port: 1234},
	})
	if err := ambiguous.Validate(); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("ambiguous topology error=%v", err)
	}
	wrongGateway := base
	wrongGateway.Client.Gateway = netip.MustParseAddr("2001:db8::1")
	if err := wrongGateway.Validate(); err == nil || !strings.Contains(err.Error(), "different address families") {
		t.Fatalf("gateway family error=%v", err)
	}
}

func TestCompileScheduleDeterministicFaults(t *testing.T) {
	s := Scenario{Version: 1, Seed: 42, Rules: []ScenarioRule{{
		Match:  ScenarioMatch{Session: "udp-0"},
		Action: ScenarioAction{Delay: Duration{5 * time.Millisecond}, Duplicate: 1, Reorder: 2},
	}}}
	trace := labTrace(labUDP(8, false), labUDP(8, false))
	a, ar, err := CompileSchedule(trace, s)
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := CompileSchedule(trace, s)
	if len(a) != 4 || ar.Duplicated != 2 || a[0].PacketIndex != b[0].PacketIndex || a[0].At != b[0].At {
		t.Fatalf("schedule not deterministic: len=%d report=%+v", len(a), ar)
	}
	if a[0].At < 5*time.Millisecond {
		t.Fatalf("delay not applied: %s", a[0].At)
	}
}

func TestRawLaneSideIsInferredBeforeDirectionFaults(t *testing.T) {
	topology := Topology{Version: 1, Client: Side{Interface: "left"}, Server: Side{Interface: "right"}, Mappings: []EndpointMapping{
		{Role: "client", Captured: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.1")}, Live: replay.Endpoint{IP: netip.MustParseAddr("10.0.0.1")}},
		{Role: "server", Captured: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.2")}, Live: replay.Endpoint{IP: netip.MustParseAddr("10.0.1.2")}},
	}}
	frame := reverseUDPFrame(labUDP(8, false))
	frame[14+9] = 99 // unknown L4 protocol keeps the event in the raw lane
	frame[14+10], frame[14+11] = 0, 0
	binary.BigEndian.PutUint16(frame[14+10:14+12], checksum16(frame[14:34]))
	trace := &replay.Trace{Packets: 1, Raw: []replay.Event{{PacketIndex: 0, Record: &pcapio.Record{Data: frame, LinkType: wire.LinkEthernet}}}}
	scenario := Scenario{Version: 1, Seed: 1, Rules: []ScenarioRule{{
		Match: ScenarioMatch{Direction: replay.ServerToClient.String()}, Action: ScenarioAction{Delay: Duration{7 * time.Millisecond}},
	}}}
	schedule, report, err := CompileSchedule(trace, scenario, topology)
	if err != nil {
		t.Fatal(err)
	}
	if len(schedule) != 1 || schedule[0].Side != "server" || schedule[0].Direction != replay.ServerToClient || schedule[0].At != 7*time.Millisecond {
		t.Fatalf("raw schedule=%+v", schedule)
	}
	if len(report.Limitations) != 0 {
		t.Fatalf("unexpected raw-side limitations=%v", report.Limitations)
	}
}

func TestIPv4MTUFragmentationReassembles(t *testing.T) {
	frame := labUDP(1200, false)
	frames, limitation := fragmentForMTU(frame, wire.LinkEthernet, 600, 1)
	if limitation != "" || len(frames) < 2 {
		t.Fatalf("fragments=%d limitation=%q", len(frames), limitation)
	}
	rebuilt, dropped, err := ipreasm.ReassembleAll(frames, wire.LinkEthernet)
	if err != nil || dropped != 0 || len(rebuilt) != 1 {
		t.Fatalf("reassemble: out=%d dropped=%d err=%v", len(rebuilt), dropped, err)
	}
	p, _ := wire.Parse(rebuilt[0], wire.LinkEthernet)
	if p.PayloadLen() != 1200 {
		t.Fatalf("payload=%d", p.PayloadLen())
	}
}

func TestScenarioRejectsInvalidProbability(t *testing.T) {
	s := Scenario{Version: 1, Rules: []ScenarioRule{{Action: ScenarioAction{Drop: 2}}}}
	if err := s.Validate(); err == nil {
		t.Fatal("invalid drop should fail")
	}
}

func labTopology() Topology {
	return Topology{Version: 1, Client: Side{Interface: "left"}, Server: Side{Interface: "right"}, Mappings: []EndpointMapping{
		{Role: "client", Captured: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.1")}, Live: replay.Endpoint{IP: netip.MustParseAddr("10.0.0.1")}},
		{Role: "server", Captured: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.2")}, Live: replay.Endpoint{IP: netip.MustParseAddr("10.0.1.2")}},
	}}
}

func twoWayUDPTrace() *replay.Trace {
	req := labUDP(16, false)
	resp := reverseUDPFrame(req)
	t := labTrace(req, resp)
	t.Sessions[0].Events[1].Direction = replay.ServerToClient
	t.Sessions[0].Events[1].At = 30 * time.Millisecond
	return t
}

func TestDUTPassThroughEndToEnd(t *testing.T) {
	sim, err := NewDUTSimulator(SimulatorConfig{Mode: "pass"})
	if err != nil {
		t.Fatal(err)
	}
	backs := sim.Backends()
	res, err := RunWithBackendsContext(context.Background(), Config{
		Trace: twoWayUDPTrace(), Topology: labTopology(), Scenario: Scenario{Version: 1, Seed: 1}, Drain: 30 * time.Millisecond,
	}, backs)
	if err != nil {
		t.Fatal(err)
	}
	if res.Metrics.Injected != 2 || res.Metrics.Crossed != 2 || res.Metrics.Lost != 0 {
		t.Fatalf("metrics=%+v", res.Metrics)
	}
	if len(res.Evidence) < 4 {
		t.Fatalf("evidence=%d", len(res.Evidence))
	}
}

func TestDUTNATPATLearning(t *testing.T) {
	sim, err := NewDUTSimulator(SimulatorConfig{Mode: "nat", NATClientIP: netip.MustParseAddr("198.51.100.9"), NATClientPort: 45000})
	if err != nil {
		t.Fatal(err)
	}
	res, err := RunWithBackendsContext(context.Background(), Config{
		Trace: twoWayUDPTrace(), Topology: labTopology(), Scenario: Scenario{Version: 1, Seed: 1}, Drain: 30 * time.Millisecond,
	}, sim.Backends())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.NAT) != 1 || res.Metrics.Crossed != 2 {
		t.Fatalf("NAT=%+v metrics=%+v", res.NAT, res.Metrics)
	}
	if !strings.Contains(res.NAT[0].After, "198.51.100.9:45000") {
		t.Fatalf("unexpected NAT observation: %+v", res.NAT[0])
	}
	path := filepath.Join(t.TempDir(), "evidence.pcapng")
	if err := WriteEvidence(path, res, labTopology()); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rd, err := pcapio.NewNgReader(f)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uint32]bool{}
	for {
		rec, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		seen[rec.InterfaceID] = true
	}
	if !seen[0] || !seen[1] {
		t.Fatalf("evidence missing interface: %v", seen)
	}
}

func TestTwoSidedActorWaitsForDUTCrossing(t *testing.T) {
	sim, err := NewDUTSimulator(SimulatorConfig{Mode: "pass", Delay: 45 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	trace := twoWayUDPTrace()
	trace.Sessions[0].Events[1].At = 2 * time.Millisecond
	var serverInjectedAt time.Duration
	res, err := RunWithBackendsContext(context.Background(), Config{
		Trace: trace, Topology: labTopology(), Scenario: Scenario{Version: 1, Seed: 1},
		Profile: replay.ProfileTiming, Drain: 60 * time.Millisecond, ActorTimeout: 200 * time.Millisecond,
		Progress: func(p Progress) {
			if p.Stage == "inject" && strings.Contains(p.Message, "server side") {
				serverInjectedAt = p.At
			}
		},
	}, sim.Backends())
	if err != nil {
		t.Fatal(err)
	}
	if serverInjectedAt < 35*time.Millisecond || res.Metrics.Crossed != 2 {
		t.Fatalf("server actor did not wait for DUT crossing: injectedAt=%s metrics=%+v", serverInjectedAt, res.Metrics)
	}
}

func TestTwoSidedActorSuppressesResponseAfterDUTDrop(t *testing.T) {
	sim, err := NewDUTSimulator(SimulatorConfig{Mode: "pass", DropEvery: 1})
	if err != nil {
		t.Fatal(err)
	}
	res, err := RunWithBackendsContext(context.Background(), Config{
		Trace: twoWayUDPTrace(), Topology: labTopology(), Scenario: Scenario{Version: 1, Seed: 1},
		Profile: replay.ProfileTiming, Drain: 10 * time.Millisecond, ActorTimeout: 25 * time.Millisecond,
	}, sim.Backends())
	if err != nil {
		t.Fatal(err)
	}
	if res.Metrics.Injected != 1 || res.Metrics.FirewallTimeouts != 1 || len(res.Limitations) < 2 {
		t.Fatalf("dropped request should suppress captured response: metrics=%+v limitations=%v", res.Metrics, res.Limitations)
	}
	if len(res.Sessions) != 1 || res.Sessions[0].Timeouts != 1 || res.Sessions[0].Lost != 1 || res.Sessions[0].Completed || len(res.Sessions[0].Evidence) != 1 {
		t.Fatalf("per-session drop evidence=%+v", res.Sessions)
	}

	wireSim, _ := NewDUTSimulator(SimulatorConfig{Mode: "pass", DropEvery: 1})
	wireResult, err := RunWithBackendsContext(context.Background(), Config{
		Trace: twoWayUDPTrace(), Topology: labTopology(), Scenario: Scenario{Version: 1, Seed: 1},
		Profile: replay.ProfileWire, Drain: 10 * time.Millisecond, ActorTimeout: 25 * time.Millisecond,
	}, wireSim.Backends())
	if err != nil {
		t.Fatal(err)
	}
	if wireResult.Metrics.Injected != 2 || wireResult.Metrics.FirewallTimeouts != 0 {
		t.Fatalf("wire mode must preserve unconditional captured timing: %+v", wireResult.Metrics)
	}
}

func TestScenarioDroppedRequestSuppressesResponseActor(t *testing.T) {
	zero := 0
	sim, _ := NewDUTSimulator(SimulatorConfig{Mode: "pass"})
	res, err := RunWithBackendsContext(context.Background(), Config{
		Trace: twoWayUDPTrace(), Topology: labTopology(), Profile: replay.ProfileTiming,
		Scenario: Scenario{Version: 1, Seed: 1, Rules: []ScenarioRule{{
			Match: ScenarioMatch{PacketIndexMin: &zero, PacketIndexMax: &zero}, Action: ScenarioAction{Drop: 1},
		}}}, Drain: 10 * time.Millisecond, ActorTimeout: 25 * time.Millisecond,
	}, sim.Backends())
	if err != nil {
		t.Fatal(err)
	}
	if res.Metrics.Injected != 0 || res.Schedule.DroppedFrames != 1 || res.Metrics.FirewallTimeouts != 1 {
		t.Fatalf("scenario dependency result: schedule=%+v metrics=%+v limitations=%v", res.Schedule, res.Metrics, res.Limitations)
	}
}

func TestTopologyMTUAppliesDuringLabRun(t *testing.T) {
	sim, err := NewDUTSimulator(SimulatorConfig{Mode: "pass"})
	if err != nil {
		t.Fatal(err)
	}
	topology := labTopology()
	topology.Client.MTU = 600
	res, err := RunWithBackendsContext(context.Background(), Config{
		Trace: labTrace(labUDP(1200, false)), Topology: topology,
		Scenario: Scenario{Version: 1, Seed: 1}, Drain: 30 * time.Millisecond,
	}, sim.Backends())
	if err != nil {
		t.Fatal(err)
	}
	if res.Metrics.Injected < 2 || res.Schedule.Fragmented == 0 || res.Metrics.Crossed != res.Metrics.Injected {
		t.Fatalf("topology MTU was not reflected in run: schedule=%+v metrics=%+v", res.Schedule, res.Metrics)
	}
}

func TestTCPProxyCrossingIgnoresTranslatedSequenceClock(t *testing.T) {
	request := labTCP(wire.FlagSYN, 10)
	trace := &replay.Trace{Packets: 1, Started: time.Unix(0, 0), Sessions: []*replay.Session{{
		ID: "tcp-0", Transport: replay.TransportTCP,
		Client: replay.Endpoint{IP: netip.MustParseAddr("10.0.0.1"), Port: 1200},
		Server: replay.Endpoint{IP: netip.MustParseAddr("10.0.1.2"), Port: 80},
		Events: []replay.Event{{PacketIndex: 0, Direction: replay.ClientToServer, Record: &pcapio.Record{Data: request, LinkType: wire.LinkEthernet}}},
	}}}
	sim, err := NewDUTSimulator(SimulatorConfig{Mode: "proxy", ProxyIP: netip.MustParseAddr("10.0.9.9"), ProxySeqDelta: 100})
	if err != nil {
		t.Fatal(err)
	}
	res, err := RunWithBackendsContext(context.Background(), Config{
		Trace: trace, Topology: Topology{Version: 1, Client: Side{Interface: "left"}, Server: Side{Interface: "right"}, Mappings: []EndpointMapping{
			{Role: "client", Captured: replay.Endpoint{IP: netip.MustParseAddr("10.0.0.1")}, Live: replay.Endpoint{IP: netip.MustParseAddr("10.0.0.1")}},
			{Role: "server", Captured: replay.Endpoint{IP: netip.MustParseAddr("10.0.1.2")}, Live: replay.Endpoint{IP: netip.MustParseAddr("10.0.1.2")}},
		}}, Scenario: Scenario{Version: 1, Seed: 1}, Drain: 30 * time.Millisecond,
	}, sim.Backends())
	if err != nil {
		t.Fatal(err)
	}
	if res.Metrics.Crossed != 1 || len(res.NAT) != 1 {
		t.Fatalf("proxy crossing was not correlated: metrics=%+v NAT=%+v", res.Metrics, res.NAT)
	}
}

func labTCP(flags uint8, seq uint32) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 1200)
	binary.BigEndian.PutUint16(tcp[2:4], 80)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12], tcp[13] = 0x50, flags
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 64, wire.ProtoTCP
	binary.BigEndian.PutUint16(ip[2:4], 40)
	src, dst := netip.MustParseAddr("10.0.0.1").As4(), netip.MustParseAddr("10.0.1.2").As4()
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	f := append(append(eth, ip...), tcp...)
	p, _ := wire.Parse(f, wire.LinkEthernet)
	p.RecalcChecksums()
	return p.Buf
}

func labTCPReverse(frame []byte, flags uint8, seq, ack uint32) []byte {
	p, _ := wire.Parse(append([]byte(nil), frame...), wire.LinkEthernet)
	src, dst, sourcePort, destinationPort := p.SrcIP(), p.DstIP(), p.SrcPort(), p.DstPort()
	p.SetSrcIP(dst)
	p.SetDstIP(src)
	p.SetSrcPort(destinationPort)
	p.SetDstPort(sourcePort)
	p.SetSeq(units.Seq(seq))
	p.SetAck(units.Ack(ack))
	p.SetFlags(flags)
	p.RecalcChecksums()
	return p.Buf
}

func twoWayTCPTrace() *replay.Trace {
	syn := labTCP(wire.FlagSYN, 100)
	synAck := labTCPReverse(syn, wire.FlagSYN|wire.FlagACK, 500, 101)
	ack := labTCP(wire.FlagACK, 101)
	p, _ := wire.Parse(ack, wire.LinkEthernet)
	p.SetAck(units.Ack(501))
	p.RecalcChecksums()
	return &replay.Trace{Packets: 3, Started: time.Unix(0, 0), Sessions: []*replay.Session{{
		ID: "tcp-0", Transport: replay.TransportTCP,
		Client: replay.Endpoint{IP: netip.MustParseAddr("10.0.0.1"), Port: 1200},
		Server: replay.Endpoint{IP: netip.MustParseAddr("10.0.1.2"), Port: 80},
		Events: []replay.Event{
			{PacketIndex: 0, At: 0, Direction: replay.ClientToServer, Record: &pcapio.Record{Data: syn, LinkType: wire.LinkEthernet}},
			{PacketIndex: 1, At: time.Millisecond, Direction: replay.ServerToClient, Record: &pcapio.Record{Data: synAck, LinkType: wire.LinkEthernet}},
			{PacketIndex: 2, At: 2 * time.Millisecond, Direction: replay.ClientToServer, Record: &pcapio.Record{Data: p.Buf, LinkType: wire.LinkEthernet}},
		},
	}}}
}

func tcpLabTopology() Topology {
	return Topology{Version: 1, Client: Side{Interface: "left"}, Server: Side{Interface: "right"}, Mappings: []EndpointMapping{
		{Role: "client", Captured: replay.Endpoint{IP: netip.MustParseAddr("10.0.0.1")}, Live: replay.Endpoint{IP: netip.MustParseAddr("10.0.0.1")}},
		{Role: "server", Captured: replay.Endpoint{IP: netip.MustParseAddr("10.0.1.2")}, Live: replay.Endpoint{IP: netip.MustParseAddr("10.0.1.2")}},
	}}
}

func TestTwoSidedTCPPassThroughAndNAT(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  SimulatorConfig
		nat  bool
	}{
		{name: "pass", cfg: SimulatorConfig{Mode: "pass"}},
		{name: "nat-pat", cfg: SimulatorConfig{Mode: "nat", NATClientIP: netip.MustParseAddr("198.51.100.9"), NATClientPort: 45000}, nat: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sim, err := NewDUTSimulator(tc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			result, err := RunWithBackendsContext(context.Background(), Config{
				Trace: twoWayTCPTrace(), Topology: tcpLabTopology(), Scenario: Scenario{Version: 1, Seed: 1},
				Profile: replay.ProfileTransport, Drain: 30 * time.Millisecond, ActorTimeout: 100 * time.Millisecond,
			}, sim.Backends())
			if err != nil {
				t.Fatal(err)
			}
			if result.Metrics.Injected != 3 || result.Metrics.Crossed != 3 || result.Metrics.FirewallTimeouts != 0 {
				t.Fatalf("TCP metrics=%+v limitations=%v", result.Metrics, result.Limitations)
			}
			if result.AchievedFidelity != replay.FidelityTransport || len(result.Sessions) != 1 || result.Sessions[0].Driver != "tcp-dual-actor" || !result.Sessions[0].Completed {
				t.Fatalf("TCP fidelity=%s sessions=%+v", result.AchievedFidelity, result.Sessions)
			}
			if len(result.Sessions[0].Evidence) != 3 || result.Sessions[0].OneWay == nil || result.Sessions[0].RTT == nil {
				t.Fatalf("TCP per-session evidence=%+v", result.Sessions[0])
			}
			if tc.nat && len(result.NAT) != 1 {
				t.Fatalf("expected NAT evidence: %+v", result.NAT)
			}
		})
	}
}

func TestTwoSidedTCPAdaptsAcknowledgementToProxyClock(t *testing.T) {
	sim, err := NewDUTSimulator(SimulatorConfig{Mode: "proxy", ProxyIP: netip.MustParseAddr("10.0.9.9"), ProxySeqDelta: 100})
	if err != nil {
		t.Fatal(err)
	}
	result, err := RunWithBackendsContext(context.Background(), Config{
		Trace: twoWayTCPTrace(), Topology: tcpLabTopology(), Scenario: Scenario{Version: 1, Seed: 1},
		Profile: replay.ProfileTransport, Drain: 30 * time.Millisecond, ActorTimeout: 100 * time.Millisecond,
	}, sim.Backends())
	if err != nil {
		t.Fatal(err)
	}
	if result.Metrics.Injected != 3 || result.Metrics.Crossed != 3 || result.Metrics.FirewallTimeouts != 0 {
		t.Fatalf("TCP proxy metrics=%+v limitations=%v", result.Metrics, result.Limitations)
	}
	if len(result.TCPClocks) != 1 || result.TCPClocks[0].SessionID != "tcp-0" || result.TCPClocks[0].Direction != replay.ClientToServer.String() || result.TCPClocks[0].Delta != 100 {
		t.Fatalf("TCP clock transformations=%+v", result.TCPClocks)
	}
	foundAdaptiveSYNACK := false
	for _, record := range result.Evidence {
		if record.InterfaceID != 1 {
			continue
		}
		packet, parseErr := wire.Parse(record.Data, record.LinkType)
		if parseErr == nil && packet.IsTCP() && packet.SrcIP() == netip.MustParseAddr("10.0.1.2") && packet.HasFlags(wire.FlagSYN|wire.FlagACK) {
			foundAdaptiveSYNACK = packet.AckNum().Uint32() == 201
		}
	}
	if !foundAdaptiveSYNACK {
		t.Fatal("server actor did not acknowledge the proxy-translated SYN sequence")
	}
}

func TestTwoSidedWireProfileDoesNotAdaptProxyClock(t *testing.T) {
	sim, err := NewDUTSimulator(SimulatorConfig{Mode: "proxy", ProxyIP: netip.MustParseAddr("10.0.9.9"), ProxySeqDelta: 100})
	if err != nil {
		t.Fatal(err)
	}
	trace := twoWayTCPTrace()
	plan := BuildReplayPlan(trace, replay.ProfileWire)
	result, err := RunWithBackendsContext(context.Background(), Config{
		Trace: trace, Plan: &plan, Topology: tcpLabTopology(), Scenario: Scenario{Version: 1, Seed: 1},
		Profile: replay.ProfileWire, Drain: 30 * time.Millisecond,
	}, sim.Backends())
	if err != nil {
		t.Fatal(err)
	}
	if result.AchievedFidelity != replay.FidelityWire || result.Sessions[0].Driver != "frame-injector" {
		t.Fatalf("wire result fidelity=%s sessions=%+v", result.AchievedFidelity, result.Sessions)
	}
	foundCapturedACK := false
	for _, record := range result.Evidence {
		if record.InterfaceID != 1 {
			continue
		}
		packet, parseErr := wire.Parse(record.Data, record.LinkType)
		if parseErr == nil && packet.IsTCP() && packet.SrcIP() == netip.MustParseAddr("10.0.1.2") && packet.HasFlags(wire.FlagSYN|wire.FlagACK) {
			foundCapturedACK = packet.AckNum().Uint32() == 101 && packet.DstIP() == netip.MustParseAddr("10.0.0.1")
		}
	}
	if !foundCapturedACK {
		t.Fatal("wire actor adapted the captured SYN-ACK instead of preserving its configured tuple and clock")
	}
}

func TestLabFidelityIsCappedByExplicitRawLane(t *testing.T) {
	trace := twoWayTCPTrace()
	trace.Raw = []replay.Event{{PacketIndex: trace.Packets}}
	trace.Packets++
	plan := BuildReplayPlan(trace, replay.ProfileTransport)
	evidence := &collector{
		injectedBySession: map[string]int{"tcp-0": 3, "raw-0": 1}, crossedBySession: map[string]int{"tcp-0": 3, "raw-0": 1},
		duplicatesBySession: map[string]int{}, timeoutsBySession: map[string]int{}, latenciesBySession: map[string][]time.Duration{},
		rttsBySession: map[string][]time.Duration{}, observedIdxBySession: map[string][]int{}, evidenceBySession: map[string]map[int]bool{},
	}
	verdicts := buildSessionVerdicts(trace, plan, evidence)
	if got := overallLabFidelity(replay.ProfileTransport, verdicts); got != replay.FidelityWire {
		t.Fatalf("overall fidelity=%s verdicts=%+v", got, verdicts)
	}
	if len(verdicts) != 2 || verdicts[1].SessionID != "tcp-0" || verdicts[0].SessionID != "raw-0" || verdicts[0].Achieved != replay.FidelityWire {
		t.Fatalf("verdicts=%+v", verdicts)
	}
}

func TestLabReplayPlanMatchesExecutedDrivers(t *testing.T) {
	trace := twoWayTCPTrace()
	trace.Sessions[0].Blockers = []string{"TLS requires a key log for one-sided semantic replay"}
	plan := BuildReplayPlan(trace, replay.ProfileFunctional)
	if err := plan.ValidateCoverage(); err != nil {
		t.Fatal(err)
	}
	if len(plan.Entries) != 1 || plan.Entries[0].Driver != "tcp-dual-actor" || plan.Entries[0].Mode != replay.ModeStateful || plan.Entries[0].Fidelity != replay.FidelityTransport {
		t.Fatalf("functional lab plan=%+v", plan.Entries)
	}
	if len(plan.Entries[0].Blockers) != 0 || !strings.Contains(strings.Join(plan.Entries[0].Warnings, " "), "does not prevent opaque") {
		t.Fatalf("opaque blocker handling=%+v", plan.Entries[0])
	}
	wirePlan := BuildReplayPlan(trace, replay.ProfileWire)
	if wirePlan.Entries[0].Driver != "frame-injector" || wirePlan.Entries[0].Fidelity != replay.FidelityWire {
		t.Fatalf("wire lab plan=%+v", wirePlan.Entries[0])
	}
}

func TestLabReplayPlanBlocksMissingTCPBytesOutsideWire(t *testing.T) {
	first := labTCPPayload(100, []byte("abcd"))
	second := labTCPPayload(105, []byte("f"))
	trace := &replay.Trace{Packets: 2, Sessions: []*replay.Session{{
		ID: "tcp-gap", Transport: replay.TransportTCP,
		Client: replay.Endpoint{IP: netip.MustParseAddr("10.0.0.1"), Port: 1200},
		Server: replay.Endpoint{IP: netip.MustParseAddr("10.0.1.2"), Port: 80},
		Events: []replay.Event{
			{PacketIndex: 0, Direction: replay.ClientToServer, Payload: []byte("abcd"), Record: &pcapio.Record{Data: first, CapLen: len(first), OrigLen: len(first), LinkType: wire.LinkEthernet}},
			{PacketIndex: 1, Direction: replay.ClientToServer, Payload: []byte("f"), Record: &pcapio.Record{Data: second, CapLen: len(second), OrigLen: len(second), LinkType: wire.LinkEthernet}},
		},
	}}}
	transportPlan := BuildReplayPlan(trace, replay.ProfileTransport)
	if transportPlan.Entries[0].Mode != replay.ModeBlocked || !strings.Contains(strings.Join(transportPlan.Entries[0].Blockers, " "), "missing 1 byte") {
		t.Fatalf("transport plan=%+v", transportPlan.Entries[0])
	}
	if wirePlan := BuildReplayPlan(trace, replay.ProfileWire); wirePlan.Entries[0].Mode != replay.ModeWire {
		t.Fatalf("wire plan=%+v", wirePlan.Entries[0])
	}
}

func labTCPPayload(seq uint32, payload []byte) []byte {
	frame := append(labTCP(wire.FlagACK, seq), payload...)
	binary.BigEndian.PutUint16(frame[14+2:14+4], uint16(len(frame)-14))
	packet, _ := wire.Parse(frame, wire.LinkEthernet)
	packet.RecalcChecksums()
	return packet.Buf
}

func recvSim(t *testing.T, b backend.PacketBackend, timeout time.Duration) ([]byte, bool) {
	t.Helper()
	buf := make([]byte, 65536)
	n, ok, err := b.Recv(buf, timeout)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buf[:n]...), ok
}

func TestDUTSimulatorImpairmentModes(t *testing.T) {
	t.Run("firewall reset", func(t *testing.T) {
		sim, _ := NewDUTSimulator(SimulatorConfig{Mode: "firewall"})
		b := sim.Backends()
		if err := b.ClientTX.Send(labTCP(wire.FlagSYN, 10)); err != nil {
			t.Fatal(err)
		}
		frame, ok := recvSim(t, b.ClientRX, 50*time.Millisecond)
		p, _ := wire.Parse(frame, wire.LinkEthernet)
		if !ok || !p.HasFlags(wire.FlagRST|wire.FlagACK) {
			t.Fatal("firewall did not synthesize a reset")
		}
	})

	t.Run("tcp proxy", func(t *testing.T) {
		sim, _ := NewDUTSimulator(SimulatorConfig{Mode: "proxy", ProxyIP: netip.MustParseAddr("10.0.9.9"), ProxySeqDelta: 100})
		b := sim.Backends()
		_ = b.ClientTX.Send(labTCP(wire.FlagSYN, 10))
		frame, ok := recvSim(t, b.ServerRX, 50*time.Millisecond)
		p, _ := wire.Parse(frame, wire.LinkEthernet)
		if !ok || p.SrcIP() != netip.MustParseAddr("10.0.9.9") || p.Seq().Uint32() != 110 {
			t.Fatalf("proxy output: ok=%v src=%s seq=%d", ok, p.SrcIP(), p.Seq().Uint32())
		}
	})

	t.Run("delay loss duplicate reorder mtu", func(t *testing.T) {
		delayed, _ := NewDUTSimulator(SimulatorConfig{Mode: "pass", Delay: 15 * time.Millisecond})
		b := delayed.Backends()
		start := time.Now()
		_ = b.ClientTX.Send(labUDP(8, false))
		_, ok := recvSim(t, b.ServerRX, 100*time.Millisecond)
		if !ok || time.Since(start) < 10*time.Millisecond {
			t.Fatal("delay was not applied")
		}

		lost, _ := NewDUTSimulator(SimulatorConfig{Mode: "pass", DropEvery: 1})
		lb := lost.Backends()
		_ = lb.ClientTX.Send(labUDP(8, false))
		if _, ok := recvSim(t, lb.ServerRX, 10*time.Millisecond); ok {
			t.Fatal("drop was not applied")
		}

		dup, _ := NewDUTSimulator(SimulatorConfig{Mode: "pass", Duplicate: 1})
		db := dup.Backends()
		_ = db.ClientTX.Send(labUDP(8, false))
		if _, ok := recvSim(t, db.ServerRX, 20*time.Millisecond); !ok {
			t.Fatal("first duplicate missing")
		}
		if _, ok := recvSim(t, db.ServerRX, 20*time.Millisecond); !ok {
			t.Fatal("second duplicate missing")
		}

		reorder, _ := NewDUTSimulator(SimulatorConfig{Mode: "pass", Reorder: 2})
		rb := reorder.Backends()
		f1, f2 := labUDP(8, false), labUDP(8, false)
		p2, _ := wire.Parse(f2, wire.LinkEthernet)
		p2.Payload()[0] = 99
		p2.RecalcChecksums()
		_ = rb.ClientTX.Send(f1)
		_ = rb.ClientTX.Send(f2)
		first, ok := recvSim(t, rb.ServerRX, 20*time.Millisecond)
		pf, _ := wire.Parse(first, wire.LinkEthernet)
		if !ok || pf.Payload()[0] != 99 {
			t.Fatal("bounded reorder did not reverse the pair")
		}

		mtu, _ := NewDUTSimulator(SimulatorConfig{Mode: "pass", MTU: 600})
		mb := mtu.Backends()
		_ = mb.ClientTX.Send(labUDP(1200, false))
		fragment, ok := recvSim(t, mb.ServerRX, 20*time.Millisecond)
		mp, _ := wire.Parse(fragment, wire.LinkEthernet)
		if !ok || !mp.IsFragment() {
			t.Fatal("MTU change did not fragment")
		}
	})
}
