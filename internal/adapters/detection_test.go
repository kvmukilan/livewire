package adapters

import (
	"net/netip"
	"testing"

	"github.com/kvmukilan/livewire/internal/replay"
)

func TestMQTTDetectionRequiresTCPAndValidFixedHeader(t *testing.T) {
	for _, tc := range []struct {
		name      string
		transport replay.Transport
		raw       []byte
		want      bool
	}{
		{"generic UDP", replay.TransportUDP, []byte("udp-lab-request"), false},
		{"ICMP echo", replay.TransportICMP4, []byte("packet-lab-echo"), false},
		{"generic TCP", replay.TransportTCP, []byte("STATEFUL REQUEST\n"), false},
		{"CONNECT", replay.TransportTCP, mqttConnect("test"), true},
		{"midstream PUBLISH", replay.TransportTCP, mqttQoS1Publish("a", 7, "value"), true},
		{"midstream PUBACK", replay.TransportTCP, []byte{0x40, 2, 0, 7}, true},
		{"truncated PUBACK", replay.TransportTCP, []byte{0x40, 2, 0}, false},
		{"bad PUBACK flags", replay.TransportTCP, []byte{0x43, 2, 0, 7}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := replay.Session{Transport: tc.transport, Events: []replay.Event{{Direction: replay.ClientToServer, Payload: tc.raw}}}
			if got := (MQTT{}).Detect(s) > 0; got != tc.want {
				t.Fatalf("detected=%v want=%v", got, tc.want)
			}
		})
	}
	s := replay.Session{Transport: replay.TransportTCP, Server: replay.Endpoint{Port: 1883}, Events: []replay.Event{{Direction: replay.ClientToServer, Payload: []byte("STATEFUL REQUEST\n")}}}
	if (MQTT{}).Detect(s) != 0 {
		t.Fatal("MQTT port hint overrode invalid packet bytes")
	}
	connect := mqttConnect("split")
	s.Events = []replay.Event{{Direction: replay.ClientToServer, Payload: connect[:3]}, {Direction: replay.ClientToServer, Payload: connect[3:]}}
	if (MQTT{}).Detect(s) == 0 {
		t.Fatal("segmented MQTT CONNECT was not recognized")
	}
}

func TestTCPOnlyAdaptersDoNotClaimUDPOrICMPPortHints(t *testing.T) {
	for _, tc := range []struct {
		adapter replay.Adapter
		port    uint16
		payload []byte
	}{
		{HTTP{}, 80, []byte("GET / HTTP/1.1\r\n\r\n")},
		{MQTT{}, 1883, mqttConnect("test")},
		{Modbus{}, 502, []byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1}},
		{FTP{}, 21, []byte("USER test\r\n")},
		{TLS{}, 443, []byte{0x16, 3, 3, 0, 4, 1, 0, 0, 0}},
		{SSH{}, 22, []byte("SSH-2.0-test\r\n")},
	} {
		for _, transport := range []replay.Transport{replay.TransportUDP, replay.TransportICMP4} {
			s := replay.Session{Transport: transport, Server: replay.Endpoint{IP: netip.MustParseAddr("127.0.0.1"), Port: tc.port}, Events: []replay.Event{{Payload: tc.payload}}}
			if got := tc.adapter.Detect(s); got != 0 {
				t.Fatalf("%s claimed %s with confidence %d", tc.adapter.Name(), transport, got)
			}
		}
	}
}

func TestGenericPayloadsKeepTheirStatefulTransportPlan(t *testing.T) {
	for _, transport := range []replay.Transport{replay.TransportTCP, replay.TransportUDP, replay.TransportICMP4} {
		s := &replay.Session{ID: "generic", Transport: transport, Server: replay.Endpoint{IP: netip.MustParseAddr("127.0.0.1"), Port: 19000}, Events: []replay.Event{{Direction: replay.ClientToServer, Payload: []byte("STATEFUL REQUEST\n")}}}
		plan := replay.BuildPlan(&replay.Trace{Sessions: []*replay.Session{s}}, replay.ProfileFunctional, DefaultRegistry())
		if len(plan.Entries) != 1 || plan.Entries[0].Mode != replay.ModeStateful || plan.Entries[0].Adapter != "" {
			t.Fatalf("%s incorrectly routed: %+v", transport, plan.Entries)
		}
	}
}
