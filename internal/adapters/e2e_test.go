package adapters

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
)

func tcpDNS(raw []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, uint16(len(raw)))
	return append(out, raw...)
}

func dnpFrame(dest, source uint16, appFunc byte) []byte {
	d := dissect.DNP3{
		Control: 0x44, Dest: dest, Source: source,
		HasTransport: true, TransportFIN: true, TransportFIR: true, TransportSeq: 1,
		HasApp: true, AppControl: 0xc1, AppFIN: true, AppFIR: true, AppSeq: 1, AppFunc: appFunc,
		UserData: []byte{0xc1, 0xc1, appFunc, 0, 0},
	}
	return d.Encode()
}

func TestBuiltInAdaptersCompleteControlledTCPTargets(t *testing.T) {
	dnsRequest := dnsQuery("device.example", 7)
	dnsResponse := append([]byte(nil), dnsRequest...)
	binary.BigEndian.PutUint16(dnsResponse[2:4], 0x8180)
	modbusRequest := []byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1}
	modbusResponse := []byte{0, 1, 0, 0, 0, 5, 1, 3, 2, 0, 42}
	cases := []struct {
		name     string
		adapter  replay.Adapter
		port     uint16
		request  []byte
		response []byte
	}{
		{"http", HTTP{}, 80, []byte("GET /health HTTP/1.1\r\nHost: device\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")},
		{"http-head", HTTP{}, 80, []byte("HEAD /health HTTP/1.1\r\nHost: device\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n")},
		{"dns-tcp", DNS{Transport: replay.TransportTCP}, 53, tcpDNS(dnsRequest), tcpDNS(dnsResponse)},
		{"mqtt", MQTT{}, 1883, mqttConnect("e2e"), []byte{0x20, 0x02, 0, 0}},
		{"modbus", Modbus{}, 502, modbusRequest, modbusResponse},
		{"dnp3", DNP3{}, 20000, dnpFrame(4, 1, 0x01), dnpFrame(1, 4, 0x81)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			dial := func(context.Context, string, string) (net.Conn, error) { return client, nil }
			go func() {
				defer server.Close()
				got := make([]byte, len(tc.request))
				_, _ = io.ReadFull(server, got)
				_, _ = server.Write(tc.response)
			}()
			session := &replay.Session{
				ID: "tcp-0", Transport: replay.TransportTCP,
				Client: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.10"), Port: 40000},
				Server: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.20"), Port: tc.port},
				Events: []replay.Event{
					{Direction: replay.ClientToServer, Record: &pcapio.Record{}, Payload: tc.request},
					{Direction: replay.ServerToClient, Record: &pcapio.Record{}, Payload: tc.response},
				},
			}
			res, err := replay.RunTCPSemanticContext(context.Background(), replay.TCPSemanticConfig{
				Session: session, TargetIP: netip.MustParseAddr("127.0.0.1"), TargetPort: tc.port,
				Adapter: tc.adapter, Verify: replay.VerifyStrict, Timeout: time.Second, Dial: dial,
			})
			if err != nil {
				t.Fatal(err)
			}
			if !res.Completed || !res.Verified || !res.Matched || res.Sent != 1 || res.Received != 1 {
				t.Fatalf("result=%+v", res)
			}
		})
	}
}

func TestMQTTQoS2FlowCompletesControlledTarget(t *testing.T) {
	publish := []byte{0x34, 6, 0, 1, 't', 0, 7, 'x'}
	pubrec := []byte{0x50, 2, 0, 7}
	pubrel := []byte{0x62, 2, 0, 7}
	pubcomp := []byte{0x70, 2, 0, 7}
	client, server := net.Pipe()
	dial := func(context.Context, string, string) (net.Conn, error) { return client, nil }
	go func() {
		defer server.Close()
		got := make([]byte, len(publish))
		_, _ = io.ReadFull(server, got)
		_, _ = server.Write(pubrec)
		got = make([]byte, len(pubrel))
		_, _ = io.ReadFull(server, got)
		_, _ = server.Write(pubcomp)
	}()
	session := &replay.Session{
		ID: "tcp-0", Transport: replay.TransportTCP,
		Client: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.10"), Port: 40000},
		Server: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.20"), Port: 1883},
		Events: []replay.Event{
			{Direction: replay.ClientToServer, Record: &pcapio.Record{}, Payload: publish},
			{Direction: replay.ServerToClient, Record: &pcapio.Record{}, Payload: pubrec},
			{Direction: replay.ClientToServer, Record: &pcapio.Record{}, Payload: pubrel},
			{Direction: replay.ServerToClient, Record: &pcapio.Record{}, Payload: pubcomp},
		},
	}
	res, err := replay.RunTCPSemanticContext(context.Background(), replay.TCPSemanticConfig{
		Session: session, TargetIP: netip.MustParseAddr("127.0.0.1"), TargetPort: 1883,
		Adapter: MQTT{}, Verify: replay.VerifyStrict, Timeout: time.Second, Dial: dial,
	})
	if err != nil || !res.Completed || !res.Matched || res.Sent != 2 || res.Received != 2 {
		t.Fatalf("QoS 2 flow result=%+v err=%v", res, err)
	}
}
