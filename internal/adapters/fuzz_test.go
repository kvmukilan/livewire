package adapters

import (
	"testing"

	"github.com/kvmukilan/livewire/internal/replay"
)

func FuzzBuiltInDecoders(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: example\r\n\r\n"),
		dnsQuery("example.com", 1), mqttConnect("client"),
		{0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1}, {0x05, 0x64},
	} {
		f.Add(seed)
	}
	adapters := []replay.Adapter{HTTP{}, DNS{Transport: replay.TransportUDP}, DNS{Transport: replay.TransportTCP}, MQTT{}, Modbus{}, DNP3{}, TLS{}, SSH{}}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		for _, a := range adapters {
			_, _ = a.Decode(replay.ClientToServer, data)
		}
	})
}

func FuzzRulePackCompiler(f *testing.F) {
	f.Add([]byte(`{"name":"x","match":{"transport":"udp"},"framing":{"type":"datagram"}}`))
	f.Add([]byte(`{"name":"x","match":{"transport":"tcp"},"framing":{"type":"length-field","lengthOffset":1,"lengthSize":2}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		a, err := CompileRulePackJSON(data)
		if err == nil {
			_, _ = a.Decode(replay.ClientToServer, data)
		}
	})
}
