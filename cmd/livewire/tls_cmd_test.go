package main

import (
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/tlsreplay"
)

func TestBuildTLSAdapterScriptPreservesHTTPPipelining(t *testing.T) {
	requests := []byte("GET /one HTTP/1.1\r\nHost: example.test\r\n\r\nGET /two HTTP/1.1\r\nHost: example.test\r\n\r\n")
	responses := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n")
	records := []tlsreplay.AppMessage{
		{Role: tlsreplay.FromClient, Data: requests, CapturedAt: time.Millisecond, CapturedPacket: 10, HasCaptureTime: true},
		{Role: tlsreplay.FromServer, Data: responses, CapturedAt: 2 * time.Millisecond, CapturedPacket: 20, HasCaptureTime: true},
	}
	state := &replay.RuntimeState{Variables: map[string]string{}, Learned: map[string][]byte{}}
	script, err := buildTLSAdapterScript(records, adapters.HTTP{}, state)
	if err != nil {
		t.Fatal(err)
	}
	if len(script) != 3 {
		t.Fatalf("script length=%d", len(script))
	}
	want := []tlsreplay.AppRole{tlsreplay.FromClient, tlsreplay.FromClient, tlsreplay.FromServer}
	for i := range want {
		if script[i].Role != want[i] {
			t.Fatalf("script[%d] role=%d want=%d", i, script[i].Role, want[i])
		}
	}
	if len(script[2].Peers) != 2 || len(script[2].Expected) != 2 {
		t.Fatalf("response group peers=%d expected=%d", len(script[2].Peers), len(script[2].Expected))
	}
}
