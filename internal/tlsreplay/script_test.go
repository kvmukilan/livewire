package tlsreplay

import (
	"testing"
	"time"
)

func TestConversationOrder(t *testing.T) {
	in := []AppMessage{{Role: FromClient, Data: []byte("c1")}, {Role: FromClient, Data: []byte("c2")}, {Role: FromServer, Data: []byte("s1")}}
	out := ConversationOrder(in)
	if string(out[0].Data) != "c1" || string(out[1].Data) != "s1" || string(out[2].Data) != "c2" {
		t.Fatalf("order=%q/%q/%q", out[0].Data, out[1].Data, out[2].Data)
	}
}

func TestConversationOrderPreservesTimedPipelining(t *testing.T) {
	in := []AppMessage{
		{Role: FromServer, Data: []byte("s1"), CapturedAt: 2 * time.Millisecond, CapturedPacket: 3, HasCaptureTime: true},
		{Role: FromClient, Data: []byte("c1"), CapturedAt: time.Millisecond, CapturedPacket: 1, HasCaptureTime: true},
		{Role: FromClient, Data: []byte("c2"), CapturedAt: time.Millisecond, CapturedPacket: 2, HasCaptureTime: true},
	}
	out := ConversationOrder(in)
	if string(out[0].Data) != "c1" || string(out[1].Data) != "c2" || string(out[2].Data) != "s1" {
		t.Fatalf("timed order=%q/%q/%q", out[0].Data, out[1].Data, out[2].Data)
	}
}
