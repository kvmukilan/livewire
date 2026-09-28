package adapters

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/replay"
)

func TestExtraMQTTPublishAcknowledgedWhileWaitingForReply(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	state := replay.NewRuntimeState(nil)
	a := MQTT{}
	sub := []byte{0x82, 6, 0, 9, 0, 1, 'a', 0}
	want := []byte{0x90, 3, 0, 9, 0}
	req, e := a.Decode(replay.ClientToServer, sub)
	if e != nil {
		t.Fatal(e)
	}
	if e = replay.Observe(a, replay.ClientToServer, req[0], req[0], state); e != nil {
		t.Fatal(e)
	}
	expected, e := a.Decode(replay.ServerToClient, want)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		defer s.Close()
		s.SetDeadline(time.Now().Add(time.Second))
		_, e := s.Write(mqttQoS1Publish("extra", 42, "new"))
		if e != nil {
			done <- e
			return
		}
		ack := make([]byte, 4)
		_, e = io.ReadFull(s, ack)
		if e != nil {
			done <- e
			return
		}
		if !bytes.Equal(ack, []byte{0x40, 2, 0, 42}) {
			done <- fmt.Errorf("ack %x", ack)
			return
		}
		_, e = s.Write(want)
		done <- e
	}()
	var reader replay.MessageReader
	got, e := reader.ReadExchange(context.Background(), c, a, expected, req, state, time.Second)
	if e != nil || len(got) != 1 || !bytes.Equal(got[0].Raw, want) {
		t.Fatalf("got=%v err=%v", got, e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if len(state.Transformations) == 0 {
		t.Fatal("extra event missing from evidence")
	}
}

func TestHTTPAdditionalInformationalResponse(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	final := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	expected, e := (HTTP{}).Decode(replay.ServerToClient, final)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		defer s.Close()
		s.SetDeadline(time.Now().Add(time.Second))
		_, e := s.Write(append([]byte("HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"), final...))
		done <- e
	}()
	var reader replay.MessageReader
	got, e := reader.ReadExchange(context.Background(), c, HTTP{}, expected, nil, replay.NewRuntimeState(nil), time.Second)
	if e != nil || len(got) != 1 || !bytes.Equal(got[0].Raw, final) {
		t.Fatalf("got=%v err=%v", got, e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
