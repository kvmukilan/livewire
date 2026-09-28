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

func TestMQTTBidirectionalQoS2UsesIndependentIdentifiers(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	publish := func(topic string, id uint16) []byte {
		b := mqttQoS1Publish(topic, id, "value")
		b[0] = 0x34
		return b
	}
	join := func(a, b []byte) []byte { return append(append([]byte(nil), a...), b...) }
	// Both captured peers use 7. The fresh broker chooses 42 for its own
	// publish, while client-owned transactions must keep their identifier 7.
	session := &replay.Session{ID: "bidirectional-mqtt", Transport: replay.TransportTCP, Events: []replay.Event{
		{Direction: replay.ServerToClient, Payload: publish("inbound", 7)},
		{Direction: replay.ClientToServer, Payload: join(publish("outbound", 7), []byte{0x50, 2, 0, 7})},
		{Direction: replay.ServerToClient, Payload: join([]byte{0x50, 2, 0, 7}, []byte{0x62, 2, 0, 7})},
		{Direction: replay.ClientToServer, Payload: join([]byte{0x62, 2, 0, 7}, []byte{0x70, 2, 0, 7})},
		{Direction: replay.ServerToClient, Payload: []byte{0x70, 2, 0, 7}},
	}}
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		server.SetDeadline(time.Now().Add(3 * time.Second))
		read := func(want []byte) error {
			got := make([]byte, len(want))
			if _, err := io.ReadFull(server, got); err != nil {
				return err
			}
			if !bytes.Equal(want, got) {
				return fmt.Errorf("wrong MQTT identifiers: want %x, got %x", want, got)
			}
			return nil
		}
		if _, err := server.Write(publish("inbound", 42)); err != nil {
			done <- err
			return
		}
		if err := read(join(publish("outbound", 7), []byte{0x50, 2, 0, 42})); err != nil {
			done <- err
			return
		}
		if _, err := server.Write(join([]byte{0x50, 2, 0, 7}, []byte{0x62, 2, 0, 42})); err != nil {
			done <- err
			return
		}
		if err := read(join([]byte{0x62, 2, 0, 7}, []byte{0x70, 2, 0, 42})); err != nil {
			done <- err
			return
		}
		_, err := server.Write([]byte{0x70, 2, 0, 7})
		done <- err
	}()
	result, err := replay.RunTCPSemanticContext(context.Background(), replay.TCPSemanticConfig{
		Session: session, Adapter: MQTT{}, Verify: replay.VerifyStrict, Timeout: time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) { return client, nil },
	})
	if err != nil || !result.Completed || !result.Matched {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestMQTTServerMappingDoesNotRewriteClientTransactionResponses(t *testing.T) {
	a := MQTT{}
	state := replay.NewRuntimeState(nil)
	state.Learned[mqttServerIDKey(7)] = []byte{0, 42}
	for _, typ := range []byte{0x40, 0x50, 0x70, 0x90, 0xb0} {
		t.Run(mqttTypeName(typ>>4), func(t *testing.T) {
			raw := []byte{typ, 2, 0, 7}
			messages, err := a.Decode(replay.ServerToClient, raw)
			if err != nil {
				t.Fatal(err)
			}
			got, err := a.NormalizeExpected(replay.ServerToClient, messages[0], state)
			if err != nil || !bytes.Equal(got.Raw, raw) {
				t.Fatalf("client-owned identifier rewritten: raw=%x err=%v", got.Raw, err)
			}
		})
	}
}

func TestMQTTQoS2RepeatedAcknowledgementPreservesTransaction(t *testing.T) {
	state := replay.NewRuntimeState(nil)
	publish := mqttQoS1Publish("a", 7, "value")
	publish[0] = 0x34
	for _, step := range []struct {
		dir replay.Direction
		raw []byte
	}{
		{replay.ClientToServer, publish},
		{replay.ServerToClient, []byte{0x50, 2, 0, 7}},
		{replay.ClientToServer, []byte{0x62, 2, 0, 7}},
		{replay.ServerToClient, []byte{0x50, 2, 0, 7}},
		{replay.ClientToServer, []byte{0x62, 2, 0, 7}},
		{replay.ServerToClient, []byte{0x70, 2, 0, 7}},
	} {
		if err := mqttObserveRaw(t, step.dir, step.raw, state); err != nil {
			t.Fatal(err)
		}
	}
	if len(state.Protocol["mqtt.state"].(*mqttState).Client) != 0 {
		t.Fatal("completed QoS2 transaction retained")
	}
}
