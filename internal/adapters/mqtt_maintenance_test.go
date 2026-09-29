package adapters

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/replay"
)

func mqttObserveRaw(t *testing.T, dir replay.Direction, raw []byte, state *replay.RuntimeState) error {
	t.Helper()
	a := MQTT{}
	m, err := a.Decode(dir, raw)
	if err != nil {
		t.Fatal(err)
	}
	return replay.Observe(a, dir, m[0], m[0], state)
}

func TestMQTTMaintenanceNegotiatedDeadlineAndOwnership(t *testing.T) {
	a := MQTT{}
	state := replay.NewRuntimeState(nil)
	if err := mqttObserveRaw(t, replay.ClientToServer, mqtt5Connect("test"), state); err != nil {
		t.Fatal(err)
	}
	if err := mqttObserveRaw(t, replay.ServerToClient, []byte{0x20, 6, 0, 0, 3, 0x13, 0, 2}, state); err != nil {
		t.Fatal(err)
	}
	start := time.Unix(1000, 0)
	state.LastWrite = start
	ping, next, err := a.Maintenance(start.Add(time.Second), state)
	if err != nil || len(ping) != 0 || !next.Equal(start.Add(2*time.Second)) {
		t.Fatalf("early ping=%v next=%v err=%v", ping, next, err)
	}
	ping, _, err = a.Maintenance(start.Add(2*time.Second), state)
	if err != nil || len(ping) != 1 || !bytes.Equal(ping[0].Raw, []byte{0xc0, 0}) {
		t.Fatalf("ping=%v err=%v", ping, err)
	}
	if err := replay.Observe(a, replay.ClientToServer, ping[0], ping[0], state); err != nil {
		t.Fatal(err)
	}
	if _, _, err = a.Maintenance(start.Add(4*time.Second), state); err == nil {
		t.Fatal("missing PINGRESP did not time out")
	}
	response, _ := a.Decode(replay.ServerToClient, []byte{0xd0, 0})
	if handled, err := a.MaintenanceEvent(response[0], state); err != nil || !handled {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	if handled, _ := a.MaintenanceEvent(response[0], state); handled {
		t.Fatal("captured PINGRESP stolen after maintenance completed")
	}
	state.Phase = replay.SessionClosed
	if ping, _, err = a.Maintenance(start.Add(10*time.Second), state); err != nil || len(ping) > 0 {
		t.Fatal("maintenance wrote after half-close")
	}
	state.Phase = replay.SessionActive
	if err := mqttObserveRaw(t, replay.ClientToServer, []byte{0xe0, 0}, state); err != nil {
		t.Fatal(err)
	}
	if state.Phase != replay.SessionClosed {
		t.Fatal("MQTT DISCONNECT did not finish the protocol session")
	}
}

func TestMQTT5NegotiatedLimitsFailBeforeInvalidPublish(t *testing.T) {
	for _, tc := range []struct {
		name       string
		properties []byte
		header     byte
		message    string
	}{
		{"maximum QoS", []byte{0x24, 0}, 0x32, "Maximum QoS"},
		{"retain unavailable", []byte{0x25, 0}, 0x31, "retained"},
		{"maximum packet size", []byte{0x27, 0, 0, 0, 4}, 0x30, "Maximum Packet Size"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := replay.NewRuntimeState(nil)
			if err := mqttObserveRaw(t, replay.ClientToServer, mqtt5Connect("test"), state); err != nil {
				t.Fatal(err)
			}
			connackBody := append([]byte{0, 0, byte(len(tc.properties))}, tc.properties...)
			if err := mqttObserveRaw(t, replay.ServerToClient, append([]byte{0x20, byte(len(connackBody))}, connackBody...), state); err != nil {
				t.Fatal(err)
			}
			body := mqttPutUTF8(nil, "a")
			if tc.header&6 != 0 {
				body = append(body, 0, 1)
			}
			body = append(body, 0, 'v')
			err := mqttObserveRaw(t, replay.ClientToServer, append([]byte{tc.header, byte(len(body))}, body...), state)
			if err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("error=%v want %q", err, tc.message)
			}
		})
	}
}

func TestMQTT5TopicAliasExpandedForFreshSession(t *testing.T) {
	a := MQTT{}
	publish := func(topic string) []byte {
		body := mqttPutUTF8(nil, topic)
		body = append(body, 3, 0x23, 0, 1, 'v')
		return append([]byte{0x30, byte(len(body))}, body...)
	}
	turns, err := a.NormalizeConversation([]replay.ConversationTurn{{Direction: replay.ClientToServer, Payload: mqtt5Connect("test")}, {Direction: replay.ClientToServer, Payload: append(publish("a"), publish("")...)}})
	if err != nil {
		t.Fatal(err)
	}
	m, err := a.Decode(replay.ClientToServer, turns[1].Payload)
	if err != nil || len(m) != 2 {
		t.Fatalf("messages=%v err=%v", m, err)
	}
	for _, message := range m {
		if message.Fields["topic"] != "a" || !bytes.Equal(message.Raw, []byte{0x30, 5, 0, 1, 'a', 0, 'v'}) {
			t.Fatalf("alias not expanded: %x %+v", message.Raw, message.Fields)
		}
	}
	state := replay.NewRuntimeState(nil)
	s := &mqttState{Version: 5, ClientAliasMaximum: 1, ServerAliases: map[uint16]string{}}
	state.Protocol["mqtt.state"] = s
	for _, raw := range [][]byte{publish("a"), publish("")} {
		m, _, err := a.DecodeAvailableState(replay.ServerToClient, raw, nil, false, state)
		if err != nil || len(m) != 1 || m[0].Fields["topic"] != "a" {
			t.Fatalf("live alias messages=%v err=%v", m, err)
		}
	}
	s.ClientAliasMaximum = 0
	if _, _, err := a.DecodeAvailableState(replay.ServerToClient, publish("a"), nil, false, state); err == nil {
		t.Fatal("unnegotiated alias accepted")
	}
}

func TestMQTT5AuthenticationAndMalformedPropertiesBlock(t *testing.T) {
	a := MQTT{}
	if _, err := a.NormalizeConversation([]replay.ConversationTurn{{Direction: replay.ClientToServer, Payload: []byte{0xf0, 0}}}); err == nil {
		t.Fatal("enhanced AUTH accepted")
	}
	for _, props := range [][]byte{{3, 0x21, 0, 0}, {6, 0x13, 0, 1, 0x13, 0, 2}, {1, 0x7f}, {3, 0x27, 0, 1}} {
		state := replay.NewRuntimeState(nil)
		if err := mqttObserveRaw(t, replay.ClientToServer, mqtt5Connect("test"), state); err != nil {
			t.Fatal(err)
		}
		body := append([]byte{0, 0}, props...)
		if err := mqttObserveRaw(t, replay.ServerToClient, append([]byte{0x20, byte(len(body))}, body...), state); err == nil {
			t.Fatalf("invalid properties accepted: %x", props)
		}
	}
}
