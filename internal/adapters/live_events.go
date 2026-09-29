package adapters

import (
	"fmt"
	"github.com/kvmukilan/livewire/internal/replay"
)

func (a MQTT) LiveEvent(m replay.Message, s *replay.RuntimeState) ([]replay.Message, bool, error) {
	typ, _ := m.Fields["type"].(uint8)
	if typ != 3 && typ != 6 && typ != 13 {
		return nil, false, nil
	}
	// PUBREL is handled automatically only for an extra live PUBLISH we own.
	id, _ := mqttFieldUint16(m.Fields["packetId"])
	key := fmt.Sprintf("mqtt.extra.%d", id)
	if typ == 6 {
		if _, ok := s.Protocol[key]; !ok {
			return nil, false, nil
		}
	}
	if err := observeMQTTTransition(replay.ServerToClient, m, s); err != nil {
		return nil, true, err
	}
	if typ == 13 {
		return nil, true, nil
	}
	qos, _ := m.Fields["qos"].(uint8)
	response := byte(0x40)
	if typ == 3 && qos == 0 {
		delete(s.Protocol, key)
		return nil, true, nil
	}
	if typ == 3 && qos == 2 {
		response = 0x50
		s.Protocol[key] = true
	}
	if typ == 3 && qos == 1 {
		delete(s.Protocol, key)
	}
	if typ == 6 {
		response = 0x70
		// Retain ownership for a repeated PUBREL until the broker reuses this
		// identifier. The bounded MQTT identifier space limits these markers.
		s.Protocol[key] = true
	}
	reply, err := a.Decode(replay.ClientToServer, []byte{response, 2, byte(id >> 8), byte(id)})
	return reply, true, err
}

func (a HTTP) LiveEvent(m replay.Message, s *replay.RuntimeState) ([]replay.Message, bool, error) {
	status := stringField(m, "status")
	if len(status) != 3 || status[0] != '1' || status == "101" {
		return nil, false, nil
	}
	return nil, true, replay.Observe(a, replay.ServerToClient, m, m, s)
}
