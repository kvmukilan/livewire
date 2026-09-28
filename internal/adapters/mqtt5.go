package adapters

import (
	"bytes"
	"fmt"

	"github.com/kvmukilan/livewire/internal/replay"
)

// Expand aliases before replaying a capture so the new broker never depends on
// an alias table from an old connection or a different negotiated alias limit.
func (a MQTT) NormalizeConversation(turns []replay.ConversationTurn) ([]replay.ConversationTurn, error) {
	version := uint8(0)
	aliases := map[replay.Direction]map[uint16]string{replay.ClientToServer: {}, replay.ServerToClient: {}}
	out := append([]replay.ConversationTurn(nil), turns...)
	buffers := map[replay.Direction][]byte{}
	for i, turn := range out {
		buffer := append(buffers[turn.Direction], turn.Payload...)
		if len(buffer) > maxRuleFrame {
			return nil, fmt.Errorf("mqtt: capture frame buffer exceeds limit")
		}
		var messages []replay.Message
		for len(buffer) > 0 {
			decoded, n, err := a.DecodeAvailable(turn.Direction, buffer, nil, false)
			if err != nil {
				return nil, err
			}
			if n == 0 {
				break
			}
			messages = append(messages, decoded...)
			buffer = buffer[n:]
		}
		buffers[turn.Direction] = append([]byte(nil), buffer...)
		var payload []byte
		for _, m := range messages {
			var err error
			typ, _ := m.Fields["type"].(uint8)
			if typ == 1 {
				version, _ = m.Fields["version"].(uint8)
			}
			if typ == 15 {
				return nil, fmt.Errorf("mqtt: enhanced authentication requires an authentication-aware adapter")
			}
			if version == 5 && typ == 1 {
				body, _ := mqttBody(m.Raw)
				_, _, flagsOff, _, ok := mqttConnectLayout(body)
				if !ok {
					return nil, fmt.Errorf("mqtt: malformed CONNECT")
				}
				props, _, err := mqtt5Properties(body, flagsOff+3)
				if err != nil {
					return nil, err
				}
				if _, auth := props[0x15]; auth {
					return nil, fmt.Errorf("mqtt: enhanced authentication requires an authentication-aware adapter")
				}
			}
			if version == 5 && typ == 3 {
				m, err = normalizeMQTT5Publish(m, aliases[turn.Direction], 65535)
				if err != nil {
					return nil, err
				}
			}
			payload = append(payload, m.Raw...)
		}
		out[i].Payload = payload
	}
	for _, buffer := range buffers {
		if len(buffer) > 0 {
			return nil, fmt.Errorf("mqtt: incomplete captured packet")
		}
	}
	filtered := out[:0]
	for _, turn := range out {
		if len(turn.Payload) > 0 || turn.CloseWrite {
			filtered = append(filtered, turn)
		}
	}
	return filtered, nil
}

func normalizeMQTT5Publish(m replay.Message, aliases map[uint16]string, maxAlias uint16) (replay.Message, error) {
	body, err := mqttBody(m.Raw)
	if err != nil {
		return m, err
	}
	topic, off, ok := mqttUTF8(body, 0)
	if !ok {
		return m, fmt.Errorf("mqtt: malformed PUBLISH topic")
	}
	qos, _ := m.Fields["qos"].(uint8)
	idBytes := []byte(nil)
	if qos > 0 {
		if len(body)-off < 2 {
			return m, fmt.Errorf("mqtt: missing PUBLISH identifier")
		}
		idBytes = body[off : off+2]
		off += 2
	}
	props, end, err := mqtt5Properties(body, off)
	if err != nil {
		return m, err
	}
	if v, found := props[0x23].(uint32); found {
		alias := uint16(v)
		if alias == 0 || alias > maxAlias {
			return m, fmt.Errorf("mqtt: PUBLISH topic alias exceeds negotiated range")
		}
		if topic != "" {
			if _, exists := aliases[alias]; !exists && len(aliases) >= 4096 {
				return m, fmt.Errorf("mqtt: topic alias table exceeds entry limit")
			}
			total := len(topic) - len(aliases[alias])
			for _, existing := range aliases {
				total += len(existing)
			}
			if total > maxRuleFrame {
				return m, fmt.Errorf("mqtt: topic alias table exceeds memory limit")
			}
			aliases[alias] = topic
		} else {
			topic = aliases[alias]
			if topic == "" {
				return m, fmt.Errorf("mqtt: PUBLISH uses an undefined topic alias")
			}
		}
	}
	if topic == "" {
		return m, fmt.Errorf("mqtt: empty PUBLISH topic without a known alias")
	}
	var properties []byte
	for _, span := range props[0].([]mqtt5PropertySpan) {
		if span.id != 0x23 {
			properties = append(properties, body[span.start:span.end]...)
		}
	}
	newBody := mqttPutUTF8(nil, topic)
	newBody = append(newBody, idBytes...)
	newBody = appendMQTTLength(newBody, len(properties))
	newBody = append(newBody, properties...)
	newBody = append(newBody, body[end:]...)
	raw := appendMQTTLength([]byte{m.Raw[0]}, len(newBody))
	raw = append(raw, newBody...)
	decoded, err := (MQTT{}).Decode(replay.ServerToClient, raw)
	if err != nil {
		return m, err
	}
	decoded[0].Fields["mqttVersion"] = uint8(5)
	return decoded[0], nil
}

func (a MQTT) DecodeAvailableState(dir replay.Direction, data []byte, peers []replay.Message, eof bool, state *replay.RuntimeState) ([]replay.Message, int, error) {
	m, n, err := a.DecodeAvailable(dir, data, peers, eof)
	if err != nil || len(m) == 0 {
		return m, n, err
	}
	s, _ := state.Protocol["mqtt.state"].(*mqttState)
	if s == nil || s.Version != 5 {
		return m, n, nil
	}
	if dir == replay.ServerToClient && s.ClientMaximumPacketSize > 0 && uint64(n) > uint64(s.ClientMaximumPacketSize) {
		return nil, 0, fmt.Errorf("mqtt: broker exceeded client Maximum Packet Size")
	}
	for i := range m {
		m[i].Fields["mqttVersion"] = uint8(5)
		if m[i].Fields["type"] == uint8(3) {
			before := m[i].Raw
			m[i], err = normalizeMQTT5Publish(m[i], s.ServerAliases, s.ClientAliasMaximum)
			if err != nil {
				return nil, 0, err
			}
			if !bytes.Equal(before, m[i].Raw) {
				state.Transformations = append(state.Transformations, "mqtt: live MQTT 5 topic alias expanded")
			}
		}
	}
	return m, n, nil
}

func mqtt5ConnackComparison(expected, actual replay.Message) []replay.Difference {
	w, we := mqttBody(expected.Raw)
	g, ge := mqttBody(actual.Raw)
	if we != nil || ge != nil || len(w) < 3 || len(g) < 3 {
		return []replay.Difference{{Field: "connack", Actual: "invalid MQTT 5 CONNACK", Structural: true}}
	}
	if !bytes.Equal(w[:2], g[:2]) {
		return []replay.Difference{{Field: "connack", Expected: fmt.Sprintf("%x", w[:2]), Actual: fmt.Sprintf("%x", g[:2]), Structural: true}}
	}
	return nil
}
