package adapters

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/kvmukilan/livewire/internal/replay"
)

type MQTT struct{}

func (MQTT) Name() string { return "mqtt" }
func (MQTT) Detect(s replay.Session) replay.Confidence {
	if c := portConfidence(s, 1883, 8883); c > 0 {
		return c
	}
	p := firstPayload(s)
	if len(p) >= 2 && p[0]>>4 >= 1 && p[0]>>4 <= 15 {
		if _, _, ok := mqttRemaining(p[1:]); ok {
			return 30
		}
	}
	return 0
}

func (MQTT) Decode(_ replay.Direction, data []byte) ([]replay.Message, error) {
	var out []replay.Message
	for len(data) > 0 {
		if len(data) < 2 {
			return nil, fmt.Errorf("mqtt: truncated fixed header")
		}
		remaining, used, ok := mqttRemaining(data[1:])
		if !ok || 1+used+remaining > len(data) {
			return nil, fmt.Errorf("mqtt: malformed remaining length")
		}
		n := 1 + used + remaining
		raw := append([]byte(nil), data[:n]...)
		packetType := raw[0] >> 4
		fields := map[string]any{"type": packetType, "qos": (raw[0] >> 1) & 3}
		body := raw[1+used:]
		if id, ok := mqttPacketID(packetType, body, fields["qos"].(uint8)); ok {
			fields["packetId"] = id
		}
		if packetType == 3 {
			if topic, _, ok := mqttUTF8(body, 0); ok {
				fields["topic"] = topic
			}
		}
		if packetType == 1 {
			parseMQTTConnect(body, fields)
		}
		out = append(out, replay.Message{Kind: mqttTypeName(packetType), Raw: raw, Fields: fields})
		data = data[n:]
	}
	return out, nil
}

func mqttRemaining(buf []byte) (value, used int, ok bool) {
	multiplier := 1
	for i := 0; i < len(buf) && i < 4; i++ {
		value += int(buf[i]&127) * multiplier
		used++
		if buf[i]&128 == 0 {
			return value, used, true
		}
		multiplier *= 128
	}
	return 0, 0, false
}

func appendMQTTLength(out []byte, n int) []byte {
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 128
		}
		out = append(out, b)
		if n == 0 {
			return out
		}
	}
}

func mqttPacketID(typ uint8, body []byte, qos uint8) (uint16, bool) {
	off, ok := mqttPacketIDOffset(typ, body, qos)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint16(body[off : off+2]), true
}

func mqttPacketIDOffset(typ uint8, body []byte, qos uint8) (int, bool) {
	off := 0
	switch typ {
	case 3: // PUBLISH: topic UTF-8 precedes packet id when QoS > 0
		if qos == 0 || len(body) < 2 {
			return 0, false
		}
		off = 2 + int(binary.BigEndian.Uint16(body[:2]))
	case 4, 5, 6, 7, 9, 11, 14:
		off = 0
	default:
		return 0, false
	}
	if off+2 > len(body) {
		return 0, false
	}
	return off, true
}

func parseMQTTConnect(body []byte, fields map[string]any) {
	version, flags, _, off, ok := mqttConnectLayout(body)
	if !ok {
		return
	}
	fields["version"] = version
	if v, next, ok := mqttUTF8(body, off); ok {
		fields["clientId"] = v
		off = next
	}
	if flags&0x04 != 0 { // will topic + payload
		if version == 5 {
			var ok bool
			off, ok = mqttPropertiesEnd(body, off)
			if !ok {
				return
			}
		}
		_, off, _ = mqttUTF8(body, off)
		_, off, _ = mqttUTF8(body, off)
	}
	if flags&0x80 != 0 {
		if v, next, ok := mqttUTF8(body, off); ok {
			fields["username"] = v
			off = next
		}
	}
	if flags&0x40 != 0 {
		if _, _, ok := mqttUTF8(body, off); ok {
			fields["hasPassword"] = true
		}
	}
}

func mqttConnectLayout(body []byte) (version, flags byte, flagsOff, payloadOff int, ok bool) {
	if len(body) < 10 {
		return 0, 0, 0, 0, false
	}
	nameLen := int(binary.BigEndian.Uint16(body[:2]))
	base := 2 + nameLen
	if base+4 > len(body) {
		return 0, 0, 0, 0, false
	}
	version, flags, flagsOff = body[base], body[base+1], base+1
	payloadOff = base + 4
	if version == 5 {
		payloadOff, ok = mqttPropertiesEnd(body, payloadOff)
		if !ok {
			return 0, 0, 0, 0, false
		}
	}
	return version, flags, flagsOff, payloadOff, true
}

func mqttPropertiesEnd(body []byte, off int) (int, bool) {
	if off >= len(body) {
		return off, false
	}
	n, used, ok := mqttRemaining(body[off:])
	if !ok || off+used+n > len(body) {
		return off, false
	}
	return off + used + n, true
}

func mqttUTF8(body []byte, off int) (string, int, bool) {
	if off+2 > len(body) {
		return "", off, false
	}
	n := int(binary.BigEndian.Uint16(body[off : off+2]))
	if off+2+n > len(body) {
		return "", off, false
	}
	return string(body[off+2 : off+2+n]), off + 2 + n, true
}

func mqttTypeName(t uint8) string {
	names := [...]string{"reserved", "connect", "connack", "publish", "puback", "pubrec", "pubrel", "pubcomp", "subscribe", "suback", "unsubscribe", "unsuback", "pingreq", "pingresp", "disconnect", "auth"}
	if int(t) < len(names) {
		return "mqtt-" + names[t]
	}
	return "mqtt-unknown"
}

func (MQTT) Prepare(direction replay.Direction, msg replay.Message, state *replay.RuntimeState) ([]byte, error) {
	if msg.Fields["type"] != uint8(1) || state == nil {
		out := substitute(msg.Raw, state)
		if direction == replay.ClientToServer && state != nil && mqttClientAcknowledgement(msg) {
			if expectedID, ok := mqttFieldUint16(msg.Fields["packetId"]); ok {
				if actualID, found := mqttLearnedServerID(state, expectedID); found {
					return rewriteMQTTPacketID(out, actualID)
				}
			}
		}
		return out, nil
	}
	clientID, hasClient := state.Variables["mqtt.client_id"]
	username, hasUser := state.Variables["mqtt.username"]
	password, hasPassword := state.Variables["mqtt.password"]
	if !hasClient && !hasUser && !hasPassword {
		return substitute(msg.Raw, state), nil
	}
	return rewriteMQTTConnect(msg.Raw, clientID, hasClient, username, hasUser, password, hasPassword)
}

func rewriteMQTTConnect(raw []byte, clientID string, setClient bool, username string, setUser bool, password string, setPassword bool) ([]byte, error) {
	remaining, used, ok := mqttRemaining(raw[1:])
	if !ok || 1+used+remaining > len(raw) {
		return nil, fmt.Errorf("mqtt: malformed CONNECT")
	}
	body := raw[1+used : 1+used+remaining]
	version, flags, flagsOff, payloadOff, ok := mqttConnectLayout(body)
	if !ok {
		return nil, fmt.Errorf("mqtt: malformed protocol name")
	}
	originalFlags := flags
	oldClient, next, ok := mqttUTF8(body, payloadOff)
	if !ok {
		return nil, fmt.Errorf("mqtt: missing client id")
	}
	if !setClient {
		clientID = oldClient
	}
	payload := mqttPutUTF8(nil, clientID)
	off := next
	if flags&0x04 != 0 {
		if version == 5 {
			propertiesEnd, ok := mqttPropertiesEnd(body, off)
			if !ok {
				return nil, fmt.Errorf("mqtt: malformed Will properties")
			}
			payload = append(payload, body[off:propertiesEnd]...)
			off = propertiesEnd
		}
		willTopic, n1, ok1 := mqttUTF8(body, off)
		willPayload, n2, ok2 := mqttUTF8(body, n1)
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("mqtt: malformed will payload")
		}
		payload = mqttPutUTF8(payload, willTopic)
		payload = mqttPutUTF8(payload, willPayload)
		off = n2
	}
	oldUser := ""
	if originalFlags&0x80 != 0 {
		var valid bool
		oldUser, off, valid = mqttUTF8(body, off)
		if !valid {
			return nil, fmt.Errorf("mqtt: malformed username")
		}
	}
	if setUser {
		flags |= 0x80
	} else if originalFlags&0x80 != 0 {
		username = oldUser
	}
	if flags&0x80 != 0 {
		payload = mqttPutUTF8(payload, username)
	}
	oldPassword := ""
	if originalFlags&0x40 != 0 {
		var valid bool
		oldPassword, off, valid = mqttUTF8(body, off)
		if !valid {
			return nil, fmt.Errorf("mqtt: malformed password")
		}
	}
	if setPassword {
		flags |= 0x40
	} else if originalFlags&0x40 != 0 {
		password = oldPassword
	}
	if flags&0x40 != 0 {
		payload = mqttPutUTF8(payload, password)
	}
	if off != len(body) {
		return nil, fmt.Errorf("mqtt: unexpected trailing CONNECT payload")
	}
	if len(clientID) > 0xffff || len(username) > 0xffff || len(password) > 0xffff {
		return nil, fmt.Errorf("mqtt: substituted UTF-8/binary field exceeds 65535 bytes")
	}
	prefix := append([]byte(nil), body[:payloadOff]...)
	prefix[flagsOff] = flags
	newBody := append(prefix, payload...)
	out := []byte{raw[0]}
	out = appendMQTTLength(out, len(newBody))
	return append(out, newBody...), nil
}

func mqttPutUTF8(dst []byte, value string) []byte {
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(value)))
	return append(dst, value...)
}

func (MQTT) Correlate(expected, actual replay.Message, state *replay.RuntimeState) replay.Match {
	if fmt.Sprint(expected.Fields["type"]) != fmt.Sprint(actual.Fields["type"]) {
		return replay.Match{Reason: "packet type differs"}
	}
	if fmt.Sprint(expected.Fields["topic"]) != fmt.Sprint(actual.Fields["topic"]) {
		return replay.Match{Reason: "publish topic differs"}
	}
	expectedID, hasExpectedID := mqttFieldUint16(expected.Fields["packetId"])
	actualID, hasActualID := mqttFieldUint16(actual.Fields["packetId"])
	if hasExpectedID != hasActualID {
		return replay.Match{Reason: "packet identifier presence differs"}
	}
	if hasExpectedID && expectedID != actualID {
		typ, _ := expected.Fields["type"].(uint8)
		qos, _ := expected.Fields["qos"].(uint8)
		if typ != 3 || qos == 0 || state == nil {
			return replay.Match{Reason: "packet identifier differs"}
		}
		if state.Learned == nil {
			state.Learned = map[string][]byte{}
		}
		state.Learned[mqttServerIDKey(expectedID)] = []byte{byte(actualID >> 8), byte(actualID)}
		return replay.Match{Matched: true, Key: fmt.Sprintf("server-publish:%d=>%d", expectedID, actualID)}
	}
	return replay.Match{Matched: true, Key: fmt.Sprint(expected.Fields["packetId"])}
}

func (MQTT) Compare(expected, actual replay.Message, mode replay.VerifyMode) []replay.Difference {
	var out []replay.Difference
	typ, _ := expected.Fields["type"].(uint8)
	fields := []string{"type", "packetId", "qos", "topic"}
	if typ == 3 {
		// A server chooses its own QoS PUBLISH identifier on each fresh
		// session. Correlate learns it and Prepare applies it to later client
		// acknowledgement packets, so the numeric drift is not a mismatch.
		fields = []string{"type", "qos", "topic"}
	}
	for _, field := range fields {
		if fmt.Sprint(expected.Fields[field]) != fmt.Sprint(actual.Fields[field]) {
			out = append(out, replay.Difference{Field: field, Expected: fmt.Sprint(expected.Fields[field]), Actual: fmt.Sprint(actual.Fields[field]), Structural: true})
		}
	}
	want, got := expected.Raw, actual.Raw
	if typ == 3 {
		if expectedID, ok := mqttFieldUint16(expected.Fields["packetId"]); ok {
			if rewritten, err := rewriteMQTTPacketID(actual.Raw, expectedID); err == nil {
				got = rewritten
			}
		}
	}
	if mode == replay.VerifyStrict && !bytes.Equal(want, got) {
		out = append(out, replay.Difference{Field: "message", Expected: "byte-identical", Actual: "different bytes", Structural: true})
	}
	return out
}

func (MQTT) NormalizeExpected(direction replay.Direction, message replay.Message, state *replay.RuntimeState) (replay.Message, error) {
	if direction != replay.ServerToClient || state == nil {
		return message, nil
	}
	expectedID, ok := mqttFieldUint16(message.Fields["packetId"])
	if !ok {
		return message, nil
	}
	actualID, found := mqttLearnedServerID(state, expectedID)
	if !found {
		return message, nil
	}
	raw, err := rewriteMQTTPacketID(message.Raw, actualID)
	if err != nil {
		return replay.Message{}, err
	}
	fields := make(map[string]any, len(message.Fields))
	for key, value := range message.Fields {
		fields[key] = value
	}
	fields["packetId"] = actualID
	message.Raw, message.Fields = raw, fields
	return message, nil
}

func mqttClientAcknowledgement(message replay.Message) bool {
	typ, _ := message.Fields["type"].(uint8)
	return typ == 4 || typ == 5 || typ == 6 || typ == 7
}

func mqttFieldUint16(value any) (uint16, bool) {
	switch v := value.(type) {
	case uint16:
		return v, true
	case uint8:
		return uint16(v), true
	case int:
		return uint16(v), v >= 0 && v <= 0xffff
	default:
		return 0, false
	}
}

func mqttServerIDKey(expected uint16) string {
	return fmt.Sprintf("mqtt.server.packet_id.%d", expected)
}

func mqttLearnedServerID(state *replay.RuntimeState, expected uint16) (uint16, bool) {
	if state == nil || len(state.Learned[mqttServerIDKey(expected)]) != 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(state.Learned[mqttServerIDKey(expected)]), true
}

func rewriteMQTTPacketID(raw []byte, id uint16) ([]byte, error) {
	if len(raw) < 2 {
		return nil, fmt.Errorf("mqtt: truncated fixed header while rewriting packet identifier")
	}
	remaining, used, ok := mqttRemaining(raw[1:])
	if !ok || 1+used+remaining != len(raw) {
		return nil, fmt.Errorf("mqtt: malformed remaining length while rewriting packet identifier")
	}
	typ, qos := raw[0]>>4, (raw[0]>>1)&3
	bodyOffset := 1 + used
	offset, ok := mqttPacketIDOffset(typ, raw[bodyOffset:], qos)
	if !ok {
		return nil, fmt.Errorf("mqtt: packet type %d has no rewritable packet identifier", typ)
	}
	out := append([]byte(nil), raw...)
	binary.BigEndian.PutUint16(out[bodyOffset+offset:bodyOffset+offset+2], id)
	return out, nil
}
