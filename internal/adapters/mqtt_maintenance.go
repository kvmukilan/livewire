package adapters

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/kvmukilan/livewire/internal/replay"
)

type mqtt5PropertySpan struct {
	id         byte
	start, end int
}

func mqttBody(raw []byte) ([]byte, error) {
	if len(raw) < 2 {
		return nil, fmt.Errorf("mqtt: truncated packet")
	}
	n, used, ok := mqttRemaining(raw[1:])
	if !ok || 1+used+n != len(raw) {
		return nil, fmt.Errorf("mqtt: malformed packet length")
	}
	return raw[1+used:], nil
}

// mqtt5Properties validates typed properties without retaining authentication
// material. Unknown properties fail closed because their width is not known.
func mqtt5Properties(body []byte, off int) (map[byte]any, int, error) {
	if off < 0 || off >= len(body) {
		return nil, 0, fmt.Errorf("mqtt: missing properties length")
	}
	n, used, ok := mqttRemaining(body[off:])
	if !ok || n > len(body)-off-used {
		return nil, 0, fmt.Errorf("mqtt: malformed properties length")
	}
	end := off + used + n
	out := map[byte]any{}
	var spans []mqtt5PropertySpan
	for pos := off + used; pos < end; {
		start := pos
		id := body[pos]
		pos++
		if _, exists := out[id]; exists && id != 0x26 && id != 0x0b {
			return nil, 0, fmt.Errorf("mqtt: duplicate property 0x%x", id)
		}
		width := 0
		switch id {
		case 0x01, 0x17, 0x19, 0x24, 0x25, 0x28, 0x29, 0x2a:
			width = 1
		case 0x13, 0x21, 0x22, 0x23:
			width = 2
		case 0x02, 0x11, 0x18, 0x27:
			width = 4
		case 0x0b:
			v, k, valid := mqttRemaining(body[pos:end])
			if !valid {
				return nil, 0, fmt.Errorf("mqtt: malformed variable property")
			}
			pos += k
			out[id] = uint32(v)
			spans = append(spans, mqtt5PropertySpan{id, start, pos})
			continue
		case 0x03, 0x08, 0x09, 0x12, 0x15, 0x16, 0x1a, 0x1c, 0x1f, 0x26:
			_, next, valid := mqttUTF8(body[:end], pos)
			if !valid {
				return nil, 0, fmt.Errorf("mqtt: truncated string property")
			}
			pos = next
			if id == 0x26 {
				_, next, valid = mqttUTF8(body[:end], pos)
				if !valid {
					return nil, 0, fmt.Errorf("mqtt: truncated user property")
				}
				pos = next
			}
			out[id] = true
			spans = append(spans, mqtt5PropertySpan{id, start, pos})
			continue
		default:
			return nil, 0, fmt.Errorf("mqtt: unsupported property 0x%x", id)
		}
		if width > end-pos {
			return nil, 0, fmt.Errorf("mqtt: truncated property 0x%x", id)
		}
		var v uint32
		switch width {
		case 1:
			v = uint32(body[pos])
		case 2:
			v = uint32(binary.BigEndian.Uint16(body[pos:]))
		case 4:
			v = binary.BigEndian.Uint32(body[pos:])
		}
		out[id] = v
		pos += width
		spans = append(spans, mqtt5PropertySpan{id, start, pos})
	}
	out[0] = spans
	return out, end, nil
}

func (a MQTT) Maintenance(now time.Time, state *replay.RuntimeState) ([]replay.Message, time.Time, error) {
	if state == nil || state.Phase != replay.SessionActive {
		return nil, time.Time{}, nil
	}
	s, _ := state.Protocol["mqtt.state"].(*mqttState)
	if s == nil || !s.Connected || s.KeepAlive == 0 {
		return nil, time.Time{}, nil
	}
	if s.Ping {
		deadline := s.PingDeadline
		if deadline.IsZero() {
			deadline = state.LastWrite.Add(s.KeepAlive)
		}
		if !now.Before(deadline) {
			return nil, time.Time{}, fmt.Errorf("mqtt: keepalive PINGRESP timed out")
		}
		return nil, deadline, nil
	}
	if state.LastWrite.IsZero() {
		return nil, time.Time{}, nil
	}
	deadline := state.LastWrite.Add(s.KeepAlive)
	if now.Before(deadline) {
		return nil, deadline, nil
	}
	m, err := a.Decode(replay.ClientToServer, []byte{0xc0, 0})
	if err != nil {
		return nil, time.Time{}, err
	}
	m[0].Fields["runtimeMaintenance"] = true
	m[0].Fields["pingDeadline"] = now.Add(s.KeepAlive)
	return m, now.Add(s.KeepAlive), nil
}

func (a MQTT) MaintenanceEvent(m replay.Message, state *replay.RuntimeState) (bool, error) {
	s, _ := state.Protocol["mqtt.state"].(*mqttState)
	if s == nil || !s.MaintenancePing || m.Fields["type"] != uint8(13) {
		return false, nil
	}
	return true, observeMQTTTransition(replay.ServerToClient, m, state)
}
