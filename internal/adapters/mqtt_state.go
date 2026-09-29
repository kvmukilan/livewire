package adapters

import (
	"fmt"
	"github.com/kvmukilan/livewire/internal/replay"
	"time"
)

type mqttState struct {
	Connecting              bool
	Connected               bool
	Version                 uint8
	Client                  map[uint16]string
	Server                  map[uint16]string
	Ping                    bool
	KeepAlive               time.Duration
	PingDeadline            time.Time
	MaintenancePing         bool
	ReceiveMaximum          uint16
	MaximumPacketSize       uint32
	MaximumQoS              uint8
	RetainAvailable         bool
	ServerAliases           map[uint16]string
	ClientAliasMaximum      uint16
	ClientReceiveMaximum    uint16
	ClientMaximumPacketSize uint32
}

func observeMQTTTransition(dir replay.Direction, m replay.Message, state *replay.RuntimeState) error {
	s, ok := state.Protocol["mqtt.state"].(*mqttState)
	if !ok {
		s = &mqttState{Client: map[uint16]string{}, Server: map[uint16]string{}, ServerAliases: map[uint16]string{}, ReceiveMaximum: 65535, ClientReceiveMaximum: 65535, MaximumQoS: 2, RetainAvailable: true}
		state.Protocol["mqtt.state"] = s
	}
	typ, _ := m.Fields["type"].(uint8)
	qos, _ := m.Fields["qos"].(uint8)
	id, hasID := mqttFieldUint16(m.Fields["packetId"])
	client := dir == replay.ClientToServer
	if client && s.Connected && s.MaximumPacketSize > 0 && uint64(len(m.Raw)) > uint64(s.MaximumPacketSize) {
		return fmt.Errorf("mqtt: request exceeds negotiated Maximum Packet Size")
	}
	if typ == 15 {
		return fmt.Errorf("mqtt: enhanced authentication requires a purpose-built authentication adapter")
	}
	if hasID && id == 0 {
		return fmt.Errorf("mqtt: packet identifier cannot be zero")
	}
	if qos == 3 && typ == 3 {
		return fmt.Errorf("mqtt: invalid PUBLISH QoS")
	}
	if typ == 1 {
		if !client {
			return fmt.Errorf("mqtt: server sent CONNECT")
		}
		if s.Connecting || s.Connected {
			return fmt.Errorf("mqtt: repeated CONNECT on one connection")
		}
		s.Connecting = true
		s.Version, _ = m.Fields["version"].(uint8)
		body, err := mqttBody(m.Raw)
		if err != nil {
			return err
		}
		_, _, flagsOff, _, valid := mqttConnectLayout(body)
		if !valid {
			return fmt.Errorf("mqtt: malformed CONNECT")
		}
		s.KeepAlive = time.Duration(uint16(body[flagsOff+1])<<8|uint16(body[flagsOff+2])) * time.Second
		if s.Version == 5 {
			props, _, err := mqtt5Properties(body, flagsOff+3)
			if err != nil {
				return err
			}
			if _, ok := props[0x15]; ok {
				return fmt.Errorf("mqtt: enhanced authentication requires a purpose-built authentication adapter")
			}
			if n, ok := props[0x22].(uint32); ok {
				s.ClientAliasMaximum = uint16(n)
			}
			if n, ok := props[0x21].(uint32); ok {
				if n == 0 {
					return fmt.Errorf("mqtt: zero client Receive Maximum")
				}
				s.ClientReceiveMaximum = uint16(n)
			}
			if n, ok := props[0x27].(uint32); ok {
				if n == 0 {
					return fmt.Errorf("mqtt: zero client Maximum Packet Size")
				}
				s.ClientMaximumPacketSize = n
			}
		}
		return nil
	}
	if typ == 2 {
		if client {
			return fmt.Errorf("mqtt: client sent CONNACK")
		}
		_, used, ok := mqttRemaining(m.Raw[1:])
		if !ok || len(m.Raw) < 1+used+2 {
			return fmt.Errorf("mqtt: truncated CONNACK")
		}
		if m.Raw[1+used+1] != 0 {
			return fmt.Errorf("mqtt: broker rejected connection")
		}
		if s.Version == 5 {
			props, end, err := mqtt5Properties(m.Raw[1+used:], 2)
			if err != nil {
				return err
			}
			if end != len(m.Raw)-1-used {
				return fmt.Errorf("mqtt: trailing CONNACK bytes")
			}
			if _, ok := props[0x15]; ok {
				return fmt.Errorf("mqtt: enhanced authentication is unsupported")
			}
			if n, ok := props[0x13].(uint32); ok {
				s.KeepAlive = time.Duration(n) * time.Second
			}
			if n, ok := props[0x21].(uint32); ok {
				if n == 0 {
					return fmt.Errorf("mqtt: zero Receive Maximum")
				}
				s.ReceiveMaximum = uint16(n)
			}
			if n, ok := props[0x27].(uint32); ok {
				if n == 0 {
					return fmt.Errorf("mqtt: zero Maximum Packet Size")
				}
				s.MaximumPacketSize = n
			}
			if n, ok := props[0x24].(uint32); ok {
				if n > 1 {
					return fmt.Errorf("mqtt: invalid Maximum QoS")
				}
				s.MaximumQoS = uint8(n)
			}
			if n, ok := props[0x25].(uint32); ok {
				if n > 1 {
					return fmt.Errorf("mqtt: invalid Retain Available")
				}
				s.RetainAvailable = n == 1
			}
		}
		s.Connecting = false
		s.Connected = true
		return nil
	}
	if s.Connecting {
		return fmt.Errorf("mqtt: operation before CONNACK")
	}
	if typ == 14 {
		s.Connected = false
		s.Ping = false
		s.MaintenancePing = false
		state.Phase = replay.SessionClosed
		return nil
	}
	if typ == 12 {
		if !client {
			return fmt.Errorf("mqtt: server sent PINGREQ")
		}
		s.Ping = true
		s.MaintenancePing, _ = m.Fields["runtimeMaintenance"].(bool)
		s.PingDeadline, _ = m.Fields["pingDeadline"].(time.Time)
		return nil
	}
	if typ == 13 {
		if client {
			return fmt.Errorf("mqtt: client sent PINGRESP")
		}
		s.Ping = false
		s.MaintenancePing = false
		s.PingDeadline = time.Time{}
		return nil
	}
	own, peer := s.Client, s.Server
	if !client {
		own, peer = s.Server, s.Client
	}
	switch typ {
	case 3:
		if !client && s.Version == 5 && qos > 0 && own[id] == "" && s.ClientReceiveMaximum > 0 && len(own) >= int(s.ClientReceiveMaximum) {
			return fmt.Errorf("mqtt: broker exceeded client Receive Maximum")
		}
		if client && s.Version == 5 {
			if qos > s.MaximumQoS {
				return fmt.Errorf("mqtt: PUBLISH exceeds negotiated Maximum QoS")
			}
			if m.Raw[0]&1 != 0 && !s.RetainAvailable {
				return fmt.Errorf("mqtt: broker does not support retained PUBLISH")
			}
			if s.MaximumPacketSize > 0 && uint64(len(m.Raw)) > uint64(s.MaximumPacketSize) {
				return fmt.Errorf("mqtt: request exceeds negotiated Maximum Packet Size")
			}
			if qos > 0 && own[id] == "" {
				active := 0
				for _, phase := range own {
					if phase == "puback" || phase == "pubrec" || phase == "pubrel" || phase == "pubcomp" {
						active++
					}
				}
				if active >= int(s.ReceiveMaximum) {
					return fmt.Errorf("mqtt: captured publish pipeline exceeds negotiated Receive Maximum")
				}
			}
		}
		if qos == 0 {
			return nil
		}
		if !hasID {
			return fmt.Errorf("mqtt: QoS PUBLISH lacks packet identifier")
		}
		phase := "puback"
		if qos == 2 {
			phase = "pubrec"
		}
		if prior := own[id]; prior != "" {
			if m.Raw[0]&8 == 0 {
				return fmt.Errorf("mqtt: packet identifier reused before acknowledgement")
			}
			if prior != phase && !(qos == 2 && prior == "pubrel") {
				return fmt.Errorf("mqtt: duplicate PUBLISH conflicts with active transaction")
			}
			return nil
		}
		own[id] = phase
	case 8, 10:
		if !client {
			return fmt.Errorf("mqtt: server sent subscription request")
		}
		if !hasID {
			return fmt.Errorf("mqtt: subscription lacks packet identifier")
		}
		if own[id] != "" {
			return fmt.Errorf("mqtt: active subscription identifier reused")
		}
		phase := "suback"
		if typ == 10 {
			phase = "unsuback"
		}
		own[id] = phase
	case 4, 5, 6, 7, 9, 11:
		phase := map[uint8]string{4: "puback", 5: "pubrec", 6: "pubrel", 7: "pubcomp", 9: "suback", 11: "unsuback"}[typ]
		pending := peer
		if typ == 6 {
			pending = own
		}
		// Mid-session captures may begin with an acknowledgement. Validate every
		// transaction whose beginning was observed; do not invent missing state.
		if prior := pending[id]; prior != "" && prior != phase {
			if typ == 5 && (prior == "pubrel" || prior == "pubcomp") || typ == 6 && prior == "pubcomp" {
				return nil
			}
			return fmt.Errorf("mqtt: invalid acknowledgement transition: expected %s", prior)
		}
		switch typ {
		case 5:
			pending[id] = "pubrel"
		case 6:
			pending[id] = "pubcomp"
		default:
			delete(pending, id)
		}
	}
	return nil
}
