package adapters

import "github.com/kvmukilan/livewire/internal/replay"

// Automatic restart is limited to operations whose protocol defines them as
// reads. No write, upload, publish, or arbitrary command is inferred safe.
func (HTTP) RestartSafe(m replay.Message) bool {
	switch stringField(m, "method") {
	case "GET", "HEAD", "OPTIONS":
		return true
	}
	return false
}
func (a DNS) RestartSafe(m replay.Message) bool {
	b := m.Raw
	if a.Transport == replay.TransportTCP {
		if len(b) < 2 {
			return false
		}
		b = b[2:]
	}
	return len(b) >= 12 && b[2]&0xf8 == 0 // query, standard opcode
}
func (Modbus) RestartSafe(m replay.Message) bool {
	f, ok := m.Fields["function"].(uint8)
	return ok && f >= 1 && f <= 4
}

func (HTTP) Capabilities() replay.Capabilities {
	return replay.Capabilities{Incremental: true, Stateful: true, Recovery: "read-only restart; fresh authentication"}
}
func (MQTT) Capabilities() replay.Capabilities {
	return replay.Capabilities{Incremental: true, Stateful: true, Recovery: "completed session boundary"}
}
func (DNS) Capabilities() replay.Capabilities {
	return replay.Capabilities{Incremental: true, Stateful: true, Recovery: "standard query restart"}
}
func (Modbus) Capabilities() replay.Capabilities {
	return replay.Capabilities{Incremental: true, Stateful: true, Recovery: "read-only restart"}
}
func (DNP3) Capabilities() replay.Capabilities {
	return replay.Capabilities{Incremental: true, Stateful: true, Recovery: "completed session boundary"}
}
