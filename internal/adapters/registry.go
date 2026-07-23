package adapters

import "github.com/kvmukilan/livewire/internal/replay"

const BuiltInAdapterVersion = "1"

// DefaultRegistry returns a fresh registry so callers can add proprietary rule
// packs without mutating process-global state.
func DefaultRegistry() *replay.Registry {
	return replay.NewRegistry(
		HTTP{}, DNS{Transport: replay.TransportUDP}, DNS{Transport: replay.TransportTCP}, MQTT{}, Modbus{}, DNP3{}, TLS{}, SSH{},
	)
}

// Versions is written into reports so a replay remains attributable even when
// adapter behavior evolves in a later Livewire release.
func Versions() map[string]string {
	return VersionsForRegistry(DefaultRegistry())
}

func VersionsForRegistry(r *replay.Registry) map[string]string {
	out := make(map[string]string)
	for _, name := range r.Names() {
		version := BuiltInAdapterVersion
		if v, ok := r.ByName(name).(interface{ Version() string }); ok {
			version = v.Version()
		}
		out[name] = version
	}
	return out
}
