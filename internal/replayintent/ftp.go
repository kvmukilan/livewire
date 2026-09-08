package replayintent

import (
	"bytes"
	"fmt"
	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/ftpreplay"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/tlsreplay"
)

// RegistryWithKeyLog resolves encrypted FTP negotiation offline. It clones the
// registry so credentials and capture-specific groups never escape a request.
func RegistryWithKeyLog(registry *replay.Registry, data []byte) (*replay.Registry, error) {
	if registry == nil {
		registry = adapters.DefaultRegistry()
	}
	if len(data) == 0 {
		return registry, nil
	}
	keys, err := tlsreplay.ParseKeyLog(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if keys.Count() == 0 {
		return nil, fmt.Errorf("key log contains no usable NSS session keys")
	}
	out := replay.NewRegistry()
	for _, name := range registry.Names() {
		if name != "ftp" {
			out.Register(registry.ByName(name))
		} else {
			out.Register(keyedFTP{KeyLog: keys})
		}
	}
	return out, nil
}

type keyedFTP struct {
	adapters.FTP
	KeyLog *tlsreplay.KeyLog
}

func (a keyedFTP) DiscoverGroups(t *replay.Trace) []replay.SessionGroup {
	groups := a.FTP.DiscoverGroups(t)
	for _, s := range t.Sessions {
		if s.Transport != replay.TransportTCP || !NeedsKeyLog(s) {
			continue
		}
		g := replay.SessionGroup{ID: "ftp:" + s.ID, ControlSessionID: s.ID}
		script, err := ftpreplay.BuildScript(s, a.KeyLog)
		if err == nil {
			var data []*replay.Session
			data, err = ftpreplay.MatchDataSessions(t, s, script)
			for _, d := range data {
				g.RelatedSessionIDs = append(g.RelatedSessionIDs, d.ID)
			}
		}
		if err != nil {
			g.Blockers = []string{err.Error()}
		}
		groups = append(groups, g)
	}
	return groups
}
