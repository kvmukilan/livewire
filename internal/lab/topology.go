// Package lab coordinates two-sided replay through a device under test.
package lab

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/kvmukilan/livewire/internal/replay"
)

type Topology struct {
	Version  int               `json:"version"`
	Client   Side              `json:"client"`
	Server   Side              `json:"server"`
	Mappings []EndpointMapping `json:"mappings"`
}

type Side struct {
	Interface  string     `json:"interface"`
	Gateway    netip.Addr `json:"gateway,omitempty"`
	SourceMAC  string     `json:"sourceMac,omitempty"`
	NextHopMAC string     `json:"nextHopMac,omitempty"`
	VLAN       uint16     `json:"vlan,omitempty"`
	MTU        int        `json:"mtu,omitempty"`
}

type EndpointMapping struct {
	Role     string          `json:"role"` // client | server
	Captured replay.Endpoint `json:"captured"`
	Live     replay.Endpoint `json:"live"`
}

func LoadTopology(path string) (Topology, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Topology{}, err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	var t Topology
	if err := dec.Decode(&t); err != nil {
		return Topology{}, fmt.Errorf("topology: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return Topology{}, fmt.Errorf("topology: trailing JSON value")
	}
	if err := t.Validate(); err != nil {
		return Topology{}, err
	}
	return t, nil
}

func (t Topology) Validate() error {
	if t.Version != 1 {
		return fmt.Errorf("topology: version must be 1")
	}
	if t.Client.Interface == "" || t.Server.Interface == "" {
		return fmt.Errorf("topology: client.interface and server.interface are required")
	}
	if t.Client.Interface == t.Server.Interface {
		return fmt.Errorf("topology: client and server interfaces must differ")
	}
	if err := validateSide("client", t.Client); err != nil {
		return err
	}
	if err := validateSide("server", t.Server); err != nil {
		return err
	}
	if len(t.Mappings) < 2 {
		return fmt.Errorf("topology: at least one client and one server mapping are required")
	}
	hasClient, hasServer := false, false
	for i, m := range t.Mappings {
		if m.Role != "client" && m.Role != "server" {
			return fmt.Errorf("topology: mappings[%d].role must be client or server", i)
		}
		if !m.Captured.IP.IsValid() || !m.Live.IP.IsValid() {
			return fmt.Errorf("topology: mappings[%d] needs valid captured and live IPs", i)
		}
		if m.Captured.IP.Is4() != m.Live.IP.Is4() {
			return fmt.Errorf("topology: mappings[%d] changes address family", i)
		}
		side := t.Client
		if m.Role == "server" {
			side = t.Server
		}
		if side.Gateway.IsValid() && side.Gateway.Is4() != m.Live.IP.Is4() {
			return fmt.Errorf("topology: mappings[%d] live address and %s gateway use different address families", i, m.Role)
		}
		for previous := 0; previous < i; previous++ {
			other := t.Mappings[previous]
			if other.Role != m.Role || other.Captured.IP != m.Captured.IP {
				continue
			}
			if other.Captured.Port == 0 || m.Captured.Port == 0 || other.Captured.Port == m.Captured.Port {
				return fmt.Errorf("topology: mappings[%d] overlaps mappings[%d] for captured %s endpoint", i, previous, m.Role)
			}
		}
		hasClient = hasClient || m.Role == "client"
		hasServer = hasServer || m.Role == "server"
	}
	if !hasClient || !hasServer {
		return fmt.Errorf("topology: both client and server roles must be mapped")
	}
	return nil
}

func validateSide(name string, s Side) error {
	if s.VLAN > 4094 {
		return fmt.Errorf("topology: %s VLAN must be 0..4094", name)
	}
	if s.MTU != 0 && s.MTU < 576 {
		return fmt.Errorf("topology: %s MTU must be at least 576", name)
	}
	if s.Gateway.IsValid() && (s.Gateway.IsUnspecified() || s.Gateway.IsMulticast()) {
		return fmt.Errorf("topology: %s.gateway must be a unicast address", name)
	}
	for label, value := range map[string]string{"sourceMac": s.SourceMAC, "nextHopMac": s.NextHopMAC} {
		if value == "" {
			continue
		}
		mac, err := net.ParseMAC(value)
		if err != nil || len(mac) != 6 {
			return fmt.Errorf("topology: %s.%s is not a six-byte MAC", name, label)
		}
	}
	return nil
}

func (t Topology) Map(role string, captured replay.Endpoint) (replay.Endpoint, bool) {
	for _, m := range t.Mappings {
		if m.Role != role || m.Captured.IP != captured.IP {
			continue
		}
		if m.Captured.Port != 0 && m.Captured.Port != captured.Port {
			continue
		}
		live := m.Live
		if live.Port == 0 {
			live.Port = captured.Port
		}
		return live, true
	}
	return replay.Endpoint{}, false
}

func (t Topology) ValidateTrace(trace *replay.Trace) error {
	for _, s := range trace.Sessions {
		if _, ok := t.Map("client", s.Client); !ok {
			return fmt.Errorf("topology: no client mapping for %s (%s)", s.Client, s.ID)
		}
		if _, ok := t.Map("server", s.Server); !ok {
			return fmt.Errorf("topology: no server mapping for %s (%s)", s.Server, s.ID)
		}
	}
	return nil
}
