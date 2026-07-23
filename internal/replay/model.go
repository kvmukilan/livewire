// Package replay contains the transport-neutral capture model, replay planner,
// adapter contract, and shared live replay primitives.
package replay

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
)

type Direction uint8

const (
	DirectionUnknown Direction = iota
	ClientToServer
	ServerToClient
)

func (d Direction) String() string {
	switch d {
	case ClientToServer:
		return "client-to-server"
	case ServerToClient:
		return "server-to-client"
	default:
		return "unknown"
	}
}

type Transport string

const (
	TransportTCP   Transport = "tcp"
	TransportUDP   Transport = "udp"
	TransportICMP4 Transport = "icmp4"
	TransportICMP6 Transport = "icmp6"
	TransportRaw   Transport = "raw"
)

type Endpoint struct {
	IP   netip.Addr `json:"ip"`
	Port uint16     `json:"port,omitempty"`
}

func (e Endpoint) String() string {
	if e.Port == 0 {
		return e.IP.String()
	}
	return netip.AddrPortFrom(e.IP, e.Port).String()
}

type Event struct {
	PacketIndex int            `json:"packetIndex"`
	At          time.Duration  `json:"at"`
	Direction   Direction      `json:"direction"`
	Record      *pcapio.Record `json:"-"`
	Payload     []byte         `json:"-"`
	Fragmented  bool           `json:"fragmented,omitempty"`
	Reassembled []byte         `json:"-"`
}

type Session struct {
	ID         string    `json:"id"`
	Transport  Transport `json:"transport"`
	Client     Endpoint  `json:"client"`
	Server     Endpoint  `json:"server"`
	Events     []Event   `json:"events"`
	Fragmented bool      `json:"fragmented,omitempty"`
	Warnings   []string  `json:"warnings,omitempty"`
	Blockers   []string  `json:"blockers,omitempty"`
}

type Trace struct {
	Started  time.Time  `json:"started"`
	Packets  int        `json:"packets"`
	Sessions []*Session `json:"sessions"`
	Raw      []Event    `json:"raw"`
}

type Profile string

const (
	ProfileFunctional Profile = "functional"
	ProfileTiming     Profile = "timing"
	ProfileTransport  Profile = "transport"
	ProfileWire       Profile = "wire"
)

func ParseProfile(s string) (Profile, error) {
	p := Profile(strings.ToLower(strings.TrimSpace(s)))
	if p == "" {
		p = ProfileFunctional
	}
	switch p {
	case ProfileFunctional, ProfileTiming, ProfileTransport, ProfileWire:
		return p, nil
	default:
		return "", fmt.Errorf("unknown fidelity profile %q (use functional, timing, transport, or wire)", s)
	}
}

type Mode string

const (
	ModeSemantic Mode = "semantic"
	ModeStateful Mode = "stateful"
	ModeWire     Mode = "wire"
	ModeBlocked  Mode = "blocked"
)

type Fidelity string

const (
	FidelitySemantic  Fidelity = "semantic"
	FidelityTransport Fidelity = "transport"
	FidelityTiming    Fidelity = "timing"
	FidelityWire      Fidelity = "wire"
	FidelityBlocked   Fidelity = "blocked"
)

type PlanEntry struct {
	SessionID       string    `json:"sessionId"`
	Transport       Transport `json:"transport"`
	Driver          string    `json:"driver"`
	Adapter         string    `json:"adapter,omitempty"`
	Mode            Mode      `json:"mode"`
	Fidelity        Fidelity  `json:"fidelity"`
	PacketIndexes   []int     `json:"packetIndexes"`
	Transformations []string  `json:"transformations,omitempty"`
	Warnings        []string  `json:"warnings,omitempty"`
	Blockers        []string  `json:"blockers,omitempty"`
}

type ReplayPlan struct {
	Profile Profile     `json:"profile"`
	Packets int         `json:"packets"`
	Entries []PlanEntry `json:"entries"`
}

// ValidateCoverage proves that every capture packet is represented exactly once.
func (p ReplayPlan) ValidateCoverage() error {
	seen := make([]int, p.Packets)
	for _, e := range p.Entries {
		for _, idx := range e.PacketIndexes {
			if idx < 0 || idx >= p.Packets {
				return fmt.Errorf("plan entry %s references packet %d outside capture", e.SessionID, idx)
			}
			seen[idx]++
		}
	}
	for i, n := range seen {
		if n != 1 {
			return fmt.Errorf("packet %d is represented %d times", i, n)
		}
	}
	return nil
}

func (p ReplayPlan) Limitations() []string {
	var out []string
	add := func(value string) {
		for _, existing := range out {
			if existing == value {
				return
			}
		}
		out = append(out, value)
	}
	for _, entry := range p.Entries {
		for _, warning := range entry.Warnings {
			add(entry.SessionID + ": " + warning)
		}
		for _, blocker := range entry.Blockers {
			add(entry.SessionID + ": blocker: " + blocker)
		}
		if entry.Mode == ModeWire {
			add(entry.SessionID + ": wire replay does not claim live adaptation or response equivalence")
		}
	}
	return out
}

func packetIndexes(events []Event) []int {
	out := make([]int, len(events))
	for i := range events {
		out[i] = events[i].PacketIndex
	}
	sort.Ints(out)
	return out
}
