package lab

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/replay"
)

type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string such as 25ms")
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

type Scenario struct {
	Version int            `json:"version"`
	Seed    int64          `json:"seed"`
	Rules   []ScenarioRule `json:"rules,omitempty"`
}

type ScenarioRule struct {
	Name   string         `json:"name,omitempty"`
	Match  ScenarioMatch  `json:"match"`
	Action ScenarioAction `json:"action"`
}

type ScenarioMatch struct {
	Direction      string   `json:"direction,omitempty"`
	Session        string   `json:"session,omitempty"`
	Start          Duration `json:"start,omitempty"`
	End            Duration `json:"end,omitempty"`
	PacketIndexMin *int     `json:"packetIndexMin,omitempty"`
	PacketIndexMax *int     `json:"packetIndexMax,omitempty"`
}

type ScenarioAction struct {
	Delay     Duration `json:"delay,omitempty"`
	Jitter    Duration `json:"jitter,omitempty"`
	Drop      float64  `json:"drop,omitempty"`
	Duplicate int      `json:"duplicate,omitempty"`
	Reorder   int      `json:"reorder,omitempty"`
	RateBPS   int64    `json:"rateBps,omitempty"`
	MTU       int      `json:"mtu,omitempty"`
}

func LoadScenario(path string) (Scenario, error) {
	if path == "" {
		return Scenario{Version: 1, Seed: 1}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Scenario{}, err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	var s Scenario
	if err := dec.Decode(&s); err != nil {
		return Scenario{}, fmt.Errorf("scenario: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return Scenario{}, fmt.Errorf("scenario: trailing JSON value")
	}
	if err := s.Validate(); err != nil {
		return Scenario{}, err
	}
	return s, nil
}

func (s Scenario) Validate() error {
	if s.Version != 1 {
		return fmt.Errorf("scenario: version must be 1")
	}
	for i, r := range s.Rules {
		if r.Match.Direction != "" && r.Match.Direction != replay.ClientToServer.String() && r.Match.Direction != replay.ServerToClient.String() {
			return fmt.Errorf("scenario: rules[%d] has invalid direction", i)
		}
		if r.Match.Start.Duration < 0 || r.Match.End.Duration < 0 || (r.Match.End.Duration > 0 && r.Match.End.Duration < r.Match.Start.Duration) {
			return fmt.Errorf("scenario: rules[%d] has invalid time range", i)
		}
		a := r.Action
		if a.Delay.Duration < 0 || a.Jitter.Duration < 0 || a.Drop < 0 || a.Drop > 1 || a.Duplicate < 0 || a.Duplicate > 16 || a.Reorder < 0 || a.Reorder > 1024 || a.RateBPS < 0 || (a.MTU != 0 && a.MTU < 576) {
			return fmt.Errorf("scenario: rules[%d] has an invalid action", i)
		}
		if a.Delay.Duration == 0 && a.Jitter.Duration == 0 && a.Drop == 0 && a.Duplicate == 0 && a.Reorder == 0 && a.RateBPS == 0 && a.MTU == 0 {
			return fmt.Errorf("scenario: rules[%d] has no action", i)
		}
	}
	return nil
}

func (m ScenarioMatch) matches(session string, e replay.Event) bool {
	if m.Session != "" && m.Session != session {
		return false
	}
	if m.Direction != "" && m.Direction != e.Direction.String() {
		return false
	}
	if e.At < m.Start.Duration || (m.End.Duration > 0 && e.At > m.End.Duration) {
		return false
	}
	if m.PacketIndexMin != nil && e.PacketIndex < *m.PacketIndexMin || m.PacketIndexMax != nil && e.PacketIndex > *m.PacketIndexMax {
		return false
	}
	return true
}
