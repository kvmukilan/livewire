package replay

import (
	"fmt"
	"time"
)

type SessionPhase string

const (
	SessionConnecting SessionPhase = "connecting"
	SessionActive     SessionPhase = "active"
	SessionClosed     SessionPhase = "closed"
	SessionFailed     SessionPhase = "failed"
)

// Observer updates live protocol state independently of comparison policy.
// expected is the captured counterpart; actual is the live message. Observers
// are invoked only after successful correlation, and must not retain secrets
// in report fields. Each runtime owns its state exclusively.
type Observer interface {
	Observe(Direction, Message, Message, *RuntimeState) error
}

type Capabilities struct {
	Incremental bool   `json:"incremental"`
	Stateful    bool   `json:"stateful"`
	Recovery    string `json:"recovery"`
}

type CapabilityProvider interface{ Capabilities() Capabilities }

// IncrementalAdapter consumes complete frames, leaving the unfinished suffix
// with its caller. Malformed input must return an error, not need-more-data.
type IncrementalAdapter interface {
	DecodeAvailable(Direction, []byte, []Message, bool) ([]Message, int, error)
}

// StatefulIncrementalAdapter owns fragment assembly in the connection's state.
// Consuming bytes without returning a message is valid while assembling a
// fragmented message. Protocol replies belong in state.Pending; decoder state
// and queued replies must remain bounded.
type StatefulIncrementalAdapter interface {
	DecodeAvailableState(Direction, []byte, []Message, bool, *RuntimeState) ([]Message, int, error)
}

// MaintenanceAdapter schedules connection-level protocol work, such as MQTT
// keepalive. The connection loop calls it during idle and response waits and
// writes returned messages through the normal observation and journal path.
type MaintenanceAdapter interface {
	Maintenance(time.Time, *RuntimeState) ([]Message, time.Time, error)
}

// MaintenanceEventAdapter claims only responses to generated maintenance work,
// before those responses can be assigned to a captured application exchange.
type MaintenanceEventAdapter interface {
	MaintenanceEvent(Message, *RuntimeState) (bool, error)
}

// ConversationTurn retains application direction and capture timing after TCP
// sequence reconstruction, independently of packet or security record framing.
type ConversationTurn struct {
	Direction  Direction
	Payload    []byte
	At         time.Duration
	CloseWrite bool
	CloseAt    time.Duration
}

type ConversationNormalizer interface {
	NormalizeConversation([]ConversationTurn) ([]ConversationTurn, error)
}

func NormalizeConversation(adapter Adapter, turns []ConversationTurn) ([]ConversationTurn, error) {
	if normalizer, ok := adapter.(ConversationNormalizer); ok {
		return normalizer.NormalizeConversation(turns)
	}
	return turns, nil
}

func NewRuntimeState(vars map[string]string) *RuntimeState {
	return &RuntimeState{Variables: copyVariables(vars), Learned: map[string][]byte{},
		Protocol: map[string]any{}, Phase: SessionActive, Generation: 1}
}

func Observe(a Adapter, dir Direction, expected, actual Message, state *RuntimeState) error {
	if state == nil {
		return nil
	}
	if state.Protocol == nil {
		state.Protocol = map[string]any{}
	}
	if state.Learned == nil {
		state.Learned = map[string][]byte{}
	}
	if o, ok := a.(Observer); ok {
		return o.Observe(dir, expected, actual, state)
	}
	return nil
}

// ObserveResponse always learns state; verification only controls comparison.
func ObserveResponse(a Adapter, expected, actual Message, state *RuntimeState, mode VerifyMode) ([]Difference, error) {
	normalized, err := NormalizeExpected(a, ServerToClient, expected, state)
	if err != nil {
		return nil, err
	}
	match := a.Correlate(normalized, actual, state)
	if !match.Matched {
		return []Difference{{Field: "correlation", Expected: match.Key, Actual: match.Reason, Structural: true}},
			fmt.Errorf("%s: response cannot be correlated: %s", a.Name(), match.Reason)
	}
	if err := Observe(a, ServerToClient, expected, actual, state); err != nil {
		return nil, err
	}
	if mode == VerifyOff {
		return nil, nil
	}
	return a.Compare(normalized, actual, mode), nil
}
