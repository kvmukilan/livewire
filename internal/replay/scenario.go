package replay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

// Scenario names application dependencies explicitly; it never guesses token
// semantics or executes shell commands. Values extracted from live replies stay
// in memory and are reacquired on resume.
type Scenario struct {
	Version       int             `json:"version"`
	CaptureDigest string          `json:"captureDigest"`
	Steps         []ScenarioStep  `json:"steps"`
	Recovery      []RecoveryProbe `json:"recovery,omitempty"`
}

// RecoveryProbe is an operator-declared contract for the target: a scalar
// value proves either that replay may restart, or that its intended effects
// are already complete. Completion by a probe does not verify captured replies.
type RecoveryProbe struct {
	Session       string     `json:"session"`
	Request       int        `json:"request"`
	Field         Extraction `json:"field"`
	RestartValue  string     `json:"restartValue"`
	CompleteValue *string    `json:"completeValue,omitempty"`
}
type ScenarioStep struct {
	ID        string            `json:"id"`
	Session   string            `json:"session"`
	Request   int               `json:"request"`
	DependsOn []string          `json:"dependsOn,omitempty"`
	Extract   []Extraction      `json:"extract,omitempty"`
	Set       map[string]string `json:"set,omitempty"`
	Setup     bool              `json:"setup,omitempty"`
	Compare   *ComparisonPolicy `json:"compare,omitempty"`
}

type ComparisonPolicy struct {
	Headers       []string `json:"headers,omitempty"`
	NormalizeJSON bool     `json:"normalizeJSON,omitempty"`
	IgnoreJSON    []string `json:"ignoreJSON,omitempty"`
}
type PolicyComparator interface {
	ComparePolicy(Message, Message, VerifyMode, ComparisonPolicy) []Difference
}
type Extraction struct {
	Name        string  `json:"name"`
	Header      string  `json:"header,omitempty"`
	JSONPointer *string `json:"jsonPointer,omitempty"`
}
type FieldExtractor interface {
	ExtractField(Message, Extraction) (string, error)
}

func ParseScenario(data []byte, digest string) (*Scenario, error) {
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("scenario exceeds 1 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var s Scenario
	if err := d.Decode(&s); err != nil {
		return nil, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, fmt.Errorf("scenario has trailing JSON")
	}
	if s.Version != 1 || s.CaptureDigest != digest {
		return nil, fmt.Errorf("scenario version or capture digest mismatch")
	}
	if len(s.Steps) > 1024 {
		return nil, fmt.Errorf("scenario exceeds 1024 steps")
	}
	probeSessions := map[string]bool{}
	for _, p := range s.Recovery {
		if p.Session == "" || p.Request < 1 || p.RestartValue == "" || (p.Field.Header == "") == (p.Field.JSONPointer == nil) || probeSessions[p.Session] || p.CompleteValue != nil && *p.CompleteValue == p.RestartValue {
			return nil, fmt.Errorf("invalid or ambiguous recovery probe")
		}
		probeSessions[p.Session] = true
	}
	ids := map[string]ScenarioStep{}
	selectors := map[string]bool{}
	names := map[string]string{}
	for _, step := range s.Steps {
		if step.Compare != nil {
			for _, path := range step.Compare.IgnoreJSON {
				if path == "" || !strings.HasPrefix(path, "/") {
					return nil, fmt.Errorf("ignored JSON pointer must name a field")
				}
			}
		}
		if step.ID == "" || step.Session == "" || step.Request < 1 {
			return nil, fmt.Errorf("scenario steps need id, session and positive request ordinal")
		}
		key := fmt.Sprintf("%s/%d", step.Session, step.Request)
		if _, ok := ids[step.ID]; ok || selectors[key] {
			return nil, fmt.Errorf("duplicate or ambiguous scenario step %s", step.ID)
		}
		ids[step.ID] = step
		selectors[key] = true
		for _, e := range step.Extract {
			if e.Name == "" || (e.Header == "") == (e.JSONPointer == nil) || names[e.Name] != "" {
				return nil, fmt.Errorf("invalid or ambiguous extraction in %s", step.ID)
			}
			names[e.Name] = step.ID
		}
	}
	marks := map[string]int{}
	var visit func(string) error
	visit = func(id string) error {
		if marks[id] == 1 {
			return fmt.Errorf("scenario dependency cycle at %s", id)
		}
		if marks[id] == 2 {
			return nil
		}
		step, ok := ids[id]
		if !ok {
			return fmt.Errorf("missing scenario dependency %s", id)
		}
		marks[id] = 1
		for _, dep := range step.DependsOn {
			if err := visit(dep); err != nil {
				return err
			}
		}
		// The capture's own request order is also a dependency.
		for _, previous := range s.Steps {
			if previous.Session == step.Session && previous.Request < step.Request {
				if err := visit(previous.ID); err != nil {
					return err
				}
			}
		}
		marks[id] = 2
		return nil
	}
	for id := range ids {
		if err := visit(id); err != nil {
			return nil, err
		}
	}
	var depends func(string, string) bool
	depends = func(id, source string) bool {
		for _, dep := range ids[id].DependsOn {
			if dep == source || depends(dep, source) {
				return true
			}
		}
		return false
	}
	for _, step := range s.Steps {
		for _, value := range step.Set {
			for _, name := range templateNames(value) {
				source := names[name]
				if source == "" {
					return nil, fmt.Errorf("missing producer for scenario binding %s", name)
				}
				p := ids[source]
				if !(p.Session == step.Session && p.Request < step.Request) && !depends(step.ID, source) {
					return nil, fmt.Errorf("binding %s requires a dependency on %s", name, source)
				}
			}
		}
	}
	return &s, nil
}
func templateNames(s string) []string {
	var out []string
	for {
		a := strings.Index(s, "${")
		if a < 0 {
			return out
		}
		s = s[a+2:]
		b := strings.IndexByte(s, '}')
		if b < 0 {
			return append(out, "")
		}
		out = append(out, s[:b])
		s = s[b+1:]
	}
}

func (s *Scenario) ValidateTrace(t *Trace, r *Registry) error {
	byID := map[string]*Session{}
	for _, session := range t.Sessions {
		byID[session.ID] = session
	}
	for _, step := range s.Steps {
		session := byID[step.Session]
		if session == nil {
			return fmt.Errorf("scenario session %s is not selected", step.Session)
		}
		a, _ := r.Best(*session)
		if a == nil {
			return fmt.Errorf("scenario requires an application adapter")
		}
		if a.Name() == "tls-reterminate" {
			continue
		} // checked after decryption, before handshake
		if err := s.ValidateSession(session, a); err != nil {
			return err
		}
	}
	for _, probe := range s.Recovery {
		session := byID[probe.Session]
		if session == nil {
			return fmt.Errorf("recovery probe references an unselected session")
		}
		a, _ := r.Best(*session)
		if a == nil {
			return fmt.Errorf("recovery probe requires an application adapter")
		}
		if a.Name() != "tls-reterminate" {
			if err := s.ValidateSession(session, a); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Scenario) ValidateSession(session *Session, a Adapter) error {
	if s == nil {
		return nil
	}
	var relevant []ScenarioStep
	for _, step := range s.Steps {
		if step.Session == session.ID {
			relevant = append(relevant, step)
		}
	}
	var probe *RecoveryProbe
	for i := range s.Recovery {
		if s.Recovery[i].Session == session.ID {
			probe = &s.Recovery[i]
		}
	}
	if len(relevant) == 0 && probe == nil {
		return nil
	}
	if a == nil || a.Name() != "http/1" {
		return fmt.Errorf("scenario bindings currently require HTTP/1 framing")
	}
	client, _, err := TCPPayloadStreams(session)
	if err != nil {
		return err
	}
	messages, err := a.Decode(ClientToServer, client)
	if err != nil {
		return err
	}
	if probe != nil {
		recovery, ok := a.(RecoveryAdapter)
		if !ok || probe.Request > len(messages) || !recovery.RestartSafe(messages[probe.Request-1]) {
			return fmt.Errorf("recovery probe must select a protocol-defined read-only request")
		}
	}
	for _, step := range relevant {
		if step.Request > len(messages) {
			return fmt.Errorf("scenario step %s references a missing request", step.ID)
		}
	}
	turns, err := semanticTurns(session)
	if err != nil {
		return err
	}
	requests, replies := 0, 0
	producers := map[string]ScenarioStep{}
	for _, step := range s.Steps {
		for _, extraction := range step.Extract {
			producers[extraction.Name] = step
		}
	}
	var peers []Message
	for _, turn := range turns {
		if len(turn.data) == 0 {
			continue
		}
		msgs, e := DecodeWithContext(a, turn.dir, turn.data, peers)
		if e != nil {
			return e
		}
		if turn.dir == ClientToServer {
			for range msgs {
				requests++
				for _, step := range relevant {
					if step.Request != requests {
						continue
					}
					for _, value := range step.Set {
						for _, name := range templateNames(value) {
							source, ok := producers[name]
							if ok && source.Session == session.ID && source.Request > replies {
								return fmt.Errorf("scenario %s binding %s requires a reply before a captured pipelined request; serialize the dependent capture requests", step.ID, name)
							}
						}
					}
					for _, dep := range step.DependsOn {
						for _, source := range relevant {
							if source.ID == dep && source.Request > replies {
								return fmt.Errorf("scenario %s requires a reply before a captured pipelined request; capture dependency cannot be satisfied", step.ID)
							}
						}
					}
				}
			}
			peers = append(peers, msgs...)
		} else {
			n := ConsumePeers(a, turn.dir, msgs, len(peers))
			replies += n
			peers = peers[n:]
		}
	}
	return nil
}

type ScenarioRuntime struct {
	Scenario  *Scenario
	mu        sync.Mutex
	values    map[string]string
	completed map[string]bool
	failed    map[string]bool
	changed   chan struct{}
}

func NewScenarioRuntime(s *Scenario) *ScenarioRuntime {
	if s == nil {
		return nil
	}
	return &ScenarioRuntime{Scenario: s, values: map[string]string{}, completed: map[string]bool{}, failed: map[string]bool{}, changed: make(chan struct{})}
}

func (s *ScenarioRuntime) HasSession(id string) bool {
	if s == nil {
		return false
	}
	for _, step := range s.Scenario.Steps {
		if step.Session == id {
			return true
		}
	}
	return false
}
func (s *ScenarioRuntime) step(session string, ordinal int) *ScenarioStep {
	for i := range s.Scenario.Steps {
		v := &s.Scenario.Steps[i]
		if v.Session == session && v.Request == ordinal {
			return v
		}
	}
	return nil
}
func (s *ScenarioRuntime) Before(ctx context.Context, session string, ordinal int, state *RuntimeState) error {
	if s == nil {
		return nil
	}
	step := s.step(session, ordinal)
	if step == nil {
		return nil
	}
	for {
		s.mu.Lock()
		ready := true
		for _, dep := range step.DependsOn {
			if s.failed[dep] {
				s.mu.Unlock()
				return fmt.Errorf("scenario prerequisite %s failed", dep)
			}
			ready = ready && s.completed[dep]
		}
		if ready {
			if step.Compare != nil {
				if step.Compare.NormalizeJSON {
					state.Transformations = append(state.Transformations, "http: declared JSON normalization")
				}
				for _, path := range step.Compare.IgnoreJSON {
					state.Transformations = append(state.Transformations, "http: declared ignored JSON pointer "+path)
				}
				for _, header := range step.Compare.Headers {
					state.Transformations = append(state.Transformations, "http: declared compared header "+header)
				}
			}
			for key, value := range step.Set {
				for _, name := range templateNames(value) {
					v, ok := s.values[name]
					if !ok {
						s.mu.Unlock()
						return fmt.Errorf("scenario binding %s is unavailable", name)
					}
					value = strings.ReplaceAll(value, "${"+name+"}", v)
				}
				state.Variables[key] = value
				state.Transformations = append(state.Transformations, "scenario: substituted "+key+" for step "+step.ID)
			}
			s.mu.Unlock()
			return nil
		}
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}
func (s *ScenarioRuntime) After(session string, ordinal int, a Adapter, m Message) error {
	if s == nil {
		return nil
	}
	step := s.step(session, ordinal)
	if step == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	values := map[string]string{}
	for _, e := range step.Extract {
		extractor, ok := a.(FieldExtractor)
		if !ok {
			return fmt.Errorf("adapter cannot extract scenario fields")
		}
		v, err := extractor.ExtractField(m, e)
		if err != nil {
			return fmt.Errorf("scenario extraction %s failed: %w", e.Name, err)
		}
		values[e.Name] = v
	}
	for k, v := range values {
		s.values[k] = v
	}
	s.completed[step.ID] = true
	close(s.changed)
	s.changed = make(chan struct{})
	return nil
}
func (s *ScenarioRuntime) End(session string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, step := range s.Scenario.Steps {
		if step.Session == session && !s.completed[step.ID] {
			s.failed[step.ID] = true
		}
	}
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *ScenarioRuntime) Compare(session string, ordinal int, a Adapter, w, g Message, mode VerifyMode) []Difference {
	if mode == VerifyOff {
		return nil
	}
	if s != nil {
		if step := s.step(session, ordinal); step != nil && step.Compare != nil {
			if compare, ok := a.(PolicyComparator); ok {
				return compare.ComparePolicy(w, g, mode, *step.Compare)
			}
		}
	}
	return a.Compare(w, g, mode)
}

// Order returns a stable topological session ordering for bounded scheduling.
// Cycles between sessions cannot be executed by sequential functional replay.
func (s *Scenario) Order(entries []PlanEntry) ([]PlanEntry, error) {
	if s == nil {
		return entries, nil
	}
	deps := map[string]map[string]bool{}
	steps := map[string]ScenarioStep{}
	for _, v := range s.Steps {
		steps[v.ID] = v
	}
	for _, v := range s.Steps {
		for _, d := range v.DependsOn {
			src := steps[d].Session
			if src != v.Session {
				if deps[v.Session] == nil {
					deps[v.Session] = map[string]bool{}
				}
				deps[v.Session][src] = true
			}
		}
	}
	done := map[string]bool{}
	out := make([]PlanEntry, 0, len(entries))
	for len(out) < len(entries) {
		advanced := false
		for _, e := range entries {
			if done[e.SessionID] {
				continue
			}
			ready := true
			for dep := range deps[e.SessionID] {
				ready = ready && done[dep]
			}
			if ready {
				done[e.SessionID] = true
				out = append(out, e)
				advanced = true
			}
		}
		if !advanced {
			return nil, fmt.Errorf("scenario contains a session dependency cycle or unselected dependency")
		}
	}
	return out, nil
}
func (s *ScenarioRuntime) SecretValues() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, v := range s.values {
		if v != "" {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
