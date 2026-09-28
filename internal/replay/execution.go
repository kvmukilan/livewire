package replay

import (
	"context"
	"fmt"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/runstate"
)

type ExecutionConfig struct {
	Concurrency int
	Attempt     int
	Journal     *runstate.Store
	SessionKey  string
	Scenario    *ScenarioRuntime
	Evidence    func(pcapio.Record) error
}
type executionKey struct{}

func WithExecution(ctx context.Context, config ExecutionConfig) context.Context {
	return context.WithValue(ctx, executionKey{}, config)
}

// BeginSession supplies an isolated journal namespace for this attempt/session.
func BeginSession(ctx context.Context, id string, restartSafe bool) (context.Context, *runstate.Result, error) {
	c := Execution(ctx)
	if c.Journal == nil {
		return ctx, nil, nil
	}
	c.SessionKey = fmt.Sprintf("%d/%s", c.Attempt+1, id)
	r, e := c.Journal.Begin(c.SessionKey, restartSafe)
	if e == nil && r != nil && c.Scenario != nil && c.Scenario.HasSession(id) {
		if !restartSafe {
			return WithExecution(ctx, c), nil, fmt.Errorf("resume requires fresh scenario state for %s, but this session contains operations without a safe restart contract", id)
		}
		e = c.Journal.Restart(c.SessionKey)
		r = nil
	}
	return WithExecution(ctx, c), r, e
}
func RecordOperation(ctx context.Context, kind string, index int) error {
	c := Execution(ctx)
	if c.Journal == nil {
		return nil
	}
	return c.Journal.Record(c.SessionKey, kind, index)
}
func FinishSession(ctx context.Context, result runstate.Result) error {
	c := Execution(ctx)
	if c.Journal == nil {
		return nil
	}
	return c.Journal.Finish(c.SessionKey, result)
}

type RecoveryAdapter interface{ RestartSafe(Message) bool }

func SessionRestartSafe(a Adapter, s *Session) bool {
	r, ok := a.(RecoveryAdapter)
	if !ok || s == nil {
		return false
	}
	client, _, err := TCPPayloadStreams(s)
	if err != nil {
		return false
	}
	messages, err := a.Decode(ClientToServer, client)
	if err != nil || len(messages) == 0 {
		return false
	}
	for _, m := range messages {
		if !r.RestartSafe(m) {
			return false
		}
	}
	return true
}

func ScenarioRestartSafe(a Adapter, s *Session, scenario *Scenario) bool {
	if scenario == nil {
		return SessionRestartSafe(a, s)
	}
	r, ok := a.(RecoveryAdapter)
	if !ok || s == nil {
		return false
	}
	client, _, err := TCPPayloadStreams(s)
	if err != nil {
		return false
	}
	messages, err := a.Decode(ClientToServer, client)
	if err != nil || len(messages) == 0 {
		return false
	}
	for i, m := range messages {
		if r.RestartSafe(m) {
			continue
		}
		setup := false
		for _, step := range scenario.Steps {
			if step.Session == s.ID && step.Request == i+1 && step.Setup {
				setup = true
			}
		}
		if !setup {
			return false
		}
	}
	return true
}
func Execution(ctx context.Context) ExecutionConfig {
	if ctx == nil {
		return ExecutionConfig{Concurrency: 32}
	}
	c, _ := ctx.Value(executionKey{}).(ExecutionConfig)
	if c.Concurrency <= 0 {
		c.Concurrency = 32
	}
	return c
}
