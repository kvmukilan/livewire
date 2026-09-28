package replay

import (
	"context"
	"errors"
	"fmt"
	"github.com/kvmukilan/livewire/internal/runstate"
	"net"
	"sort"
	"time"
)

// CheckRecovery runs only when a previous operation is uncertain. The probe
// uses a fresh, caller-authenticated connection and the same bounded framing.
func CheckRecovery(ctx context.Context, s *Session, a Adapter, vars map[string]string, timeout time.Duration, dial func(context.Context) (net.Conn, error), secure bool) (safe bool, completed *runstate.Result, retErr error) {
	exec := Execution(ctx)
	if exec.Journal == nil || exec.Scenario == nil {
		return false, nil, nil
	}
	key := fmt.Sprintf("%d/%s", exec.Attempt+1, s.ID)
	progress := exec.Journal.Progress()[key]
	if !progress.Uncertain {
		return false, nil, nil
	}
	var probe *RecoveryProbe
	for i := range exec.Scenario.Scenario.Recovery {
		p := &exec.Scenario.Scenario.Recovery[i]
		if p.Session == s.ID {
			probe = p
		}
	}
	if probe == nil {
		return false, nil, nil
	}
	if err := exec.Scenario.Scenario.ValidateSession(s, a); err != nil {
		return false, nil, err
	}
	client, server, err := TCPPayloadStreams(s)
	if err != nil {
		return false, nil, err
	}
	requests, err := a.Decode(ClientToServer, client)
	if err != nil {
		return false, nil, err
	}
	replies, err := DecodeWithContext(a, ServerToClient, server, requests)
	if err != nil {
		return false, nil, err
	}
	var finals []Message
	for _, r := range replies {
		if ConsumePeers(a, ServerToClient, []Message{r}, 1) > 0 {
			finals = append(finals, r)
		}
	}
	if len(finals) != len(requests) {
		return false, nil, fmt.Errorf("recovery requires one final response per captured request")
	}
	// Authentication setup is explicit. No other state-changing request may
	// execute while the original operation's outcome remains uncertain.
	var ordinals []int
	for _, step := range exec.Scenario.Scenario.Steps {
		if step.Session == s.ID && step.Setup && step.Request != probe.Request {
			ordinals = append(ordinals, step.Request)
		}
	}
	sort.Ints(ordinals)
	ordinals = append(ordinals, probe.Request)
	// Never wait for a business operation while probing its uncertain outcome.
	allowed := map[string]bool{}
	for _, ordinal := range ordinals {
		if step := exec.Scenario.step(s.ID, ordinal); step != nil {
			for _, dep := range step.DependsOn {
				if !allowed[dep] {
					return false, nil, fmt.Errorf("recovery setup/probe depends on a step outside fresh setup: %s", dep)
				}
			}
			allowed[step.ID] = true
		}
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dial(ctx)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		if e := conn.Close(); e != nil && !errors.Is(e, net.ErrClosed) {
			retErr = errors.Join(retErr, e)
			safe = false
			completed = nil
		}
	}()
	state := NewRuntimeState(vars)
	if secure {
		state.Protocol["http.scheme"] = "https"
	}
	var reader MessageReader
	for _, ordinal := range ordinals {
		request := requests[ordinal-1]
		if err := exec.Scenario.Before(ctx, s.ID, ordinal, state); err != nil {
			return false, nil, err
		}
		data, err := a.Prepare(ClientToServer, request, state)
		if err != nil {
			return false, nil, err
		}
		live, err := a.Decode(ClientToServer, data)
		if err != nil || len(live) != 1 {
			return false, nil, fmt.Errorf("invalid recovery request framing")
		}
		if err = Observe(a, ClientToServer, request, live[0], state); err != nil {
			return false, nil, err
		}
		if err = exec.Journal.Record(key, "intent", 0); err != nil {
			return false, nil, err
		}
		if err = WriteContext(ctx, conn, data, timeout); err != nil {
			return false, nil, err
		}
		var actual []Message
		for {
			actual, err = reader.Read(ctx, conn, a, ServerToClient, []Message{finals[ordinal-1]}, live, timeout)
			if err != nil {
				return false, nil, err
			}
			if ConsumePeers(a, ServerToClient, actual, 1) > 0 {
				break
			}
		}
		if err = Observe(a, ServerToClient, finals[ordinal-1], actual[0], state); err != nil {
			return false, nil, err
		}
		if actual[0].Fields["status"] != finals[ordinal-1].Fields["status"] {
			return false, nil, fmt.Errorf("recovery response status differs from the declared probe/setup response")
		}
		if ordinal != probe.Request {
			if err = exec.Scenario.After(s.ID, ordinal, a, actual[0]); err != nil {
				return false, nil, err
			}
			continue
		}
		extractor, ok := a.(FieldExtractor)
		if !ok {
			return false, nil, fmt.Errorf("recovery adapter cannot extract a target-state field")
		}
		value, err := extractor.ExtractField(actual[0], probe.Field)
		if err != nil {
			return false, nil, err
		}
		if value == probe.RestartValue {
			return true, nil, nil
		}
		if probe.CompleteValue != nil && value == *probe.CompleteValue {
			return false, &runstate.Result{Completed: true, Verified: false, Matched: false, Received: 1}, nil
		}
		return false, nil, fmt.Errorf("recovery probe did not establish a safe restart or completed target state")
	}
	return false, nil, fmt.Errorf("recovery probe did not execute")
}
