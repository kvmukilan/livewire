package replay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// WriteStateContext records actual wire activity for connection maintenance.
// Protocol observation and durable intent remain the caller's responsibility.
func WriteStateContext(ctx context.Context, conn net.Conn, data []byte, state *RuntimeState, timeout time.Duration) error {
	if err := WriteContext(ctx, conn, data, timeout); err != nil {
		return err
	}
	if state != nil && len(data) > 0 {
		state.LastWrite = time.Now()
	}
	return nil
}

func (r *MessageReader) writeControl(ctx context.Context, conn net.Conn, a Adapter, messages []Message, state *RuntimeState, timeout time.Duration) error {
	if len(messages) > 128 || expectedBytes(messages) > maxSemanticFrame {
		return fmt.Errorf("resource limit: excessive queued protocol control messages")
	}
	deadline := time.Now().Add(timeout)
	for _, message := range messages {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return context.DeadlineExceeded
		}
		if err := Observe(a, ClientToServer, message, message, state); err != nil {
			return err
		}
		if err := RecordOperation(ctx, "intent", 0); err != nil {
			return err
		}
		if err := WriteStateContext(ctx, conn, message.Raw, state, remaining); err != nil {
			return err
		}
	}
	return nil
}

func (r *MessageReader) drainControl(ctx context.Context, conn net.Conn, a Adapter, state *RuntimeState, timeout time.Duration) error {
	if state == nil || len(state.Pending) == 0 {
		return nil
	}
	queued := state.Pending
	state.Pending = nil
	return r.writeControl(ctx, conn, a, queued, state, timeout)
}

func (r *MessageReader) maintain(ctx context.Context, conn net.Conn, a Adapter, state *RuntimeState, timeout time.Duration) (time.Time, error) {
	if state == nil {
		return time.Time{}, nil
	}
	if err := r.drainControl(ctx, conn, a, state, timeout); err != nil {
		return time.Time{}, err
	}
	m, ok := a.(MaintenanceAdapter)
	if !ok {
		return time.Time{}, nil
	}
	messages, next, err := m.Maintenance(time.Now(), state)
	if err != nil {
		return next, err
	}
	if err := r.writeControl(ctx, conn, a, messages, state, timeout); err != nil {
		return next, err
	}
	return next, nil
}

func maintenanceEvent(a Adapter, message Message, state *RuntimeState) (bool, error) {
	if state != nil {
		if m, ok := a.(MaintenanceEventAdapter); ok {
			return m.MaintenanceEvent(message, state)
		}
	}
	return false, nil
}

func (r *MessageReader) handleLiveEvent(ctx context.Context, conn net.Conn, a Adapter, message Message, state *RuntimeState, timeout time.Duration) (bool, error) {
	events, ok := a.(LiveEventAdapter)
	if !ok || state == nil {
		return false, nil
	}
	replies, handled, err := events.LiveEvent(message, state)
	if err != nil || !handled {
		return handled, err
	}
	state.Transformations = append(state.Transformations, a.Name()+": additional live event observed; payload not compared to capture")
	if len(state.Transformations) > 4096 {
		return true, fmt.Errorf("resource limit: excessive live protocol events")
	}
	return true, r.writeControl(ctx, conn, a, replies, state, timeout)
}

func (r *MessageReader) retain(message Message) error {
	if len(r.pending) >= 128 || expectedBytes(r.pending)+len(message.Raw) > maxSemanticFrame {
		return fmt.Errorf("resource limit: excessive unmatched protocol responses")
	}
	r.pending = append(r.pending, message)
	return nil
}

// WaitUntil keeps one connection alive during capture pacing. The same reader
// owns every byte: expected early responses remain queued, unsolicited protocol
// messages are serviced, and partial frames survive the end of the wait.
// expected contains future captured responses that must retain their identity.
func (r *MessageReader) WaitUntil(ctx context.Context, conn net.Conn, a Adapter, expected, peers []Message, state *RuntimeState, target time.Time, timeout time.Duration) error {
	// A completed protocol shutdown has no remaining traffic to maintain. The
	// peer may close immediately (for example after MQTT DISCONNECT), before
	// the captured TCP FIN timestamp. Preserve that final delay without
	// requiring a response that the protocol does not send.
	if state != nil && state.Phase == SessionClosed && len(expected) == 0 {
		waitWallUntil(ctx, target)
		return ctx.Err()
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	for time.Now().Before(target) {
		if err := ctx.Err(); err != nil {
			return err
		}
		messages, err := r.read(ctx, conn, a, ServerToClient, []Message{{}}, peers, state, time.Until(target), timeout)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, context.DeadlineExceeded) && !time.Now().Before(target) {
				return nil
			}
			if errors.Is(err, io.ErrUnexpectedEOF) && r.eof && len(r.buffer) == 0 && len(r.pending) > 0 {
				if !waitWallUntil(ctx, target) {
					return ctx.Err()
				}
				return nil
			}
			return err
		}
		message := messages[0]
		if handled, err := maintenanceEvent(a, message, state); handled || err != nil {
			if err != nil {
				return err
			}
			continue
		}
		reserved := false
		for _, captured := range expected {
			normalized, err := NormalizeExpected(a, ServerToClient, captured, state)
			if err != nil {
				// A future request may not yet have supplied its bindings. Keep
				// this response until that request's normal correlation step.
				reserved = true
				break
			}
			if keyed, ok := a.(KeyedResponses); ok {
				reserved = keyed.ResponseKey(normalized) == keyed.ResponseKey(message)
			} else {
				reserved = a.Correlate(normalized, message, state).Matched
			}
			if reserved {
				break
			}
		}
		if !reserved {
			handled, err := r.handleLiveEvent(ctx, conn, a, message, state, timeout)
			if err != nil {
				return err
			}
			if handled {
				continue
			}
		}
		if err := r.retain(message); err != nil {
			return err
		}
	}
	return ctx.Err()
}
