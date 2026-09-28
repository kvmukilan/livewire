package replay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// MessageReader belongs to one connection. Bytes beyond a response boundary
// remain buffered for the next operation, including partial following frames.
type MessageReader struct {
	buffer  []byte
	eof     bool
	decoded []Message
	pending []Message
}

// LiveEventAdapter handles additional peer-originated protocol messages without
// assigning them to a captured response. Any generated acknowledgement is sent
// through the same bounded writer and durable intent path.
type LiveEventAdapter interface {
	LiveEvent(Message, *RuntimeState) ([]Message, bool, error)
}

func (r *MessageReader) ReadExchange(ctx context.Context, conn net.Conn, a Adapter, expected, peers []Message, state *RuntimeState, timeout time.Duration) ([]Message, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)
	var out []Message
	remaining := append([]Message(nil), expected...)
	keyed, unordered := a.(KeyedResponses)
	for len(remaining) > 0 {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		index := func(m Message) (int, error) {
			for i, w := range remaining {
				n, e := NormalizeExpected(a, ServerToClient, w, state)
				if e != nil {
					return -1, e
				}
				if unordered {
					if keyed.ResponseKey(n) == keyed.ResponseKey(m) {
						return i, nil
					}
				} else if a.Correlate(n, m, state).Matched {
					return i, nil
				}
				if !unordered {
					break
				}
			}
			return -1, nil
		}
		var next Message
		found := false
		for i, m := range r.pending {
			match, err := index(m)
			if err != nil {
				return out, err
			}
			if match >= 0 {
				next = m
				r.pending = append(r.pending[:i], r.pending[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			left := time.Until(deadline)
			if left <= 0 {
				return out, &ResponseReadError{Err: context.DeadlineExceeded}
			}
			msgs, e := r.read(ctx, conn, a, ServerToClient, remaining[:1], peers, state, left, left)
			if e != nil {
				var readError *peerReadError
				if errors.As(e, &readError) {
					e = &ResponseReadError{Err: readError.err}
				}
				return out, e
			}
			next = msgs[0]
		}
		if handled, err := maintenanceEvent(a, next, state); handled || err != nil {
			if err != nil {
				return out, err
			}
			continue
		}
		i, err := index(next)
		if err != nil {
			return out, err
		}
		if i >= 0 {
			out = append(out, next)
			remaining = append(remaining[:i], remaining[i+1:]...)
			if n := ConsumePeers(a, ServerToClient, []Message{next}, len(peers)); n > 0 {
				peers = peers[n:]
			}
			continue
		}
		if handled, err := r.handleLiveEvent(ctx, conn, a, next, state, time.Until(deadline)); handled || err != nil {
			if err != nil {
				return out, err
			}
			continue
		}
		if !unordered {
			return append(out, next), nil
		} // caller reports the precise correlation failure
		if err := r.retain(next); err != nil {
			return out, err
		}
		state.Transformations = append(state.Transformations, a.Name()+": unmatched or early response retained for correlation")
	}
	return out, nil
}

func (r *MessageReader) Read(ctx context.Context, conn net.Conn, adapter Adapter, dir Direction, expected, peers []Message, timeout time.Duration) ([]Message, error) {
	return r.read(ctx, conn, adapter, dir, expected, peers, nil, timeout, timeout)
}

func (r *MessageReader) read(ctx context.Context, conn net.Conn, adapter Adapter, dir Direction, expected, peers []Message, state *RuntimeState, timeout, controlTimeout time.Duration) ([]Message, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(expected) == 0 {
		return nil, nil
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)
	controlBudget := func() time.Duration {
		remaining := time.Until(deadline)
		if controlTimeout > 0 && controlTimeout < remaining {
			return controlTimeout
		}
		return remaining
	}
	var out []Message
	if len(r.decoded) > 0 {
		n := len(r.decoded)
		if n > len(expected) {
			n = len(expected)
		}
		out = append(out, r.decoded[:n]...)
		r.decoded = r.decoded[n:]
		if len(out) == len(expected) {
			return out, nil
		}
	}
	tmp := make([]byte, 16*1024)
	incremental, hasIncremental := adapter.(IncrementalAdapter)
	stateful, hasStateful := adapter.(StatefulIncrementalAdapter)
	hasStateful = hasStateful && state != nil
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if hasIncremental || hasStateful {
			for len(r.buffer) > 0 {
				remainingPeers := peers[ConsumePeers(adapter, dir, out, len(peers)):]
				var msgs []Message
				var n int
				var err error
				if hasStateful {
					msgs, n, err = stateful.DecodeAvailableState(dir, r.buffer, remainingPeers, r.eof, state)
				} else {
					msgs, n, err = incremental.DecodeAvailable(dir, r.buffer, remainingPeers, r.eof)
				}
				if err != nil {
					return out, err
				}
				if err := r.drainControl(ctx, conn, adapter, state, controlBudget()); err != nil {
					return out, err
				}
				if n == 0 {
					if len(msgs) != 0 {
						return out, fmt.Errorf("%s: decoder returned messages without consuming bytes", adapter.Name())
					}
					break
				}
				if n < 0 || n > len(r.buffer) || len(msgs) == 0 && !hasStateful {
					return out, fmt.Errorf("%s: invalid incremental decoder result", adapter.Name())
				}
				r.buffer = r.buffer[n:]
				out = append(out, msgs...)
				if len(out) >= len(expected) {
					r.decoded = append(r.decoded, out[len(expected):]...)
					return out[:len(expected)], nil
				}
			}
		} else if len(r.buffer) > 0 {
			msgs, err := DecodeWithContext(adapter, dir, r.buffer, peers)
			if err == nil && (!adapterRequiresEOF(adapter, dir, msgs) || r.eof) && len(msgs) >= len(expected) {
				taken := msgs[:len(expected)]
				n := expectedBytes(taken)
				if n > len(r.buffer) {
					return nil, fmt.Errorf("%s: invalid decoded length", adapter.Name())
				}
				r.buffer = r.buffer[n:]
				return taken, nil
			}
			if r.eof && err != nil {
				return out, err
			}
		}
		if r.eof {
			return out, &peerReadError{err: io.ErrUnexpectedEOF}
		}
		if !time.Now().Before(deadline) {
			return out, &peerReadError{err: fmt.Errorf("%s: response timed out: %w", adapter.Name(), context.DeadlineExceeded)}
		}
		nextMaintenance, err := r.maintain(ctx, conn, adapter, state, controlBudget())
		if err != nil {
			return out, err
		}
		step := time.Now().Add(100 * time.Millisecond)
		if step.After(deadline) {
			step = deadline
		}
		if !nextMaintenance.IsZero() && nextMaintenance.Before(step) {
			step = nextMaintenance
		}
		if err := conn.SetReadDeadline(step); err != nil && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
			return out, err
		}
		n, err := conn.Read(tmp)
		if n > 0 {
			if state != nil {
				state.LastRead = time.Now()
			}
			if len(r.buffer)+n > maxSemanticFrame {
				return out, fmt.Errorf("%s: response exceeds %d bytes", adapter.Name(), maxSemanticFrame)
			}
			r.buffer = append(r.buffer, tmp[:n]...)
		}
		if errors.Is(err, io.EOF) {
			r.eof = true
		} else if err != nil {
			if ctx.Err() != nil {
				return out, ctx.Err()
			}
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				return out, &peerReadError{err: err}
			}
		}
	}
}

// WriteContext handles short writes without losing bytes and never busy-loops
// on a broken writer returning (0, nil).
func WriteContext(ctx context.Context, conn net.Conn, data []byte, timeout time.Duration) error {
	return writeContext(ctx, conn, data, timeout)
}
