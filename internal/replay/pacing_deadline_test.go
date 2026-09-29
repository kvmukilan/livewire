package replay

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type pacingDeadlineConn struct {
	net.Conn
	deadline time.Time
	err      error
	reads    int
}

func (c *pacingDeadlineConn) SetReadDeadline(deadline time.Time) error {
	c.deadline = deadline
	return c.err
}
func (c *pacingDeadlineConn) Read([]byte) (int, error) {
	c.reads++
	return 0, c.err
}

func TestExpiredAbsoluteReadDeadlineDoesNotStartDefaultTimeout(t *testing.T) {
	conn := &pacingDeadlineConn{err: errors.New("unexpected socket operation")}
	reader := MessageReader{decoded: []Message{{Raw: []byte("pong")}}}
	_, err := reader.readUntil(context.Background(), conn, fourByteAdapter{}, ServerToClient, []Message{{}}, nil, nil, time.Now().Add(-time.Nanosecond), time.Second)
	var readErr *peerReadError
	if !errors.As(err, &readErr) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired pacing deadline was not preserved: %v", err)
	}
	if !conn.deadline.IsZero() || conn.reads != 0 || len(reader.decoded) != 1 {
		t.Fatalf("expired read touched socket or consumed buffered response: %+v", conn)
	}
}

func TestPacingNeverSetsReadDeadlineBeyondCaptureTarget(t *testing.T) {
	stop := errors.New("stop before socket read")
	// Exercise the socket-deadline branch deterministically as well: under a
	// slow race build every tiny target below could expire before the call.
	target := time.Now().Add(time.Second)
	conn := &pacingDeadlineConn{err: stop}
	var reader MessageReader
	if err := reader.WaitUntil(context.Background(), conn, fourByteAdapter{}, nil, nil, nil, target, time.Second); !errors.Is(err, stop) {
		t.Fatalf("future target did not reach read-deadline setup: %v", err)
	}
	if conn.deadline.IsZero() || conn.deadline.After(target) {
		t.Fatalf("future capture target did not bound socket deadline: %v", conn.deadline)
	}
	for i := 0; i < 10000; i++ {
		target := time.Now().Add(time.Duration(1+i%1000) * time.Nanosecond)
		conn := &pacingDeadlineConn{err: stop}
		var reader MessageReader
		err := reader.WaitUntil(context.Background(), conn, fourByteAdapter{}, nil, nil, nil, target, time.Second)
		if err != nil && !errors.Is(err, stop) {
			t.Fatalf("unexpected pacing result: %v", err)
		}
		if !conn.deadline.IsZero() && conn.deadline.After(target) {
			t.Fatalf("capture pacing deadline extended by %v", conn.deadline.Sub(target))
		}
	}
}

type boundaryMaintenanceAdapter struct {
	fourByteAdapter
	at  time.Time
	err error
}

func (a boundaryMaintenanceAdapter) Maintenance(time.Time, *RuntimeState) ([]Message, time.Time, error) {
	time.Sleep(time.Until(a.at))
	return nil, time.Time{}, a.err
}

func TestPacingBoundaryDoesNotSuppressMaintenanceDeadline(t *testing.T) {
	target := time.Now().Add(100 * time.Millisecond)
	maintenanceErr := errors.Join(errors.New("protocol maintenance failed"), context.DeadlineExceeded)
	adapter := boundaryMaintenanceAdapter{at: target.Add(time.Millisecond), err: maintenanceErr}
	var reader MessageReader
	err := reader.WaitUntil(context.Background(), nil, adapter, nil, nil, NewRuntimeState(nil), target, time.Second)
	if !errors.Is(err, maintenanceErr) {
		t.Fatalf("pacing expiry hid maintenance failure: %v", err)
	}
	var observed *ResponseReadError
	if errors.As(err, &observed) {
		t.Fatalf("maintenance failure became response-read evidence: %v", err)
	}
}

type boundaryControlConn struct {
	net.Conn
	at  time.Time
	err error
}

func (c boundaryControlConn) SetWriteDeadline(time.Time) error { return nil }
func (c boundaryControlConn) Write([]byte) (int, error) {
	time.Sleep(time.Until(c.at))
	return 0, c.err
}

func TestPacingBoundaryDoesNotSuppressQueuedControlFailure(t *testing.T) {
	target := time.Now().Add(100 * time.Millisecond)
	writeErr := errors.Join(errors.New("queued acknowledgement failed"), context.DeadlineExceeded)
	conn := boundaryControlConn{at: target.Add(time.Millisecond), err: writeErr}
	state := NewRuntimeState(nil)
	state.Pending = []Message{{Raw: []byte("ping")}}
	var reader MessageReader
	err := reader.WaitUntil(context.Background(), conn, fourByteAdapter{}, nil, nil, state, target, time.Second)
	if !errors.Is(err, writeErr) {
		t.Fatalf("pacing expiry hid generated-control failure: %v", err)
	}
}

func TestPublicReadRetainsNonpositiveTimeoutDefault(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		client, server := net.Pipe()
		go func() { defer server.Close(); _, _ = server.Write([]byte("pong")) }()
		var reader MessageReader
		messages, err := reader.Read(context.Background(), client, fourByteAdapter{}, ServerToClient, []Message{{Raw: []byte("pong")}}, nil, timeout)
		_ = client.Close()
		if err != nil || len(messages) != 1 || string(messages[0].Raw) != "pong" {
			t.Fatalf("default read timeout changed: %v %+v", err, messages)
		}
	}
}
