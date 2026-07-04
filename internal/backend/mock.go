package backend

import (
	"time"

	"github.com/kvmukilan/livewire/internal/wire"
)

// Responder is the simulated peer a MockBackend talks to. Keeping protocol
// logic behind this interface keeps the backend package free of any engine
// dependency.
type Responder interface {
	// OnSend consumes one frame the engine sent and returns the peer's replies,
	// in delivery order.
	OnSend(frame []byte, now time.Time) [][]byte
}

// MockBackend is an in-memory PacketBackend for CI: a scripted Responder over a
// virtual clock, no NIC, no privileges. When the queue is empty Recv advances
// the clock by the timeout and reports a miss, so retransmit timers fire
// deterministically.
type MockBackend struct {
	responder Responder
	link      wire.LinkType
	caps      Capabilities
	now       time.Time
	queue     [][]byte

	sent int
	recv int
}

// NewMock builds a MockBackend delivering frames of the given link type from the
// supplied responder. start seeds the virtual clock.
func NewMock(r Responder, link wire.LinkType, start time.Time) *MockBackend {
	return &MockBackend{
		responder: r,
		link:      link,
		caps:      CanReceive | StatefulSafe | Layer2,
		now:       start,
	}
}

// Send hands the frame to the responder and queues whatever it emits.
func (m *MockBackend) Send(frame []byte) error {
	m.sent++
	for _, out := range m.responder.OnSend(frame, m.now) {
		m.queue = append(m.queue, append([]byte(nil), out...))
	}
	return nil
}

// Recv returns the next queued frame, or advances the virtual clock by timeout
// and reports a miss when the queue is empty.
func (m *MockBackend) Recv(buf []byte, timeout time.Duration) (int, bool, error) {
	if len(m.queue) > 0 {
		f := m.queue[0]
		m.queue = m.queue[1:]
		n := copy(buf, f)
		m.recv++
		return n, true, nil
	}
	if timeout > 0 {
		m.now = m.now.Add(timeout)
	}
	return 0, false, nil
}

// Now returns the virtual clock.
func (m *MockBackend) Now() time.Time { return m.now }

// LinkType reports the DLT of emitted frames.
func (m *MockBackend) LinkType() wire.LinkType { return m.link }

// Caps reports the mock's capabilities (receive-capable and stateful-safe).
func (m *MockBackend) Caps() Capabilities { return m.caps }

// Close is a no-op for the mock.
func (m *MockBackend) Close() error { return nil }

// Sent and Received expose frame counters for test assertions.
func (m *MockBackend) Sent() int     { return m.sent }
func (m *MockBackend) Received() int { return m.recv }
