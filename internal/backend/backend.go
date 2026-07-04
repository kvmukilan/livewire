// Package backend is the transport the stateful engine drives: a NIC-less
// MockBackend for CI, plus build-tagged AF_PACKET (Linux) and Npcap (Windows)
// backends for real hardware. It depends only on internal/wire to avoid an
// import cycle with the engine.
package backend

import (
	"time"

	"github.com/kvmukilan/livewire/internal/wire"
)

// Capabilities is a bitset of what a backend can do.
type Capabilities uint8

const (
	// CanReceive: Recv delivers frames from the wire (not send-only).
	CanReceive Capabilities = 1 << iota
	// StatefulSafe: can inject crafted TCP without the host stack racing it
	// (raw L2, or a diverter that suppresses the kernel RST).
	StatefulSafe
	// BatchSend: can enqueue many frames in one syscall.
	BatchSend
	// Layer2: Send/Recv operate on full link-layer frames.
	Layer2
)

// Has reports whether every capability in mask is present.
func (c Capabilities) Has(mask Capabilities) bool { return c&mask == mask }

// PacketBackend is the transport the engine drives. Not safe for concurrent
// use; the driver calls it from a single goroutine.
type PacketBackend interface {
	// Send transmits one frame. The caller keeps ownership of the buffer.
	Send(frame []byte) error
	// Recv reads the next frame into buf, waiting up to timeout. ok=false with
	// err=nil is a timeout, not a failure.
	Recv(buf []byte, timeout time.Duration) (n int, ok bool, err error)
	// Now returns the backend's clock: wall time for real backends, a virtual
	// clock for the mock.
	Now() time.Time
	// LinkType is the DLT of frames crossing this backend.
	LinkType() wire.LinkType
	// Caps reports the backend's capabilities.
	Caps() Capabilities
	// Close releases the backend's resources.
	Close() error
}
