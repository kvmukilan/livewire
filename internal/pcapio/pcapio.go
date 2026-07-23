// Package pcapio reads/writes classic pcap and reads pcapng, dependency-free,
// preserving nanosecond timestamps end-to-end.
package pcapio

import (
	"errors"
	"time"

	"github.com/kvmukilan/livewire/internal/wire"
)

// Record is one captured packet with full-resolution timing and link metadata.
type Record struct {
	Time        time.Time     // capture time at nanosecond resolution
	CapLen      int           // bytes captured (len(Data))
	OrigLen     int           // original on-wire length
	Data        []byte        // frame bytes
	LinkType    wire.LinkType // link type for this record
	InterfaceID uint32        // pcapng interface index (zero for classic pcap)
}

// Common errors.
var (
	ErrBadMagic   = errors.New("pcapio: unrecognized file magic")
	ErrTruncated  = errors.New("pcapio: truncated file")
	ErrMixedLinks = errors.New("pcapio: capture mixes link types; cannot flatten")
)
