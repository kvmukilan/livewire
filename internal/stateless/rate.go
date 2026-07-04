// Package stateless computes send scheduling for tcpreplay-style replay: pacing
// a capture's frames onto an interface with no live sequence state. The pacing
// math is pure, so the CLI drives the real send loop from the schedule.
package stateless

import (
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
)

// Pace selects a replay rate. The modes are mutually exclusive; they are checked
// in priority order TopSpeed > PPS > Mbps > Multiplier, matching tcpreplay.
type Pace struct {
	TopSpeed   bool    // send as fast as possible (no inter-packet delay)
	PPS        float64 // fixed packets per second
	Mbps       float64 // fixed megabits per second (paced by frame size)
	Multiplier float64 // scale the capture's own inter-packet gaps (1 = realtime, 2 = 2x faster)
}

// Schedule returns the cumulative send offset from t=0 for each record. Offsets
// are monotonically non-decreasing so the caller can sleep to each in turn.
func Schedule(recs []*pcapio.Record, p Pace) []time.Duration {
	out := make([]time.Duration, len(recs))
	if len(recs) == 0 {
		return out
	}
	switch {
	case p.TopSpeed:
		// all zero: back-to-back
	case p.PPS > 0:
		step := time.Duration(float64(time.Second) / p.PPS)
		for i := range recs {
			out[i] = time.Duration(i) * step
		}
	case p.Mbps > 0:
		bitsPerSec := p.Mbps * 1e6
		var acc time.Duration
		for i := range recs {
			out[i] = acc
			bits := float64(len(recs[i].Data) * 8)
			acc += time.Duration(bits / bitsPerSec * float64(time.Second))
		}
	default:
		mult := p.Multiplier
		if mult <= 0 {
			mult = 1
		}
		base := recs[0].Time
		for i := range recs {
			gap := recs[i].Time.Sub(base)
			if gap < 0 {
				gap = 0 // out-of-order timestamps never rewind the schedule
			}
			out[i] = time.Duration(float64(gap) / mult)
		}
	}
	return out
}

// TotalDuration is the offset of the last scheduled packet.
func TotalDuration(sched []time.Duration) time.Duration {
	if len(sched) == 0 {
		return 0
	}
	return sched[len(sched)-1]
}
