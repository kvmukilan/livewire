// Package stateless computes send scheduling for tcpreplay-style replay: pacing
// a capture's frames onto an interface with no live sequence state. The pacing
// math is pure, so the CLI drives the real send loop from the schedule.
package stateless

import (
	"fmt"
	"math"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
)

// Pace selects one replay rate. Zero-valued rates are unset; no rate preserves
// capture timing. Multiple selected rates are rejected instead of ignored.
type Pace struct {
	TopSpeed   bool    // send as fast as possible (no inter-packet delay)
	PPS        float64 // fixed packets per second
	Mbps       float64 // fixed megabits per second (paced by frame size)
	Multiplier float64 // scale the capture's own inter-packet gaps (1 = realtime, 2 = 2x faster)
}

// Schedule returns cumulative send offsets, or nil for an invalid schedule.
// Call CheckedSchedule when the caller needs an explanation of invalid input.
func Schedule(recs []*pcapio.Record, p Pace) []time.Duration {
	out, _ := CheckedSchedule(recs, p)
	return out
}

// CheckedSchedule returns monotonically non-decreasing offsets in capture
// record order. Invalid rates and offsets outside time.Duration are rejected.
func CheckedSchedule(recs []*pcapio.Record, p Pace) ([]time.Duration, error) {
	selected := 0
	if p.TopSpeed {
		selected++
	}
	for _, rate := range []struct {
		name  string
		value float64
	}{{"pps", p.PPS}, {"mbps", p.Mbps}, {"multiplier", p.Multiplier}} {
		if math.IsNaN(rate.value) || math.IsInf(rate.value, 0) || rate.value < 0 {
			return nil, fmt.Errorf("-%s must be finite and greater than zero when selected", rate.name)
		}
		if rate.value > 0 {
			selected++
		}
	}
	if selected > 1 {
		return nil, fmt.Errorf("choose only one replay rate: -topspeed, -pps, -mbps, or -multiplier")
	}
	out := make([]time.Duration, len(recs))
	if len(recs) == 0 {
		return out, nil
	}
	if recs[0] == nil {
		return nil, fmt.Errorf("capture record 0 is missing")
	}
	base := recs[0].Time
	var priorBytes float64
	for i, rec := range recs {
		if rec == nil {
			return nil, fmt.Errorf("capture record %d is missing", i)
		}
		var ns float64
		switch {
		case p.TopSpeed:
			// All zero: back-to-back.
		case p.PPS > 0:
			ns = float64(i) * float64(time.Second) / p.PPS
		case p.Mbps > 0:
			ns = priorBytes * 8 * 1000 / p.Mbps
		default:
			gap := rec.Time.Sub(base)
			if gap > 0 && base.Add(gap).Before(rec.Time) {
				return nil, fmt.Errorf("capture timestamp at record %d exceeds supported duration", i)
			}
			if gap < 0 {
				gap = 0
			}
			mult := p.Multiplier
			if mult == 0 {
				mult = 1
			}
			ns = float64(gap) / mult
		}
		// The float representation of MaxInt64 rounds up to 1<<63; equality
		// would overflow when converted to a signed duration too.
		if math.IsNaN(ns) || math.IsInf(ns, 0) || ns >= float64(math.MaxInt64) {
			return nil, fmt.Errorf("replay offset at record %d exceeds supported duration; increase the replay rate", i)
		}
		out[i] = time.Duration(ns)
		if i > 0 && out[i] < out[i-1] {
			out[i] = out[i-1]
		}
		priorBytes += float64(len(rec.Data))
	}
	return out, nil
}

// TotalDuration is the offset of the last scheduled packet.
func TotalDuration(sched []time.Duration) time.Duration {
	if len(sched) == 0 {
		return 0
	}
	return sched[len(sched)-1]
}
