package stateless

import (
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
)

func recsAt(offsets []time.Duration, size int) []*pcapio.Record {
	base := time.Unix(1700000000, 0)
	recs := make([]*pcapio.Record, len(offsets))
	for i, off := range offsets {
		recs[i] = &pcapio.Record{Time: base.Add(off), Data: make([]byte, size)}
	}
	return recs
}

func TestScheduleTopSpeed(t *testing.T) {
	recs := recsAt([]time.Duration{0, time.Second, 2 * time.Second}, 100)
	sched := Schedule(recs, Pace{TopSpeed: true})
	for i, d := range sched {
		if d != 0 {
			t.Fatalf("topspeed offset[%d] = %v, want 0", i, d)
		}
	}
}

func TestSchedulePPS(t *testing.T) {
	recs := recsAt([]time.Duration{0, 0, 0, 0}, 100)
	sched := Schedule(recs, Pace{PPS: 1000}) // 1000 pps => 1ms apart
	for i := range sched {
		want := time.Duration(i) * time.Millisecond
		if sched[i] != want {
			t.Fatalf("pps offset[%d] = %v, want %v", i, sched[i], want)
		}
	}
}

func TestScheduleMbps(t *testing.T) {
	// 1000-byte frames = 8000 bits; at 8 Mbps that is exactly 1ms per frame.
	recs := recsAt([]time.Duration{0, 0, 0}, 1000)
	sched := Schedule(recs, Pace{Mbps: 8})
	for i := range sched {
		want := time.Duration(i) * time.Millisecond
		if sched[i] != want {
			t.Fatalf("mbps offset[%d] = %v, want %v", i, sched[i], want)
		}
	}
}

func TestScheduleMultiplier(t *testing.T) {
	recs := recsAt([]time.Duration{0, 2 * time.Second, 4 * time.Second}, 100)
	sched := Schedule(recs, Pace{Multiplier: 2}) // twice as fast: gaps halved
	want := []time.Duration{0, time.Second, 2 * time.Second}
	for i := range sched {
		if sched[i] != want[i] {
			t.Fatalf("mult offset[%d] = %v, want %v", i, sched[i], want[i])
		}
	}
}

func TestScheduleRealtimeDefault(t *testing.T) {
	recs := recsAt([]time.Duration{0, time.Second, 3 * time.Second}, 100)
	sched := Schedule(recs, Pace{}) // no rate: preserve original timing
	want := []time.Duration{0, time.Second, 3 * time.Second}
	for i := range sched {
		if sched[i] != want[i] {
			t.Fatalf("realtime offset[%d] = %v, want %v", i, sched[i], want[i])
		}
	}
	if TotalDuration(sched) != 3*time.Second {
		t.Fatalf("total = %v, want 3s", TotalDuration(sched))
	}
}
