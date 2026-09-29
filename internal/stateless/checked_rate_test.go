package stateless

import (
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
)

func TestCheckedScheduleRejectsInvalidRates(t *testing.T) {
	for _, tc := range []struct {
		name string
		pace Pace
		want string
	}{
		{"negative pps", Pace{PPS: -1}, "pps"},
		{"negative mbps", Pace{Mbps: -1}, "mbps"},
		{"negative multiplier", Pace{Multiplier: -1}, "multiplier"},
		{"nan", Pace{PPS: math.NaN()}, "finite"},
		{"infinite", Pace{Mbps: math.Inf(1)}, "finite"},
		{"negative infinite", Pace{Multiplier: math.Inf(-1)}, "finite"},
		{"two rates", Pace{PPS: 10, Mbps: 1}, "only one"},
		{"topspeed and rate", Pace{TopSpeed: true, Multiplier: 2}, "only one"},
		{"pps overflow", Pace{PPS: 1e-300}, "duration"},
		{"mbps overflow", Pace{Mbps: 1e-300}, "duration"},
		{"multiplier overflow", Pace{Multiplier: 1e-300}, "duration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := CheckedSchedule(recsAt([]time.Duration{0, time.Second}, 64), tc.pace); err == nil || !strings.Contains(err.Error(), tc.want) || got != nil {
				t.Fatalf("schedule=%v err=%v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestCheckedScheduleClampsBackwardsTimestampsWithoutReordering(t *testing.T) {
	recs := recsAt([]time.Duration{0, 3 * time.Second, time.Second, -time.Second, 4 * time.Second}, 10)
	for _, mult := range []float64{0, 2} {
		got, err := CheckedSchedule(recs, Pace{Multiplier: mult})
		want := []time.Duration{0, 3 * time.Second, 3 * time.Second, 3 * time.Second, 4 * time.Second}
		if mult == 2 {
			for i := range want {
				want[i] /= 2
			}
		}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("multiplier=%v: got %v err=%v, want %v", mult, got, err, want)
		}
		if TotalDuration(got) != want[len(want)-1] {
			t.Fatal("duration does not cover the entire schedule")
		}
	}
}

func TestCheckedScheduleAccumulatesFractionalRateOffsets(t *testing.T) {
	recs := recsAt([]time.Duration{0, 0, 0, 0}, 1)
	for _, tc := range []struct {
		pace Pace
		last time.Duration
	}{{Pace{PPS: 3}, time.Second}, {Pace{Mbps: 3}, 8 * time.Microsecond}} {
		got, err := CheckedSchedule(recs, tc.pace)
		if err != nil || got[3] != tc.last {
			t.Fatalf("pace=%+v: got %v err=%v, want last %s", tc.pace, got, err, tc.last)
		}
	}
}

func TestCheckedScheduleRejectsMissingAndOutOfRangeRecords(t *testing.T) {
	for _, recs := range [][]*pcapio.Record{
		{nil},
		{&pcapio.Record{}, nil},
		{{Time: time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)}, {Time: time.Date(1000, 1, 1, 0, 0, 0, 0, time.UTC)}},
	} {
		if _, err := CheckedSchedule(recs, Pace{}); err == nil {
			t.Fatalf("accepted invalid records: %+v", recs)
		}
	}
}
