package replay

import (
	"testing"
	"time"
)

func TestTimingRecorderMeasuresTurnsAndDrift(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var r timingRecorder
	if r.result() != nil {
		t.Fatal("empty recorder produced timing")
	}
	// Recorded: the reply came 10 ms after the request. Live: 40 ms, and the
	// paced send left 3 ms late.
	r.sent(0, base.Add(3*time.Millisecond), base)
	r.received(10*time.Millisecond, base.Add(43*time.Millisecond))
	// A reply with no request in front of it is ignored.
	r.received(20*time.Millisecond, base.Add(50*time.Millisecond))
	// Second turn: recorded 20 ms, live 20 ms, unpaced.
	r.sent(100*time.Millisecond, base.Add(100*time.Millisecond), time.Time{})
	r.received(120*time.Millisecond, base.Add(120*time.Millisecond))
	got := r.result()
	if got == nil || got.Turns != 2 {
		t.Fatalf("timing=%+v", got)
	}
	if got.RecordedResponseMS != 15 || got.LiveResponseMS != 30 || got.MaxLiveResponseMS != 40 || got.MaxPacingDriftMS != 3 {
		t.Fatalf("timing=%+v", got)
	}
	if len(got.Samples) != 2 || got.Samples[0] != (TurnTiming{RecordedMS: 10, LiveMS: 40}) {
		t.Fatalf("samples=%+v", got.Samples)
	}
	if factor := got.SlowdownFactor(); factor != 2 {
		t.Fatalf("slowdown=%v", factor)
	}
	var none *SessionTiming
	if none.SlowdownFactor() != 0 {
		t.Fatal("nil timing has a slowdown factor")
	}
}
