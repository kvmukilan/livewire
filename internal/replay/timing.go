package replay

import "time"

// SessionTiming compares when the live peer answered with when the recording
// shows it answering, so a reproduction can be judged on time as well as on
// content. A device that returns the right bytes ten times slower than it did
// in the field has not reproduced a timing fault, and a paced replay that
// could not keep up with the recording has not exercised it. Values are in
// milliseconds so a report reader needs no unit conversion.
type SessionTiming struct {
	// Turns is how many request/response turns contributed to the means.
	Turns int `json:"turns"`
	// RecordedResponseMS is the mean recorded time from the last byte the
	// client sent to the first byte of the reply.
	RecordedResponseMS float64 `json:"recordedResponseMs"`
	// LiveResponseMS is the same measurement against the live peer.
	LiveResponseMS float64 `json:"liveResponseMs"`
	// MaxLiveResponseMS is the slowest live reply.
	MaxLiveResponseMS float64 `json:"maxLiveResponseMs"`
	// MaxPacingDriftMS is how late, at worst, a paced send left relative to
	// its recorded offset. It stays zero when the replay was not paced.
	MaxPacingDriftMS float64 `json:"maxPacingDriftMs"`
	// Samples lists every turn so a reader can see the distribution, not
	// just the mean.
	Samples []TurnTiming `json:"samples,omitempty"`
}

// TurnTiming is one request/response turn.
type TurnTiming struct {
	RecordedMS float64 `json:"recordedMs"`
	LiveMS     float64 `json:"liveMs"`
}

// SlowdownFactor is how many times slower the live peer answered than the
// recording shows. It is zero when either mean is unavailable.
func (t *SessionTiming) SlowdownFactor() float64 {
	if t == nil || t.Turns == 0 || t.RecordedResponseMS <= 0 {
		return 0
	}
	return t.LiveResponseMS / t.RecordedResponseMS
}

// timingRecorder accumulates SessionTiming while a session is replayed. A
// runner calls sent after it finishes transmitting a client turn and received
// when the first reply bytes of the following server turn have arrived.
type timingRecorder struct {
	timing         SessionTiming
	pending        bool
	liveSentAt     time.Time
	recordedSentAt time.Duration
	total          struct{ recorded, live float64 }
}

// sent notes the end of a client turn. scheduled is the wall-clock instant a
// paced replay meant to send at; zero means the send was not paced.
func (r *timingRecorder) sent(recordedAt time.Duration, now, scheduled time.Time) {
	r.pending = true
	r.liveSentAt = now
	r.recordedSentAt = recordedAt
	if !scheduled.IsZero() {
		if drift := ms(now.Sub(scheduled)); drift > r.timing.MaxPacingDriftMS {
			r.timing.MaxPacingDriftMS = drift
		}
	}
}

// received notes the first reply of a server turn.
func (r *timingRecorder) received(recordedAt time.Duration, now time.Time) {
	if !r.pending {
		return
	}
	r.pending = false
	recorded := ms(recordedAt - r.recordedSentAt)
	live := ms(now.Sub(r.liveSentAt))
	if recorded < 0 {
		recorded = 0
	}
	if live < 0 {
		live = 0
	}
	r.timing.Turns++
	r.total.recorded += recorded
	r.total.live += live
	if live > r.timing.MaxLiveResponseMS {
		r.timing.MaxLiveResponseMS = live
	}
	r.timing.Samples = append(r.timing.Samples, TurnTiming{RecordedMS: recorded, LiveMS: live})
}

// result returns the accumulated timing, or nil when no turn completed so a
// report never carries an empty timing block.
func (r *timingRecorder) result() *SessionTiming {
	if r.timing.Turns == 0 && r.timing.MaxPacingDriftMS == 0 {
		return nil
	}
	out := r.timing
	if out.Turns > 0 {
		out.RecordedResponseMS = r.total.recorded / float64(out.Turns)
		out.LiveResponseMS = r.total.live / float64(out.Turns)
	}
	return &out
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
