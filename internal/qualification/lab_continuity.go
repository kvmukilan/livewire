package qualification

import (
	"fmt"
	"time"
)

// These v1.1+ limits leave margin over the labs' 45-second application and
// 25-second packet process deadlines and 20-second round intervals. They bound
// unobserved time; a first/last wall-clock span alone cannot prove a soak when a
// host sleeps. Historical v1.0 evidence keeps its original validation rules.
const (
	LabMaxExecutionDuration = 2 * time.Minute
	LabMaxIdleGap           = time.Minute
	LabMaxCaseGap           = 5 * time.Minute
)

// LabContinuity checks chronological, regularly repeated executions. Both the
// application producer and independent validator use it; the Python packet
// producer implements the same limits. Its zero state needs only Version set.
type LabContinuity struct {
	Version      string
	lastFinished time.Time
	caseFinished map[string]time.Time
}

// CheckStart rejects a resumed or out-of-order run before starting more traffic.
func (c *LabContinuity) CheckStart(name string, started time.Time) error {
	if !UsesStatelessReproduce(c.Version) {
		return nil
	}
	// Strip monotonic data even in the running producer: on some operating
	// systems the monotonic clock stops during suspend, unlike recorded UTC.
	started = started.Round(0)
	if name == "" || started.IsZero() {
		return fmt.Errorf("lab continuity: missing case or execution timestamp")
	}
	if !c.lastFinished.IsZero() {
		gap := started.Sub(c.lastFinished)
		if gap < 0 || gap > LabMaxIdleGap {
			return fmt.Errorf("lab continuity: %s idle gap %s outside 0..%s", name, gap, LabMaxIdleGap)
		}
	}
	if prior := c.caseFinished[name]; !prior.IsZero() {
		if gap := started.Sub(prior); gap > LabMaxCaseGap {
			return fmt.Errorf("lab continuity: %s case gap %s exceeds %s", name, gap, LabMaxCaseGap)
		}
	}
	return nil
}

// Observe credits a completed execution only after its wall time and cadence
// pass. Failure leaves the previous successful boundary intact.
func (c *LabContinuity) Observe(name string, started, finished time.Time) error {
	if !UsesStatelessReproduce(c.Version) {
		return nil
	}
	if err := c.CheckStart(name, started); err != nil {
		return err
	}
	started, finished = started.Round(0), finished.Round(0)
	if duration := finished.Sub(started); finished.IsZero() || duration < 0 || duration > LabMaxExecutionDuration {
		return fmt.Errorf("lab continuity: %s execution duration %s outside 0..%s", name, duration, LabMaxExecutionDuration)
	}
	if c.caseFinished == nil {
		c.caseFinished = map[string]time.Time{}
	}
	c.lastFinished, c.caseFinished[name] = finished, finished
	return nil
}
