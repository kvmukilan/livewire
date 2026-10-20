package secureexec

import (
	"context"
	"errors"
	"fmt"

	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/replayintent"
)

// SessionOutcome is the result of one TLS session inside a multi-session job.
type SessionOutcome struct {
	SessionID  string `json:"sessionId"`
	Status     string `json:"status,omitempty"`
	Completed  bool   `json:"completed"`
	Verified   bool   `json:"verified"`
	Matched    bool   `json:"matched"`
	Adapter    string `json:"adapter,omitempty"`
	Requests   int    `json:"requests"`
	Responses  int    `json:"responses"`
	Mismatches int    `json:"mismatches"`
	Error      string `json:"error,omitempty"`
	Skipped    string `json:"skipped,omitempty"`
}

// preparedSession pairs a session with its prepared driver, or the reason it
// could not be prepared.
type preparedSession struct {
	id       string
	prepared *Prepared
	skipped  string
}

// prepareTLSSessions prepares every TLS session of the route individually and
// returns one driver that runs them in capture order on the same target.
// Sessions that cannot be prepared are reported as skipped rather than
// stopping the whole job, as long as at least one session can run.
func prepareTLSSessions(c Config, host string) (*Prepared, error) {
	var sessions []preparedSession
	for _, s := range c.Inspection.Route.All() {
		single := c
		inspection := *c.Inspection
		inspection.Route = replayintent.Route{Kind: replayintent.TLS, Session: s, Trace: c.Inspection.Trace}
		single.Inspection = &inspection
		p, err := Prepare(single)
		if err != nil && len(c.KeyLog) > 0 && !replayintent.IsTLS(&replay.Session{Transport: s.Transport, Events: serverOnly(s)}) {
			// The capture holds a client offer but no server handshake, so
			// there is nothing to decrypt: a fresh handshake is the only
			// stimulus this session can reproduce.
			handshake := single
			handshake.Variables, handshake.Scenario = nil, nil
			if p2, e2 := prepareTLSHandshake(handshake, host); e2 == nil {
				p, err = p2, nil
			}
		}
		if err != nil {
			sessions = append(sessions, preparedSession{id: s.ID, skipped: err.Error()})
			continue
		}
		sessions = append(sessions, preparedSession{id: s.ID, prepared: p})
	}
	return combineSessions(sessions)
}

func serverOnly(s *replay.Session) []replay.Event {
	var out []replay.Event
	for _, e := range s.Events {
		if e.Direction == replay.ServerToClient {
			out = append(out, e)
		}
	}
	return out
}

func combineSessions(sessions []preparedSession) (*Prepared, error) {
	runnable := 0
	for _, s := range sessions {
		if s.prepared != nil {
			runnable++
		}
	}
	if runnable == 0 {
		var reasons []error
		for _, s := range sessions {
			reasons = append(reasons, fmt.Errorf("%s: %s", s.id, s.skipped))
		}
		return nil, fmt.Errorf("none of the %d selected TLS sessions can be replayed: %w", len(sessions), errors.Join(reasons...))
	}
	return &Prepared{sessionID: "tls-sessions", restartSafe: true, run: func(ctx context.Context) (Outcome, error) {
		o := Outcome{Completed: true, Verified: false, Matched: true, PeerIdentityChecked: true}
		o.Scope = fmt.Sprintf("%d of %d selected TLS sessions replayed in capture order", runnable, len(sessions))
		o.Cleanup = "complete"
		var errs []error
		for _, s := range sessions {
			if s.prepared == nil {
				o.Sessions = append(o.Sessions, SessionOutcome{SessionID: s.id, Skipped: s.skipped, Status: "skipped"})
				o.Transformations = append(o.Transformations, s.id+": skipped, "+s.skipped)
				continue
			}
			if err := ctx.Err(); err != nil {
				o.Completed = false
				errs = append(errs, err)
				break
			}
			result, err := s.prepared.Run(ctx)
			entry := SessionOutcome{SessionID: s.id, Status: result.Status, Completed: result.Completed, Verified: result.Verified, Matched: result.Matched, Adapter: result.Adapter, Requests: result.Requests, Responses: result.Responses, Mismatches: result.Mismatches, Error: result.Error}
			if err != nil {
				if entry.Error == "" {
					entry.Error = err.Error()
				}
				errs = append(errs, fmt.Errorf("%s: %w", s.id, err))
			}
			o.Sessions = append(o.Sessions, entry)
			if o.Adapter == "" || o.Adapter == "tls-handshake" && result.Adapter != "" {
				o.Adapter = result.Adapter
			}
			if o.ProtocolVersion == "" {
				o.ProtocolVersion, o.CipherSuite, o.ALPN = result.ProtocolVersion, result.CipherSuite, result.ALPN
			}
			o.Requests += result.Requests
			o.Responses += result.Responses
			o.Mismatches += result.Mismatches
			o.Expected += result.Expected
			o.Observed += result.Observed
			o.Compared += result.Compared
			for _, d := range result.Differences {
				d.Field = s.id + " " + d.Field
				o.Differences = append(o.Differences, d)
			}
			o.Transformations = append(o.Transformations, result.Transformations...)
			o.HandshakeCompleted = o.HandshakeCompleted || result.HandshakeCompleted
			o.PeerIdentityChecked = o.PeerIdentityChecked && result.PeerIdentityChecked
			if result.Adapter == "tls-handshake" {
				// A fresh handshake reproduces the stimulus but has no
				// application response to compare; it neither completes nor
				// fails the application verdict.
				o.Transformations = append(o.Transformations, s.id+": fresh TLS handshake only; the capture holds no server handshake to decrypt")
				continue
			}
			o.Completed = o.Completed && result.Completed
			o.Verified = o.Verified || result.Verified
			o.Matched = o.Matched && result.Matched
			if result.Cleanup == "failed" {
				o.Cleanup = "failed"
			}
		}
		if len(errs) > 0 {
			o.Error = errors.Join(errs...).Error()
		}
		return o, errors.Join(errs...)
	}}, nil
}
