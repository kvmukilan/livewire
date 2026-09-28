// Package compare judges a reproduction by its evidence. It pairs the sessions
// of a recorded capture with the sessions of a second capture of the same
// exchange, such as the actual traffic a replay saved or a recording taken from
// another device, and reports per session whether the peer answered the same
// way, where the first divergence is, and how the reply timing compares.
//
// Sessions are compared with the same protocol adapters the replay drivers
// use, so a Modbus reply that differs only in a drifting register value is a
// value drift rather than a structural difference, exactly as it would be
// during a lenient replay. Sessions no adapter understands are compared byte
// for byte.
package compare

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
)

// Options tune how captures are read and understood.
type Options struct {
	// Registry supplies the protocol adapters; nil uses the built-in set.
	Registry *replay.Registry
	// UDPIdle splits a UDP tuple into a new session after this idle interval.
	UDPIdle  time.Duration
	Verify   replay.VerifyMode
	Scenario *replay.Scenario
}

// Verdicts and statuses. A session is matched when no structural difference
// was found, different when one was, and missing when the second capture has
// no session for it. The report verdict is the worst session status.
const (
	Matched    = "matched"
	Different  = "different"
	Missing    = "missing"
	Incomplete = "incomplete"
)

// Report is the whole comparison.
type Report struct {
	Verdict  string    `json:"verdict"`
	Summary  Summary   `json:"summary"`
	Sessions []Session `json:"sessions"`
	// Unpaired lists sessions of the second capture that no recorded session
	// claimed, such as background traffic the replay host produced.
	Unpaired []string `json:"unpairedActualSessions,omitempty"`
}

// Summary counts sessions by status.
type Summary struct {
	Matched    int `json:"matched"`
	Different  int `json:"different"`
	Missing    int `json:"missing"`
	Incomplete int `json:"incomplete"`
}

// Session is one paired exchange.
type Session struct {
	RecordedID  string           `json:"recordedId"`
	ActualID    string           `json:"actualId,omitempty"`
	Fingerprint string           `json:"fingerprint"`
	Transport   replay.Transport `json:"transport"`
	ServerPort  uint16           `json:"serverPort,omitempty"`
	// Adapter names the protocol adapter that framed the comparison; empty
	// when the sessions were compared byte for byte.
	Adapter string `json:"adapter,omitempty"`
	Status  string `json:"status"`
	// Recorded and Actual count what each side of the exchange carried.
	Recorded Counts `json:"recorded"`
	Actual   Counts `json:"actual"`
	// Differences lists every difference found. Structural ones decide the
	// status; the rest are value drift a lenient replay would tolerate.
	Differences     []replay.Difference `json:"differences,omitempty"`
	FirstDivergence *Divergence         `json:"firstDivergence,omitempty"`
	Timing          *Timing             `json:"timing,omitempty"`
}

// Counts describes one side of one session.
type Counts struct {
	Requests     int `json:"requests"`
	Replies      int `json:"replies"`
	RequestBytes int `json:"requestBytes"`
	ReplyBytes   int `json:"replyBytes"`
}

// Divergence locates the first structural difference in a session.
type Divergence struct {
	// Direction is request or reply.
	Direction string `json:"direction"`
	// Message is the 1-based message number when the protocol was framed,
	// and zero for a byte comparison.
	Message int `json:"message,omitempty"`
	// Offset is the byte position in that direction's stream.
	Offset int `json:"offset"`
	// Expected and Actual are payload digests; reports never copy credential bytes.
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
}

// Timing compares reply latency between the two captures, measured from the
// end of a request to the reply in each capture's own timestamps.
type Timing struct {
	Turns              int     `json:"turns"`
	RecordedResponseMS float64 `json:"recordedResponseMs"`
	ActualResponseMS   float64 `json:"actualResponseMs"`
	// SlowdownFactor is actual divided by recorded, when both are known.
	SlowdownFactor float64 `json:"slowdownFactor,omitempty"`
}

// Captures compares two captures.
func Captures(recorded, actual []*pcapio.Record, o Options) *Report {
	extract := replay.ExtractOptions{UDPIdle: o.UDPIdle}
	return Traces(replay.ExtractTrace(recorded, extract), replay.ExtractTrace(actual, extract), o)
}

// Traces compares two already extracted traces.
func Traces(recorded, actual *replay.Trace, o Options) *Report {
	registry := o.Registry
	if registry == nil {
		registry = adapters.DefaultRegistry()
	}
	report := &Report{}
	used := make([]bool, len(actual.Sessions))
	pair := func(rs *replay.Session) *replay.Session {
		// Identical content is the strongest pairing; otherwise the same
		// service is the best guess, in order of appearance.
		fingerprint := rs.Fingerprint()
		for i, as := range actual.Sessions {
			if !used[i] && as.Fingerprint() == fingerprint {
				used[i] = true
				return as
			}
		}
		for i, as := range actual.Sessions {
			if !used[i] && as.Transport == rs.Transport && as.Server.Port == rs.Server.Port {
				used[i] = true
				return as
			}
		}
		return nil
	}
	for _, rs := range recorded.Sessions {
		s := Session{RecordedID: rs.ID, Fingerprint: rs.Fingerprint(), Transport: rs.Transport, ServerPort: rs.Server.Port, Recorded: counts(rs)}
		as := pair(rs)
		if as == nil {
			s.Status = Missing
			report.Summary.Missing++
			report.Sessions = append(report.Sessions, s)
			continue
		}
		s.ActualID = as.ID
		s.Actual = counts(as)
		compareSession(&s, rs, as, registry, o)
		s.Timing = timing(rs, as)
		if s.Status == Different {
			report.Summary.Different++
		} else if s.Status == Incomplete {
			report.Summary.Incomplete++
		} else {
			report.Summary.Matched++
		}
		report.Sessions = append(report.Sessions, s)
	}
	for i, as := range actual.Sessions {
		if !used[i] {
			report.Unpaired = append(report.Unpaired, as.ID)
		}
	}
	switch {
	case report.Summary.Missing > 0 || report.Summary.Incomplete > 0 || len(report.Sessions) == 0:
		report.Verdict = Incomplete
	case report.Summary.Different > 0:
		report.Verdict = Different
	default:
		report.Verdict = Matched
	}
	return report
}

func counts(s *replay.Session) Counts {
	var c Counts
	for _, e := range s.Events {
		if len(e.Payload) == 0 {
			continue
		}
		switch e.Direction {
		case replay.ClientToServer:
			c.Requests++
			c.RequestBytes += len(e.Payload)
		case replay.ServerToClient:
			c.Replies++
			c.ReplyBytes += len(e.Payload)
		}
	}
	return c
}

// streams reassembles each direction of a session into one byte stream. TCP
// uses sequence numbers when the capture carries them, so retransmissions and
// reordering do not count as differences.
func streams(s *replay.Session) (client, server []byte) {
	if s.Transport == replay.TransportTCP {
		if c, sv, err := replay.TCPPayloadTimelines(s); err == nil {
			return c.Data, sv.Data
		}
	}
	for _, e := range s.Events {
		switch e.Direction {
		case replay.ClientToServer:
			client = append(client, e.Payload...)
		case replay.ServerToClient:
			server = append(server, e.Payload...)
		}
	}
	return client, server
}

func compareSession(s *Session, rs, as *replay.Session, registry *replay.Registry, o Options) {
	for _, session := range []*replay.Session{rs, as} {
		if session.Transport == replay.TransportTCP {
			if _, _, err := replay.TCPPayloadTimelines(session); err != nil {
				s.Status = Incomplete
				s.Differences = append(s.Differences, replay.Difference{Field: "capture-gap", Actual: "TCP stream cannot be reconstructed unambiguously", Structural: true})
				return
			}
		}
	}
	recordedRequests, recordedReplies := streams(rs)
	actualRequests, actualReplies := streams(as)
	if len(recordedReplies) == 0 || len(actualReplies) == 0 {
		s.Status = Incomplete
		return
	}
	s.Recorded.RequestBytes, s.Recorded.ReplyBytes = len(recordedRequests), len(recordedReplies)
	s.Actual.RequestBytes, s.Actual.ReplyBytes = len(actualRequests), len(actualReplies)
	if a, score := registry.Best(*rs); a != nil && score > 0 {
		s.Adapter = a.Name()
		if compareFramed(s, a, recordedRequests, recordedReplies, actualRequests, actualReplies, o) {
			s.Status = status(s.Differences)
			return
		}
		// The adapter could not frame one side, so fall back to bytes rather
		// than claim a comparison it did not make.
		s.Adapter = ""
	}
	compareRaw(s, "request", recordedRequests, actualRequests)
	compareRaw(s, "reply", recordedReplies, actualReplies)
	s.Status = status(s.Differences)
}

func status(differences []replay.Difference) string {
	if len(differences) > 0 {
		return Different
	}
	return Matched
}

func compareFramed(s *Session, adapter replay.Adapter, recordedRequests, recordedReplies, actualRequests, actualReplies []byte, o Options) bool {
	recReq, err := adapter.Decode(replay.ClientToServer, recordedRequests)
	if err != nil {
		return false
	}
	actReq, err := adapter.Decode(replay.ClientToServer, actualRequests)
	if err != nil {
		return false
	}
	recRep, err := replay.DecodeWithContext(adapter, replay.ServerToClient, recordedReplies, recReq)
	if err != nil {
		return false
	}
	actRep, err := replay.DecodeWithContext(adapter, replay.ServerToClient, actualReplies, actReq)
	if err != nil {
		return false
	}
	s.Recorded.Requests, s.Recorded.Replies = len(recReq), len(recRep)
	s.Actual.Requests, s.Actual.Replies = len(actReq), len(actRep)
	compareMessages(s, adapter, "request", recReq, actReq, o)
	compareMessages(s, adapter, "reply", recRep, actRep, o)
	return true
}

func compareMessages(s *Session, adapter replay.Adapter, direction string, expected, actual []replay.Message, o Options) {
	if len(expected) != len(actual) {
		s.Differences = append(s.Differences, replay.Difference{Field: direction + "-count", Expected: fmt.Sprint(len(expected)), Actual: fmt.Sprint(len(actual)), Structural: true})
	}
	state := &replay.RuntimeState{Variables: map[string]string{}, Learned: map[string][]byte{}}
	mode := o.Verify
	if mode == "" {
		mode = replay.VerifyLenient
	}
	scenario := replay.NewScenarioRuntime(o.Scenario)
	offset := 0
	for i := 0; i < len(expected) && i < len(actual); i++ {
		structural := false
		if match := adapter.Correlate(expected[i], actual[i], state); !match.Matched {
			s.Differences = append(s.Differences, replay.Difference{Field: direction + "-correlation", Expected: match.Key, Actual: match.Reason, Structural: true})
			structural = true
		}
		var differences []replay.Difference
		if direction == "reply" {
			differences = scenario.Compare(s.RecordedID, i+1, adapter, expected[i], actual[i], mode)
		} else {
			differences = adapter.Compare(expected[i], actual[i], mode)
		}
		for _, d := range differences {
			d.Field = direction + "." + d.Field
			s.Differences = append(s.Differences, d)
			structural = true
		}
		if structural && s.FirstDivergence == nil {
			s.FirstDivergence = &Divergence{Direction: direction, Message: i + 1, Offset: offset, Expected: excerpt(expected[i].Raw, 0), Actual: excerpt(actual[i].Raw, 0)}
		}
		offset += len(expected[i].Raw)
	}
	if s.FirstDivergence == nil && len(expected) != len(actual) {
		i := min(len(expected), len(actual))
		var exp, act []byte
		if i < len(expected) {
			exp = expected[i].Raw
		}
		if i < len(actual) {
			act = actual[i].Raw
		}
		s.FirstDivergence = &Divergence{Direction: direction, Message: i + 1, Offset: offset, Expected: excerpt(exp, 0), Actual: excerpt(act, 0)}
	}
}

func compareRaw(s *Session, direction string, expected, actual []byte) {
	i := 0
	for i < len(expected) && i < len(actual) && expected[i] == actual[i] {
		i++
	}
	if i == len(expected) && i == len(actual) {
		return
	}
	s.Differences = append(s.Differences, replay.Difference{
		Field:      direction + "-bytes",
		Expected:   fmt.Sprintf("%d bytes; %s at offset %d", len(expected), excerpt(expected, i), i),
		Actual:     fmt.Sprintf("%d bytes; %s at offset %d", len(actual), excerpt(actual, i), i),
		Structural: true,
	})
	if s.FirstDivergence == nil {
		s.FirstDivergence = &Divergence{Direction: direction, Offset: i, Expected: excerpt(expected, i), Actual: excerpt(actual, i)}
	}
}

// excerpt describes the differing suffix without serializing credential bytes.
func excerpt(b []byte, offset int) string {
	if offset >= len(b) {
		return "(end of data)"
	}
	return fmt.Sprintf("%d bytes, sha256:%x", len(b)-offset, sha256.Sum256(b[offset:]))
}

// responseTurns measures, from a capture's own timestamps, how long the peer
// took to answer each request.
func responseTurns(s *replay.Session) (turns int, total time.Duration) {
	var lastRequest time.Duration
	pending := false
	for _, e := range s.Events {
		if len(e.Payload) == 0 {
			continue
		}
		switch e.Direction {
		case replay.ClientToServer:
			lastRequest, pending = e.At, true
		case replay.ServerToClient:
			if pending {
				turns++
				total += e.At - lastRequest
				pending = false
			}
		}
	}
	return turns, total
}

func timing(rs, as *replay.Session) *Timing {
	recordedTurns, recordedTotal := responseTurns(rs)
	actualTurns, actualTotal := responseTurns(as)
	if recordedTurns == 0 || actualTurns == 0 {
		return nil
	}
	t := &Timing{
		Turns:              min(recordedTurns, actualTurns),
		RecordedResponseMS: milliseconds(recordedTotal) / float64(recordedTurns),
		ActualResponseMS:   milliseconds(actualTotal) / float64(actualTurns),
	}
	if t.RecordedResponseMS > 0 {
		t.SlowdownFactor = t.ActualResponseMS / t.RecordedResponseMS
	}
	return t
}

func milliseconds(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
