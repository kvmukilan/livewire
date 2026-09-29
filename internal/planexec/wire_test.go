package planexec

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/runstate"
	"github.com/kvmukilan/livewire/internal/wire"
)

type wireSender struct {
	frames [][]byte
	link   wire.LinkType
	closed int
	send   func([]byte) error
	close  func() error
}

func (s *wireSender) Send(data []byte) error {
	if s.send != nil {
		if err := s.send(data); err != nil {
			return err
		}
	}
	s.frames = append(s.frames, append([]byte(nil), data...))
	return nil
}
func (s *wireSender) Recv([]byte, time.Duration) (int, bool, error) {
	return 0, false, errors.New("wire replay must not receive")
}
func (s *wireSender) Now() time.Time             { return time.Now() }
func (s *wireSender) LinkType() wire.LinkType    { return s.link }
func (s *wireSender) Caps() backend.Capabilities { return backend.Layer2 }
func (s *wireSender) Close() error {
	s.closed++
	if s.close != nil {
		return s.close()
	}
	return nil
}

// Every session's first frame precedes every session's second frame, and plan
// order is reversed. Tied timestamps cannot be used to recover packet order.
func wireFixture(sessions int) Config {
	base := time.Unix(1000, 0)
	trace := &replay.Trace{Started: base, Packets: sessions * 2}
	plan := replay.ReplayPlan{Profile: replay.ProfileWire, Packets: trace.Packets}
	for i := 0; i < sessions; i++ {
		s := &replay.Session{ID: fmt.Sprintf("session-%d", i), Transport: replay.TransportTCP}
		for _, index := range []int{i, i + sessions} {
			data := []byte{byte(index >> 8), byte(index), 0xa5}
			s.Events = append(s.Events, replay.Event{PacketIndex: index, Record: &pcapio.Record{
				Time: base, CapLen: len(data), OrigLen: len(data), Data: data, LinkType: wire.LinkEthernet,
			}})
		}
		trace.Sessions = append(trace.Sessions, s)
		plan.Entries = append(plan.Entries, replay.PlanEntry{
			SessionID: s.ID, Transport: s.Transport, Mode: replay.ModeWire, Fidelity: replay.FidelityWire, PacketIndexes: []int{i, i + sessions},
		})
	}
	for i, j := 0, len(plan.Entries)-1; i < j; i, j = i+1, j-1 {
		plan.Entries[i], plan.Entries[j] = plan.Entries[j], plan.Entries[i]
	}
	return Config{Trace: trace, Plan: plan}
}

func wireFrameIndexes(frames [][]byte) []int {
	var out []int
	for _, frame := range frames {
		out = append(out, int(frame[0])<<8|int(frame[1]))
	}
	return out
}

func wireStore(t *testing.T) *runstate.Store {
	t.Helper()
	store, err := runstate.Open(filepath.Join(t.TempDir(), "state"), runstate.Manifest{
		Version: runstate.Version, CaptureDigest: "wire-fixture", ConfigurationDigest: "wire-config",
	}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store
}

func TestWirePlanPreservesGlobalOrderBeyondWorkerLimit(t *testing.T) {
	cfg := wireFixture(64)
	sender := &wireSender{link: wire.LinkEthernet}
	opens := 0
	cfg.openWireSender = func(string) (backend.PacketBackend, error) { opens++; return sender, nil }
	var evidence [][]byte
	cfg.Context = replay.WithExecution(context.Background(), replay.ExecutionConfig{Concurrency: 1, Evidence: func(record pcapio.Record) error {
		evidence = append(evidence, append([]byte(nil), record.Data...))
		return nil
	}})
	results := Execute(cfg)
	if opens != 1 || sender.closed != 1 {
		t.Fatalf("opens=%d closes=%d", opens, sender.closed)
	}
	want := make([]int, 128)
	for i := range want {
		want[i] = i
	}
	if got := wireFrameIndexes(sender.frames); !reflect.DeepEqual(got, want) {
		t.Fatalf("order=%v", got)
	}
	if !reflect.DeepEqual(sender.frames, evidence) {
		t.Fatal("evidence order/bytes differ from emitted frames")
	}
	for i, result := range results {
		if result.Entry.SessionID != cfg.Plan.Entries[i].SessionID {
			t.Fatal("results lost plan order")
		}
		if result.Err != nil || !result.Transport.Completed || result.Transport.Verified || result.Transport.Matched || result.Transport.Sent != 2 {
			t.Fatalf("result %d: %+v", i, result)
		}
	}
}

func TestWirePlanMixesRawAndSessionsAndHonorsSelection(t *testing.T) {
	cfg := wireFixture(3)
	rawSession := cfg.Trace.Sessions[1]
	cfg.Trace.Raw = rawSession.Events
	cfg.Trace.Sessions = append(cfg.Trace.Sessions[:1], cfg.Trace.Sessions[2:]...)
	cfg.Plan.Entries[1].SessionID = "raw-0"
	cfg.Plan.Entries[1].Transport = replay.TransportRaw
	cfg.Plan.Entries[0].Excluded = true
	sender := &wireSender{link: wire.LinkEthernet}
	cfg.openWireSender = func(string) (backend.PacketBackend, error) { return sender, nil }
	results := Execute(cfg)
	if got := wireFrameIndexes(sender.frames); !reflect.DeepEqual(got, []int{0, 1, 3, 4}) {
		t.Fatalf("order=%v", got)
	}
	if len(results) != 2 {
		t.Fatalf("selected results=%d", len(results))
	}
	for _, result := range results {
		if result.Err != nil || !result.Transport.Completed {
			t.Fatalf("result=%+v", result)
		}
	}
}

func TestWirePlanClosesBeforeCompletionCheckpoint(t *testing.T) {
	for _, failClose := range []bool{false, true} {
		t.Run(fmt.Sprint(failClose), func(t *testing.T) {
			cfg := wireFixture(2)
			store := wireStore(t)
			cfg.Context = replay.WithExecution(context.Background(), replay.ExecutionConfig{Journal: store})
			closeFailure := errors.New("close failed")
			sender := &wireSender{link: wire.LinkEthernet, close: func() error {
				for key, p := range store.Progress() {
					if p.Result != nil && p.Result.Completed {
						t.Errorf("%s checkpoint completed before close", key)
					}
				}
				if failClose {
					return closeFailure
				}
				return nil
			}}
			cfg.openWireSender = func(string) (backend.PacketBackend, error) { return sender, nil }
			results := Execute(cfg)
			if sender.closed != 1 {
				t.Fatalf("closed=%d", sender.closed)
			}
			for _, result := range results {
				p := store.Progress()["1/"+result.Entry.SessionID]
				if result.Transport.Sent != 2 || result.Transport.Completed == failClose || errors.Is(result.Err, closeFailure) != failClose {
					t.Fatalf("result=%+v", result)
				}
				if p.Result == nil || p.Result.Completed == failClose || p.Uncertain != failClose || p.Result.Verified || p.Result.Matched {
					t.Fatalf("progress=%+v", p)
				}
			}
		})
	}
}

func TestWirePlanPartialSendAndEvidenceFailuresRetainCounts(t *testing.T) {
	for _, failEvidence := range []bool{false, true} {
		t.Run(fmt.Sprint(failEvidence), func(t *testing.T) {
			cfg := wireFixture(2)
			store := wireStore(t)
			failure := errors.New("injected failure")
			sender := &wireSender{link: wire.LinkEthernet}
			check := func(data []byte) error {
				if data[1] == 3 {
					return failure
				}
				return nil
			}
			execution := replay.ExecutionConfig{Journal: store}
			if failEvidence {
				execution.Evidence = func(r pcapio.Record) error { return check(r.Data) }
			} else {
				sender.send = check
			}
			cfg.Context = replay.WithExecution(context.Background(), execution)
			cfg.openWireSender = func(string) (backend.PacketBackend, error) { return sender, nil }
			results := Execute(cfg)
			for _, r := range results {
				failed := r.Entry.SessionID == "session-1"
				wantSent := 2
				if failed && !failEvidence {
					wantSent = 1
				}
				if r.Transport.Sent != wantSent || r.Transport.Completed == failed || errors.Is(r.Err, failure) != failed {
					t.Fatalf("result=%+v", r)
				}
				p := store.Progress()["1/"+r.Entry.SessionID]
				if p.Result.Sent != wantSent || p.Result.Completed == failed || p.Uncertain != failed {
					t.Fatalf("progress=%+v", p)
				}
			}
			if sender.closed != 1 {
				t.Fatalf("closed=%d", sender.closed)
			}
		})
	}
}

func TestWirePlanResumeSkipsOnlyCompletedSessions(t *testing.T) {
	cfg := wireFixture(3)
	store := wireStore(t)
	if _, err := store.Begin("1/session-1", false); err != nil {
		t.Fatal(err)
	}
	if err := store.Finish("1/session-1", runstate.Result{Completed: true, Verified: true, Matched: true, Sent: 2}); err != nil {
		t.Fatal(err)
	}
	cfg.Context = replay.WithExecution(context.Background(), replay.ExecutionConfig{Journal: store})
	sender := &wireSender{link: wire.LinkEthernet}
	opens := 0
	cfg.openWireSender = func(string) (backend.PacketBackend, error) { opens++; return sender, nil }
	for attempt := 0; attempt < 2; attempt++ {
		results := Execute(cfg)
		for _, r := range results {
			if r.Err != nil || !r.Transport.Completed || r.Transport.Verified || r.Transport.Matched || r.Transport.Sent != 2 {
				t.Fatalf("result=%+v", r)
			}
		}
	}
	if got := wireFrameIndexes(sender.frames); !reflect.DeepEqual(got, []int{0, 2, 3, 5}) {
		t.Fatalf("resume order=%v", got)
	}
	if opens != 1 || sender.closed != 1 {
		t.Fatalf("resume opens=%d closes=%d", opens, sender.closed)
	}
}

func TestWirePlanResumeRefusesUncertainSessionBeforeAnySend(t *testing.T) {
	cfg := wireFixture(3)
	store := wireStore(t)
	if _, err := store.Begin("1/session-1", false); err != nil {
		t.Fatal(err)
	}
	if err := store.Record("1/session-1", "intent", 0); err != nil {
		t.Fatal(err)
	}
	cfg.Context = replay.WithExecution(context.Background(), replay.ExecutionConfig{Journal: store})
	cfg.openWireSender = func(string) (backend.PacketBackend, error) {
		t.Fatal("opened despite uncertain prior send")
		return nil, nil
	}
	for _, r := range Execute(cfg) {
		if r.Err == nil || r.Transport.Completed || r.Transport.Sent != 0 {
			t.Fatalf("result=%+v", r)
		}
	}
}

func TestWirePlanCancellationBeforeAndDuringWait(t *testing.T) {
	for _, before := range []bool{false, true} {
		t.Run(fmt.Sprint(before), func(t *testing.T) {
			cfg := wireFixture(1)
			cfg.Trace.Sessions[0].Events[1].Record.Time = cfg.Trace.Started.Add(time.Hour)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cfg.Context = ctx
			sender := &wireSender{link: wire.LinkEthernet, send: func([]byte) error { cancel(); return nil }}
			cfg.openWireSender = func(string) (backend.PacketBackend, error) {
				if before {
					t.Fatal("opened after cancellation")
				}
				return sender, nil
			}
			if before {
				cancel()
			}
			started := time.Now()
			result := Execute(cfg)[0]
			if !errors.Is(result.Err, context.Canceled) || result.Transport.Completed || time.Since(started) > time.Second {
				t.Fatalf("result=%+v elapsed=%s", result, time.Since(started))
			}
			if !before && (result.Transport.Sent != 1 || sender.closed != 1) {
				t.Fatalf("result=%+v closed=%d", result, sender.closed)
			}
		})
	}
}

func TestWirePlanRejectsMalformedFramesBeforeOpening(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"missing":            func(c *Config) { c.Trace.Sessions[0].Events[1].Record = nil },
		"empty":              func(c *Config) { c.Trace.Sessions[0].Events[1].Record.Data = nil },
		"truncated":          func(c *Config) { c.Trace.Sessions[0].Events[1].Record.OrigLen++ },
		"mixed-links":        func(c *Config) { c.Trace.Sessions[0].Events[1].Record.LinkType++ },
		"duplicate-index":    func(c *Config) { c.Trace.Sessions[0].Events[1].PacketIndex = 0 },
		"coverage":           func(c *Config) { c.Plan.Entries[0].PacketIndexes = []int{0, 8} },
		"duplicate-id":       func(c *Config) { c.Plan.Entries = append(c.Plan.Entries, c.Plan.Entries[0]) },
		"timestamp-overflow": func(c *Config) { c.Trace.Sessions[0].Events[1].Record.Time = c.Trace.Started.AddDate(400, 0, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := wireFixture(1)
			mutate(&cfg)
			cfg.openWireSender = func(string) (backend.PacketBackend, error) { t.Fatal("opened malformed capture"); return nil, nil }
			for _, r := range Execute(cfg) {
				if r.Err == nil || r.Transport.Completed || r.Transport.Sent != 0 {
					t.Fatalf("result=%+v", r)
				}
			}
		})
	}
}

func TestWirePlanRejectsInterfaceLinkBeforeSending(t *testing.T) {
	cfg := wireFixture(1)
	sender := &wireSender{link: wire.LinkEthernet + 1}
	cfg.openWireSender = func(string) (backend.PacketBackend, error) { return sender, nil }
	result := Execute(cfg)[0]
	if result.Err == nil || !strings.Contains(result.Err.Error(), "link type") || len(sender.frames) != 0 || sender.closed != 1 {
		t.Fatalf("result=%+v sender=%+v", result, sender)
	}
}

func TestWirePlanTimingKeepsCaptureOriginAndMonotonicOffsets(t *testing.T) {
	cfg := wireFixture(2)
	cfg.Trace.Sessions[0].Events[0].Record.Time = cfg.Trace.Started.Add(10 * time.Millisecond)
	cfg.Trace.Sessions[1].Events[0].Record.Time = cfg.Trace.Started.Add(30 * time.Millisecond)
	cfg.Trace.Sessions[0].Events[1].Record.Time = cfg.Trace.Started.Add(20 * time.Millisecond)
	cfg.Trace.Sessions[1].Events[1].Record.Time = cfg.Trace.Started.Add(30 * time.Millisecond)
	var results []Result
	for _, entry := range cfg.Plan.Entries {
		for _, session := range cfg.Trace.Sessions {
			if entry.SessionID == session.ID {
				results = append(results, Result{Entry: entry, Session: session})
			}
		}
	}
	frames, offsets, err := wirePlanFrames(cfg.Trace, results)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 4 || !reflect.DeepEqual(offsets, []time.Duration{10 * time.Millisecond, 30 * time.Millisecond, 30 * time.Millisecond, 30 * time.Millisecond}) {
		t.Fatalf("offsets=%v", offsets)
	}
}

func TestWireEntryCompatibilityHonorsSharedStart(t *testing.T) {
	cfg := wireFixture(1)
	// The legacy entry scheduler constructs a trace without Started; retain
	// the event's offset from the scheduler's shared start in that case too.
	cfg.Trace.Started = time.Time{}
	for i := range cfg.Trace.Sessions[0].Events {
		event := &cfg.Trace.Sessions[0].Events[i]
		event.At = time.Hour
		event.Record.Time = event.Record.Time.Add(time.Hour)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cfg.Context = ctx
	sender := &wireSender{link: wire.LinkEthernet}
	cfg.openWireSender = func(string) (backend.PacketBackend, error) { return sender, nil }
	result := ExecuteEntry(cfg, cfg.Plan.Entries[0], cfg.Trace.Sessions[0], time.Now().Add(-2*time.Hour))
	if result.Err != nil || !result.Transport.Completed || result.Transport.Sent != 2 {
		t.Fatalf("entry restarted the shared timing clock: %+v", result)
	}
}
