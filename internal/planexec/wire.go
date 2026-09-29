package planexec

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/runstate"
	"github.com/kvmukilan/livewire/internal/stateless"
)

type wireFrame struct {
	entry int
	event replay.Event
}

// executeWirePlan owns one sender for the entire selected capture. Session
// workers cannot preserve cross-session packet order, particularly when the
// capture has more interleaved sessions than the worker limit.
func executeWirePlan(cfg Config, started time.Time) []Result {
	byID := make(map[string]*replay.Session, len(cfg.Trace.Sessions))
	for _, session := range cfg.Trace.Sessions {
		byID[session.ID] = session
	}
	var results []Result
	for _, entry := range cfg.Plan.Entries {
		if !entry.Excluded {
			results = append(results, Result{Entry: entry, Session: byID[entry.SessionID], Transport: replay.TransportResult{
				SessionID: entry.SessionID, Mode: replay.ModeWire, Fidelity: replay.FidelityWire,
			}})
		}
	}
	frames, schedule, err := wirePlanFrames(cfg.Trace, results)
	if err == nil {
		err = cfg.Context.Err()
	}
	if err != nil {
		for i := range results {
			results[i].Err, results[i].Transport.Error = err, err.Error()
		}
		return results
	}
	contexts := make([]context.Context, len(results))
	saved := make([]bool, len(results))
	intent := make([]bool, len(results))
	expected := make([]int, len(results))
	for _, frame := range frames {
		expected[frame.entry]++
	}
	var sender backend.PacketBackend
	var runErr error
	failedEntry := -1
	defer func() {
		var closeErr error
		if sender != nil {
			if err := sender.Close(); err != nil {
				closeErr = fmt.Errorf("close wire backend: %w", err)
			}
		}
		// A new completion is durable only after shared backend cleanup. A
		// later send failure does not erase a fully emitted earlier session;
		// a cleanup failure invalidates every newly emitted session.
		for i := range results {
			if saved[i] {
				continue
			}
			result := &results[i]
			entryErr := runErr
			if result.Transport.Sent == expected[i] && failedEntry != i {
				entryErr = nil
			}
			entryErr = errors.Join(entryErr, closeErr)
			result.Transport.Completed = entryErr == nil && result.Transport.Sent == expected[i]
			if contexts[i] != nil {
				entryErr = errors.Join(entryErr, replay.FinishSession(contexts[i], runstate.Result{
					Completed: result.Transport.Completed, Sent: result.Transport.Sent,
				}))
			}
			result.Err = entryErr
			if entryErr != nil {
				result.Transport.Completed = false
				result.Transport.Error = entryErr.Error()
			} else {
				cfg.Progress(result.Entry, "wire", fmt.Sprintf("wire replay sent %d frame(s); no live adaptation claimed", result.Transport.Sent))
			}
		}
	}()
	active := 0
	for i := range results {
		ctx, previous, err := replay.BeginSession(cfg.Context, results[i].Entry.SessionID, false)
		if err != nil {
			runErr = err
			return results
		}
		contexts[i] = ctx
		if previous != nil {
			saved[i] = true
			results[i].Transport.Completed = previous.Completed
			results[i].Transport.Sent = previous.Sent
		} else {
			active++
		}
	}
	if active == 0 {
		return results
	}
	if runErr = cfg.Context.Err(); runErr != nil {
		return results
	}
	sender, runErr = cfg.openWireSender(cfg.Iface)
	if runErr != nil {
		return results
	}
	if sender.LinkType() != frames[0].event.Record.LinkType {
		runErr = fmt.Errorf("wire capture link type %d differs from interface link type %d", frames[0].event.Record.LinkType, sender.LinkType())
		return results
	}
	if started.IsZero() {
		started = time.Now()
	}
	for k, frame := range frames {
		i := frame.entry
		if saved[i] {
			continue
		}
		ctx := contexts[i]
		if !waitOffset(ctx, started, schedule[k]) {
			runErr = ctx.Err()
			return results
		}
		if !intent[i] {
			if runErr = replay.RecordOperation(ctx, "intent", 0); runErr != nil {
				return results
			}
			intent[i] = true
		}
		if runErr = ctx.Err(); runErr != nil {
			return results
		}
		data := append([]byte(nil), frame.event.Record.Data...)
		if runErr = sender.Send(data); runErr != nil {
			return results
		}
		result := &results[i].Transport
		result.Sent++
		record := pcapio.Record{Time: sender.Now(), CapLen: len(data), OrigLen: len(data), Data: data, LinkType: sender.LinkType()}
		if sink := replay.Execution(ctx).Evidence; sink != nil {
			if runErr = sink(record); runErr != nil {
				failedEntry = i
				return results
			}
		} else {
			result.Evidence = append(result.Evidence, record)
		}
	}
	return results
}

// Validate every selected frame before opening the interface or writing a send
// intent. Capture indexes, rather than timestamps or session order, determine
// emission order; tied and backward timestamps must never reorder frames.
func wirePlanFrames(trace *replay.Trace, results []Result) ([]wireFrame, []time.Duration, error) {
	var frames []wireFrame
	indexes := make(map[int]bool)
	ids := make(map[string]bool)
	for i, result := range results {
		entry := result.Entry
		if entry.Mode != replay.ModeWire || entry.SessionID == "" || ids[entry.SessionID] {
			return nil, nil, fmt.Errorf("invalid wire plan entry %q", entry.SessionID)
		}
		ids[entry.SessionID] = true
		var events []replay.Event
		if result.Session != nil {
			events = result.Session.Events
		} else if entry.SessionID == "raw-0" {
			events = trace.Raw
		} else {
			return nil, nil, fmt.Errorf("wire session %s is missing from trace", entry.SessionID)
		}
		selected := make(map[int]bool, len(entry.PacketIndexes))
		for _, index := range entry.PacketIndexes {
			selected[index] = true
		}
		if len(events) == 0 || len(events) != len(entry.PacketIndexes) || len(selected) != len(events) {
			return nil, nil, fmt.Errorf("wire session %s has inconsistent packet coverage", entry.SessionID)
		}
		for _, event := range events {
			if event.PacketIndex < 0 || !selected[event.PacketIndex] || indexes[event.PacketIndex] {
				return nil, nil, fmt.Errorf("wire packet %d has inconsistent or duplicate coverage", event.PacketIndex)
			}
			indexes[event.PacketIndex] = true
			record := event.Record
			if record == nil || len(record.Data) == 0 {
				return nil, nil, fmt.Errorf("wire packet %d has no captured frame bytes", event.PacketIndex)
			}
			if len(record.Data) < record.OrigLen {
				return nil, nil, fmt.Errorf("wire packet %d is snaplen-truncated", event.PacketIndex)
			}
			if len(frames) > 0 && record.LinkType != frames[0].event.Record.LinkType {
				return nil, nil, pcapio.ErrMixedLinks
			}
			frames = append(frames, wireFrame{entry: i, event: event})
		}
	}
	sort.Slice(frames, func(i, j int) bool { return frames[i].event.PacketIndex < frames[j].event.PacketIndex })
	records := make([]*pcapio.Record, 0, len(frames)+1)
	// Keep the capture's time origin when selected/resumed sessions omit its
	// first frame, matching the other timing-profile runners.
	origin := trace.Started
	if origin.IsZero() && len(frames) > 0 {
		origin = frames[0].event.Record.Time.Add(-frames[0].event.At)
	}
	if !origin.IsZero() {
		records = append(records, &pcapio.Record{Time: origin})
	}
	for _, frame := range frames {
		records = append(records, frame.event.Record)
	}
	schedule, err := stateless.CheckedSchedule(records, stateless.Pace{})
	if !origin.IsZero() && len(schedule) > 0 {
		schedule = schedule[1:]
	}
	return frames, schedule, err
}
