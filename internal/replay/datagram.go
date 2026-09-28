package replay

import (
	"context"
	"fmt"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/wire"
)

// DatagramInbox keeps replies that arrived before their captured response turn.
// All packets still pass through the evidence recorder. The bounded inbox never
// silently drops unmatched packets to make a replay appear successful.
type DatagramInbox struct {
	pending [][]byte
	bytes   int
}

func (q *DatagramInbox) Receive(ctx context.Context, b backend.PacketBackend, expected Event, a Adapter, state *RuntimeState, timeout time.Duration) ([]byte, bool, error) {
	matches := func(frame []byte) bool {
		ep, err := wire.Parse(transportEventFrame(expected), expected.Record.LinkType)
		if err != nil {
			return false
		}
		ap, err := wire.Parse(frame, expected.Record.LinkType)
		if err != nil {
			return false
		}
		if ep.IsICMP() {
			er, ei, es, eo := ep.ICMPEcho()
			ar, ai, as, ao := ap.ICMPEcho()
			return eo && ao && er == ar && ei == ai && es == as
		}
		if a == nil {
			return true
		}
		want, err := a.Decode(ServerToClient, ep.Payload())
		if err != nil {
			return false
		}
		got, err := a.Decode(ServerToClient, ap.Payload())
		if err != nil || len(want) != len(got) {
			return false
		}
		want, err = NormalizeExpectedMessages(a, ServerToClient, want, state)
		if err != nil {
			return false
		}
		for i := range want {
			if !a.Correlate(want[i], got[i], state).Matched {
				return false
			}
		}
		return len(want) > 0
	}
	for i, frame := range q.pending {
		if matches(frame) {
			q.pending = append(q.pending[:i], q.pending[i+1:]...)
			q.bytes -= len(frame)
			return frame, true, nil
		}
	}
	deadline := b.Now().Add(timeout)
	for {
		remaining := deadline.Sub(b.Now())
		if remaining <= 0 {
			return nil, false, nil
		}
		buf := make([]byte, 64*1024)
		n, ok, err := recvContext(ctx, b, buf, remaining)
		if err != nil || !ok {
			return nil, ok, err
		}
		frame := buf[:n]
		if matches(frame) {
			return frame, true, nil
		}
		if len(q.pending) >= 128 || q.bytes+n > 8<<20 {
			return nil, false, fmt.Errorf("resource limit: more than 128 unmatched datagrams or 8 MiB awaiting correlation")
		}
		q.pending = append(q.pending, frame)
		q.bytes += n
	}
}
