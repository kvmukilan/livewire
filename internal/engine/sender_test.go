package engine

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/units"
	"github.com/kvmukilan/livewire/internal/wire"
)

// windowPeer is independent of the captured packet schedule. It implements a
// cumulative byte receiver and releases each response fragment only after the
// preceding fragment is acknowledged, as a real small-window server can do.
type windowPeer struct {
	t                 *testing.T
	request, response []byte
	window            uint16
	mss               uint16
	dropOffset        int
	dropped           bool
	zeroUntil         int
	probes            int
	clientISN         units.Seq
	clientNext        units.Seq
	serverNext        units.Seq
	received          map[units.Seq]byte
	responseOff       int
	finSent, finalACK bool
	partialFirst      bool
	earlyFIN          bool
}

func (p *windowPeer) reply(flags uint8, data []byte, syn bool) []byte {
	frame := frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, p.serverNext.Uint32(), p.clientNext.Uint32(), flags, 200, 0, data)
	q, _ := wire.Parse(frame, wire.LinkEthernet)
	q.SetWindow(p.window)
	if syn {
		frame, _ = q.RebuildWithOptions(append(wire.SynMSS(p.mss), wire.SynTimestamp(200)...), data)
	} else {
		q.RecalcChecksums()
	}
	return frame
}

func (p *windowPeer) nextResponse() []byte {
	n := min(4, len(p.response)-p.responseOff)
	data := p.response[p.responseOff : p.responseOff+n]
	frame := p.reply(wire.FlagACK|wire.FlagPSH, data, false)
	p.responseOff += n
	p.serverNext = p.serverNext.Add(uint32(n))
	if p.earlyFIN && p.responseOff == len(p.response) {
		q, _ := wire.Parse(frame, wire.LinkEthernet)
		q.SetFlags(q.Flags() | wire.FlagFIN)
		q.RecalcChecksums()
		p.serverNext = p.serverNext.Add(1)
		p.finSent = true
	}
	return frame
}

func (p *windowPeer) OnSend(frame []byte, _ time.Time) [][]byte {
	q, err := wire.Parse(frame, wire.LinkEthernet)
	if err != nil {
		p.t.Fatal(err)
	}
	if ip, tcp := q.VerifyChecksums(); !ip || !tcp {
		p.t.Fatal("invalid emitted TCP checksum")
	}
	if q.HasFlags(wire.FlagSYN) {
		p.clientISN, p.clientNext = q.Seq(), q.Seq().Add(1)
		p.serverNext = 0xfffffff0
		p.received = map[units.Seq]byte{}
		reply := p.reply(wire.FlagSYN|wire.FlagACK, nil, true)
		p.serverNext = p.serverNext.Add(1)
		return [][]byte{reply}
	}
	if p.window == 0 && q.PayloadLen() == 0 && q.Seq() == p.clientNext.Sub(1) {
		p.probes++
		if p.probes >= p.zeroUntil {
			p.window = 17
		}
		return [][]byte{p.reply(wire.FlagACK, nil, false)}
	}
	if q.PayloadLen() > 0 {
		if q.PayloadLen() > int(p.mss) {
			p.t.Fatalf("sent %d bytes beyond peer MSS %d", q.PayloadLen(), p.mss)
		}
		if p.window == 0 || q.Seq().Add(uint32(q.PayloadLen())).Greater(p.clientNext.Add(uint32(p.window))) {
			p.t.Fatal("sent application data outside peer receive window")
		}
		off := int(p.clientISN.Add(1).Delta(q.Seq()))
		if p.dropOffset >= 0 && !p.dropped && off == p.dropOffset {
			p.dropped = true
			return [][]byte{p.reply(wire.FlagACK, nil, false)}
		}
		data := q.Payload()[:q.PayloadLen()]
		if p.partialFirst {
			data = data[:len(data)/2]
			p.partialFirst = false
		}
		for i, b := range data {
			p.received[q.Seq().Add(uint32(i))] = b
		}
		for {
			b, ok := p.received[p.clientNext]
			if !ok {
				break
			}
			i := int(p.clientISN.Add(1).Delta(p.clientNext))
			if i >= len(p.request) || b != p.request[i] {
				p.t.Fatalf("request corrupt at byte %d", i)
			}
			delete(p.received, p.clientNext)
			p.clientNext = p.clientNext.Add(1)
		}
		if p.clientISN.Add(1).Delta(p.clientNext) == uint32(len(p.request)) && p.responseOff == 0 {
			return [][]byte{p.nextResponse()}
		}
		return [][]byte{p.reply(wire.FlagACK, nil, false)}
	}
	if q.HasFlags(wire.FlagFIN) {
		if q.Seq() != p.clientNext {
			p.t.Fatal("FIN sent before contiguous client data")
		}
		p.clientNext = p.clientNext.Add(1)
		if p.finSent {
			return [][]byte{p.reply(wire.FlagACK, nil, false)}
		}
		reply := p.reply(wire.FlagFIN|wire.FlagACK, nil, false)
		p.serverNext = p.serverNext.Add(1)
		p.finSent = true
		return [][]byte{reply}
	}
	if p.finSent && q.AckNum() == p.serverNext {
		p.finalACK = true
	}
	if p.responseOff > 0 && p.responseOff < len(p.response) && q.AckNum() == p.serverNext {
		return [][]byte{p.nextResponse()}
	}
	return nil
}

func TestStatefulSenderWindowLossAndACKDrivenResponse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		drop    int
		partial bool
		window  uint16
	}{
		{"small-window", -1, false, 17},
		{"first-segment-lost", 0, false, 64},
		{"middle-segment-lost", 16, false, 64},
		{"partially-acknowledged-segment", -1, true, 64},
		{"one-byte-window", -1, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, resp := bytes.Repeat([]byte("abcdefgh"), 12), []byte("independent-response")
			f := ExtractFlows(session("10.0.0.9", "10.0.0.1", 5000, 8080, req, resp))[0]
			isn := uint32(0xfffffff0)
			c, err := NewConversation(f, Options{ClientISN: &isn}, ConvConfig{Verify: VerifyStrict})
			if err != nil {
				t.Fatal(err)
			}
			peer := &windowPeer{t: t, request: req, response: resp, window: tc.window, mss: 16, dropOffset: tc.drop, partialFirst: tc.partial}
			out, err := Drive(c, backend.NewMock(peer, c.link, time.Unix(0, 0)), 10000)
			if err != nil || !out.Succeeded() || len(out.Mismatches) != 0 || !peer.finalACK {
				t.Fatalf("sender failed: out=%+v err=%v finalACK=%v", out, err, peer.finalACK)
			}
			if (tc.drop >= 0 || tc.partial) && out.Retransmits == 0 {
				t.Fatal("loss did not exercise retransmission")
			}
			if len(c.sender.outstanding) != 0 || c.sender.una != c.clientNext {
				t.Fatal("completion left unacknowledged client bytes")
			}
		})
	}
}

func TestStatefulSenderZeroWindowReopens(t *testing.T) {
	req, resp := []byte("request"), []byte("reply")
	f := ExtractFlows(session("10.0.0.9", "10.0.0.1", 5000, 8080, req, resp))[0]
	c, err := NewConversation(f, Options{Seed: 1}, ConvConfig{Verify: VerifyStrict})
	if err != nil {
		t.Fatal(err)
	}
	peer := &windowPeer{t: t, request: req, response: resp, mss: 16, dropOffset: -1, zeroUntil: 2}
	out, err := Drive(c, backend.NewMock(peer, c.link, time.Unix(0, 0)), 1000)
	if err != nil || !out.Succeeded() || peer.probes != 2 || !peer.finalACK {
		t.Fatalf("zero-window recovery: out=%+v err=%v probes=%d", out, err, peer.probes)
	}
}

func TestStatefulSenderZeroWindowIsBounded(t *testing.T) {
	c, _ := reliabilityConversation(t, ConvConfig{ResendBudget: 2})
	peer := &windowPeer{t: t, request: []byte("request"), response: []byte("response-bytes"), mss: 16, dropOffset: -1, zeroUntil: 100}
	out, err := Drive(c, backend.NewMock(peer, c.link, time.Unix(0, 0)), 1000)
	if err != nil || !out.Aborted || peer.probes != 2 || !strings.Contains(out.Reason, "window stayed closed") {
		t.Fatalf("zero-window bound: out=%+v err=%v probes=%d", out, err, peer.probes)
	}
}

func TestPacedSenderReceivesACKsDuringCapturedGap(t *testing.T) {
	req, resp := []byte("first-second"), []byte("reply")
	f := ExtractFlows(session("10.0.0.9", "10.0.0.1", 5000, 8080, req, resp))[0]
	cp := f.Packets[3]
	parts, ok := splitTCP(cp.Rec.Data, cp.Rec.LinkType, 6)
	if !ok {
		t.Fatal("split request")
	}
	recs := recsFrom([][]byte{f.Packets[0].Rec.Data, f.Packets[1].Rec.Data, f.Packets[2].Rec.Data, parts[0], parts[1], f.Packets[4].Rec.Data, f.Packets[5].Rec.Data, f.Packets[6].Rec.Data, f.Packets[7].Rec.Data})
	// A long gap must not consume the event budget through polling alone.
	for i := 4; i < len(recs); i++ {
		recs[i].Time = recs[i].Time.Add(time.Hour)
	}
	f = ExtractFlows(recs)[0]
	c, err := NewConversation(f, Options{Seed: 1}, ConvConfig{Pace: true, Verify: VerifyStrict})
	if err != nil {
		t.Fatal(err)
	}
	peer := &windowPeer{t: t, request: req, response: resp, window: 64, mss: 16, dropOffset: -1}
	var payloadTimes []time.Time
	r := responderFunc(func(frame []byte, now time.Time) [][]byte {
		p, _ := wire.Parse(frame, c.link)
		if p.PayloadLen() > 0 {
			payloadTimes = append(payloadTimes, now)
		}
		return peer.OnSend(frame, now)
	})
	start := time.Unix(0, 0)
	out, err := Drive(c, backend.NewMock(r, c.link, start), 100)
	if err != nil || !out.Succeeded() || out.Retransmits != 0 || len(payloadTimes) != 2 {
		t.Fatalf("paced replay: out=%+v err=%v times=%v", out, err, payloadTimes)
	}
	if payloadTimes[1].Sub(start) < time.Hour {
		t.Fatal("captured gap was shortened")
	}
}

func TestSenderRejectsFutureACKAndPreservesOutstanding(t *testing.T) {
	c, _ := reliabilityConversation(t, ConvConfig{Verify: VerifyStrict})
	c.Poll(Event{Kind: EvStart})
	synack := frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9000, c.clientNext.Uint32(), wire.FlagSYN|wire.FlagACK, 9, 0, nil)
	c.Poll(Event{Kind: EvRecv, Frame: synack})
	before := c.sender.una
	bad := frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9001, c.clientNext.Add(1).Uint32(), wire.FlagACK, 10, 0, []byte("response-bytes"))
	acts := c.Poll(Event{Kind: EvRecv, Frame: bad})
	if c.sender.una != before || len(c.sender.outstanding) != 1 || c.verify.contig != 0 || len(acts) != 1 || acts[0].Kind != ActSend {
		t.Fatal("future ACK delivered data or retired outstanding bytes")
	}
	retries := c.Poll(Event{Kind: EvTimeout})
	for _, a := range retries {
		if a.Kind == ActSend {
			p, _ := wire.Parse(a.Bytes, c.link)
			if p.Seq() != before || string(p.Payload()[:p.PayloadLen()]) != "request" {
				t.Fatal("wrong outstanding range retransmitted")
			}
		}
	}
}

func TestSenderWindowScalingAndStaleUpdates(t *testing.T) {
	f := ExtractFlows(session("10.0.0.9", "10.0.0.1", 5000, 8080, bytes.Repeat([]byte("x"), 2048), []byte("reply")))[0]
	syn, _ := wire.Parse(f.Packets[0].Rec.Data, wire.LinkEthernet)
	f.Packets[0].Rec.Data, _ = syn.RebuildWithOptions([]byte{3, 3, 2}, nil)
	c, err := NewConversation(f, Options{Seed: 1}, ConvConfig{})
	if err != nil {
		t.Fatal(err)
	}
	c.Poll(Event{Kind: EvStart})
	synack := frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9000, c.clientNext.Uint32(), wire.FlagSYN|wire.FlagACK, 9, 0, nil)
	p, _ := wire.Parse(synack, c.link)
	p.SetWindow(4)
	synack, _ = p.RebuildWithOptions([]byte{3, 3, 3}, nil)
	c.Poll(Event{Kind: EvRecv, Frame: synack})
	if c.sender.window != 4 || c.sender.scale != 3 || c.sender.clientScale != 2 {
		t.Fatal("SYN window was scaled or negotiation lost")
	}
	ack := frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9001, c.clientNext.Uint32(), wire.FlagACK, 10, 0, nil)
	p, _ = wire.Parse(ack, c.link)
	p.SetWindow(10)
	p.RecalcChecksums()
	c.Poll(Event{Kind: EvRecv, Frame: ack})
	if c.sender.window != 80 {
		t.Fatalf("established window=%d want 80", c.sender.window)
	}
	old := frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9001, c.sender.una.Sub(1).Uint32(), wire.FlagACK, 10, 0, nil)
	p, _ = wire.Parse(old, c.link)
	p.SetWindow(0)
	p.RecalcChecksums()
	c.Poll(Event{Kind: EvRecv, Frame: old})
	if c.sender.window != 80 {
		t.Fatal("stale ACK shrank peer window")
	}
}

func TestReceiverClipsPayloadAndFINAtAdvertisedRightEdge(t *testing.T) {
	c, _ := reliabilityConversation(t, ConvConfig{Verify: VerifyLenient})
	c.Poll(Event{Kind: EvStart})
	synack := frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9000, c.clientNext.Uint32(), wire.FlagSYN|wire.FlagACK, 9, 0, nil)
	c.Poll(Event{Kind: EvRecv, Frame: synack})
	right := c.serverRcvd.Add(c.receiveWindow())
	frame := frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, right.Sub(2).Uint32(), c.clientNext.Uint32(), wire.FlagFIN|wire.FlagACK, 10, 0, []byte("abcd"))
	c.Poll(Event{Kind: EvRecv, Frame: frame})
	if len(c.serverPending) != 1 || c.serverPending[0].end != right || c.sender.peerFINQueued {
		t.Fatalf("accepted bytes/FIN beyond window: ranges=%v FIN=%v", c.serverPending, c.sender.peerFINQueued)
	}
	if got := len(c.verify.live); got != int(c.receiveWindow()) {
		t.Fatalf("verified %d bytes beyond advertised %d-byte window", got, c.receiveWindow())
	}
	outside := frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, right.Uint32(), c.clientNext.Uint32(), wire.FlagACK, 10, 0, nil)
	p, _ := wire.Parse(outside, c.link)
	if c.acceptableSequence(p) {
		t.Fatal("accepted zero-length segment at excluded right edge")
	}
}

func TestStatefulSenderHandlesPeerFirstClose(t *testing.T) {
	req, resp := []byte("request"), []byte("reply")
	f := ExtractFlows(session("10.0.0.9", "10.0.0.1", 5000, 8080, req, resp))[0]
	c, err := NewConversation(f, Options{Seed: 1}, ConvConfig{Verify: VerifyStrict})
	if err != nil {
		t.Fatal(err)
	}
	peer := &windowPeer{t: t, request: req, response: resp, window: 17, mss: 16, dropOffset: -1, earlyFIN: true}
	out, err := Drive(c, backend.NewMock(peer, c.link, time.Unix(0, 0)), 1000)
	if err != nil || !out.Succeeded() || !peer.finalACK || len(c.sender.outstanding) != 0 {
		t.Fatalf("peer-first close: out=%+v err=%v finalACK=%v", out, err, peer.finalACK)
	}
}

func TestSegmentSplitKeepsFINOnFinalPayload(t *testing.T) {
	frame := frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9001, 1, wire.FlagFIN|wire.FlagACK|wire.FlagPSH, 10, 0, []byte("abcdef"))
	parts, ok := splitTCP(frame, wire.LinkEthernet, 3)
	if !ok {
		t.Fatal("split failed")
	}
	first, _ := wire.Parse(parts[0], wire.LinkEthernet)
	last, _ := wire.Parse(parts[1], wire.LinkEthernet)
	if first.HasFlags(wire.FlagFIN) || first.HasFlags(wire.FlagPSH) || !last.HasFlags(wire.FlagFIN) || last.Seq() != first.Seq().Add(3) {
		t.Fatal("split duplicated FIN or broke sequence accounting")
	}
}

func TestQueuedPeerFINDiscardsFutureDataPastStreamEnd(t *testing.T) {
	c, _ := reliabilityConversation(t, ConvConfig{Verify: VerifyLenient})
	c.Poll(Event{Kind: EvStart})
	synack := frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9000, c.clientNext.Uint32(), wire.FlagSYN|wire.FlagACK, 9, 0, nil)
	c.Poll(Event{Kind: EvRecv, Frame: synack})
	// Receive future payload before an earlier out-of-order FIN reveals that
	// it lies outside the peer's stream; it must never become ACKed data.
	extra := frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9007, c.clientNext.Uint32(), wire.FlagACK, 10, 0, []byte("extra"))
	c.Poll(Event{Kind: EvRecv, Frame: extra})
	fin := frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9005, c.clientNext.Uint32(), wire.FlagACK|wire.FlagFIN, 10, 0, nil)
	c.Poll(Event{Kind: EvRecv, Frame: fin})
	if c.sender.peerFIN || len(c.serverPending) != 1 || c.serverPending[0].end != 9006 || len(c.verify.live) > 4 {
		t.Fatal("queued FIN retained invalid future payload")
	}
	if err := c.receiveRange(9001, 9005); err != nil {
		t.Fatal(err)
	}
	if c.serverRcvd != 9006 {
		t.Fatalf("ACK advanced beyond FIN: %d", c.serverRcvd)
	}
}
