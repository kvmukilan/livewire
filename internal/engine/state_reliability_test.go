package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/units"
	"github.com/kvmukilan/livewire/internal/wire"
)

type responderFunc func([]byte, time.Time) [][]byte

func (f responderFunc) OnSend(frame []byte, now time.Time) [][]byte { return f(frame, now) }

func reliabilityConversation(t *testing.T, cfg ConvConfig) (*Conversation, *MockPeer) {
	t.Helper()
	f := ExtractFlows(session("10.0.0.9", "10.0.0.1", 5000, 8080, []byte("request"), []byte("response-bytes")))[0]
	opts := Options{Seed: 42}
	c, err := NewConversation(f, opts, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c, NewMockPeer(f, BehaviorCompliant, opts)
}

func TestConversationReceivesReorderedResponse(t *testing.T) {
	for _, verify := range []VerifyMode{VerifyOff, VerifyStrict} {
		t.Run(verify.String(), func(t *testing.T) {
			c, peer := reliabilityConversation(t, ConvConfig{Verify: verify})
			r := responderFunc(func(frame []byte, now time.Time) [][]byte {
				var out [][]byte
				for _, reply := range peer.OnSend(frame, now) {
					p, err := wire.Parse(reply, c.link)
					if err != nil {
						t.Fatal(err)
					}
					if p.PayloadLen() > 1 {
						parts, ok := splitTCP(reply, c.link, p.PayloadLen()/2)
						if !ok {
							t.Fatal("split failed")
						}
						// Duplicate the tail before the missing head arrives.
						out = append(out, parts[1], parts[1], parts[0])
					} else {
						out = append(out, reply)
					}
				}
				return out
			})
			b := backend.NewMock(r, c.link, time.Unix(0, 0))
			out, err := Drive(c, b, 1000)
			if err != nil || !out.Succeeded() || out.Retransmits != 0 || len(out.Mismatches) != 0 {
				t.Fatalf("reordered response: outcome=%+v error=%v", out, err)
			}
		})
	}
}

func TestReceiveRangesAcrossWrapAndFIN(t *testing.T) {
	c := &Conversation{serverRcvd: units.Seq(0xfffffffc)}
	// The tail and FIN arrive first; overlapping retransmissions must not
	// move the cumulative ACK past the hole or count bytes twice.
	for _, r := range []sequenceRange{{1, 5}, {2, 6}, {6, 7}} {
		if err := c.receiveRange(r.start, r.end); err != nil {
			t.Fatal(err)
		}
	}
	if c.serverRcvd != 0xfffffffc || len(c.serverPending) != 1 {
		t.Fatalf("advanced across a hole: rcvd=%x ranges=%v", c.serverRcvd, c.serverPending)
	}
	if err := c.receiveRange(0xfffffffc, 1); err != nil {
		t.Fatal(err)
	}
	if c.serverRcvd != 7 || len(c.serverPending) != 0 {
		t.Fatalf("failed to join wrapped stream and FIN: rcvd=%x ranges=%v", c.serverRcvd, c.serverPending)
	}
}

func TestReceiveRangesBounded(t *testing.T) {
	c := &Conversation{serverRcvd: 100}
	if err := c.receiveRange(101, 100+maxReorderSpan+1); err == nil {
		t.Fatal("unbounded sequence gap accepted")
	}
	for i := 0; i < maxPendingRanges; i++ {
		start := units.Seq(101 + 2*i)
		if err := c.receiveRange(start, start.Add(1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.receiveRange(100+2*maxPendingRanges+1, 100+2*maxPendingRanges+2); err == nil {
		t.Fatal("unbounded receive range count accepted")
	}
}

func TestHandshakeIgnoresStaleAndUnrelatedFrames(t *testing.T) {
	c, _ := reliabilityConversation(t, ConvConfig{})
	c.Poll(Event{Kind: EvStart})
	frames := [][]byte{
		frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9000, c.sess.LiveClientISN.Uint32(), wire.FlagSYN|wire.FlagACK, 9, 0, nil),
		frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9000, c.clientNext.Add(1).Uint32(), wire.FlagSYN|wire.FlagACK, 9, 0, nil),
		frameTS("10.0.0.2", "10.0.0.9", 8080, 5000, 9000, c.clientNext.Uint32(), wire.FlagSYN|wire.FlagACK, 9, 0, nil),
		frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9000, c.clientNext.Add(1).Uint32(), wire.FlagRST|wire.FlagACK, 9, 0, nil),
		frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9000, c.clientNext.Uint32(), wire.FlagSYN|wire.FlagACK|wire.FlagFIN, 9, 0, nil),
	}
	for i, frame := range frames {
		if acts := c.Poll(Event{Kind: EvRecv, Frame: frame}); len(acts) != 0 || c.serverKnown || c.Phase() != PhaseSynSent {
			t.Fatalf("frame %d changed handshake: phase=%s actions=%v", i, c.Phase(), acts)
		}
	}
	valid := frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9000, c.clientNext.Uint32(), wire.FlagSYN|wire.FlagACK, 98765, 0, nil)
	acts := c.Poll(Event{Kind: EvRecv, Frame: valid})
	if !c.serverKnown || c.Phase() != PhaseEstablished {
		t.Fatalf("valid SYN-ACK rejected: phase=%s", c.Phase())
	}
	for _, a := range acts {
		if a.Kind != ActSend {
			continue
		}
		p, err := wire.Parse(a.Bytes, c.link)
		if err != nil {
			t.Fatal(err)
		}
		if _, echo, ok := p.Timestamps(); !ok || echo != 98765 {
			t.Fatalf("client did not echo live server timestamp: echo=%d present=%v", echo, ok)
		}
	}
}

func TestConversationRawRecoversLostSYN(t *testing.T) {
	c, peer := reliabilityConversation(t, ConvConfig{RawL4: true})
	first := true
	r := responderFunc(func(frame []byte, now time.Time) [][]byte {
		if first {
			first = false
			return nil
		}
		return peer.OnSend(frame, now)
	})
	out, err := Drive(c, backend.NewMock(r, c.link, time.Unix(0, 0)), 1000)
	if err != nil || !out.Succeeded() || out.Retransmits != 1 {
		t.Fatalf("raw lost SYN: outcome=%+v error=%v", out, err)
	}
}

func TestDriverIgnoredFramePreservesRetransmitTimer(t *testing.T) {
	c, peer := reliabilityConversation(t, ConvConfig{})
	first := true
	r := responderFunc(func(frame []byte, now time.Time) [][]byte {
		if first {
			first = false
			return [][]byte{{0}} // malformed capture noise while SYN is outstanding
		}
		return peer.OnSend(frame, now)
	})
	out, err := Drive(c, backend.NewMock(r, c.link, time.Unix(0, 0)), 1000)
	if err != nil || !out.Succeeded() || out.Retransmits != 1 {
		t.Fatalf("ignored receive disabled loss recovery: outcome=%+v error=%v", out, err)
	}
}

func TestConversationTerminalStateIgnoresLateEvents(t *testing.T) {
	for _, phase := range []Phase{PhaseClosed, PhaseAborted} {
		c, _ := reliabilityConversation(t, ConvConfig{})
		c.phase = phase
		for _, ev := range []Event{{Kind: EvStart}, {Kind: EvTimeout}, {Kind: EvRecv, Frame: frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 0, 0, wire.FlagRST, 0, 0, nil)}} {
			if acts := c.Poll(ev); len(acts) != 0 || c.phase != phase {
				t.Fatalf("late event changed terminal %s: phase=%s actions=%v", phase, c.phase, acts)
			}
		}
	}
}

func TestConversationRawHandshakeHasFiniteRetryBudget(t *testing.T) {
	c, _ := reliabilityConversation(t, ConvConfig{RawL4: true, ResendBudget: 2})
	r := responderFunc(func([]byte, time.Time) [][]byte { return nil })
	out, err := Drive(c, backend.NewMock(r, c.link, time.Unix(0, 0)), 1000)
	if err != nil || !out.Aborted || out.Retransmits != 2 || !strings.Contains(out.Reason, "no progress") {
		t.Fatalf("raw handshake did not exhaust retry budget: outcome=%+v error=%v", out, err)
	}
}

func TestConversationVerifiesSYNACKPayload(t *testing.T) {
	frames := [][]byte{
		frameTS("10.0.0.9", "10.0.0.1", 5000, 8080, 1000, 0, wire.FlagSYN, 1, 0, nil),
		frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 5000, 1001, wire.FlagSYN|wire.FlagACK, 2, 1, []byte("hello")),
		frameTS("10.0.0.9", "10.0.0.1", 5000, 8080, 1001, 5006, wire.FlagACK, 3, 2, nil),
	}
	f := ExtractFlows(recsFrom(frames))[0]
	opts := Options{Seed: 42}
	c, err := NewConversation(f, opts, ConvConfig{Verify: VerifyStrict})
	if err != nil {
		t.Fatal(err)
	}
	peer := NewMockPeer(f, BehaviorCompliant, opts)
	out, err := Drive(c, backend.NewMock(peer, c.link, time.Unix(0, 0)), 1000)
	if err != nil || !out.Succeeded() || out.ObservedResponseBytes != 5 || out.ComparedResponseBytes != 5 || len(out.Mismatches) != 0 {
		t.Fatalf("SYN-ACK payload lost: outcome=%+v error=%v", out, err)
	}
	if c.serverRcvd != units.Seq(peer.HiddenISN()).Add(6) {
		t.Fatalf("SYN payload incorrectly acknowledged: rcvd=%x", c.serverRcvd)
	}
}

func TestConversationHandshakeACKMayPartlyAcknowledgeSYNPayload(t *testing.T) {
	for _, consumed := range []uint32{1, 3, 6} {
		c, _ := reliabilityConversation(t, ConvConfig{})
		c.Poll(Event{Kind: EvStart})
		// SYN plus five bytes sent: RFC 9293 accepts any ACK after ISS up
		// through SND.NXT, including a server declining the early payload.
		c.clientNext = c.sess.LiveClientISN.Add(6)
		frame := frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9000, c.sess.LiveClientISN.Add(consumed).Uint32(), wire.FlagSYN|wire.FlagACK, 9, 0, nil)
		c.Poll(Event{Kind: EvRecv, Frame: frame})
		if !c.serverKnown {
			t.Fatalf("legal SYN ACK acknowledging %d sequence bytes rejected", consumed)
		}
	}
}

func TestConversationRSTMustMatchEstablishedReceiveSequence(t *testing.T) {
	c, _ := reliabilityConversation(t, ConvConfig{})
	c.Poll(Event{Kind: EvStart})
	synack := frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9000, c.clientNext.Uint32(), wire.FlagSYN|wire.FlagACK, 9, 0, nil)
	c.Poll(Event{Kind: EvRecv, Frame: synack})
	for _, seq := range []uint32{9000, 9002} {
		rst := frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, seq, c.clientNext.Uint32(), wire.FlagRST|wire.FlagACK, 10, 0, nil)
		acts := c.Poll(Event{Kind: EvRecv, Frame: rst})
		if c.Phase() != PhaseEstablished {
			t.Fatalf("out-of-sequence RST changed connection: seq=%d phase=%s", seq, c.Phase())
		}
		if seq == 9002 && (len(acts) != 1 || acts[0].Kind != ActSend) {
			t.Fatal("in-window RST did not elicit challenge ACK")
		}
	}
	rst := frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9001, c.clientNext.Uint32(), wire.FlagRST|wire.FlagACK, 10, 0, nil)
	c.Poll(Event{Kind: EvRecv, Frame: rst})
	if c.Phase() != PhaseAborted {
		t.Fatal("valid established RST did not abort")
	}
}

func TestServerTimestampEchoDoesNotRegressOnRetransmission(t *testing.T) {
	c, _ := reliabilityConversation(t, ConvConfig{})
	for _, ts := range []uint32{0xfffffffd, 0xfffffffe, 1, 0xffffffff} {
		p, err := wire.Parse(frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9001, 1, wire.FlagACK, ts, 0, nil), c.link)
		if err != nil {
			t.Fatal(err)
		}
		c.observeServerTimestamp(p)
	}
	if got := c.sess.lastLiveTS[S2C]; got != 1 {
		t.Fatalf("timestamp regressed across wrap: %x", got)
	}
}

type noisyBackend struct {
	*backend.MockBackend
	now time.Time
}

func (b *noisyBackend) Now() time.Time { return b.now }

func (b *noisyBackend) Recv(buf []byte, _ time.Duration) (int, bool, error) {
	b.now = b.now.Add(50 * time.Millisecond)
	buf[0] = 0 // queued capture noise; Recv never reports a timeout
	return 1, true, nil
}

func TestDriverContinuousNoiseCannotStarveRetryDeadline(t *testing.T) {
	c, _ := reliabilityConversation(t, ConvConfig{ResendBudget: 2, RTO: 100 * time.Millisecond})
	start := time.Unix(0, 0)
	r := responderFunc(func([]byte, time.Time) [][]byte { return nil })
	b := &noisyBackend{MockBackend: backend.NewMock(r, c.link, start), now: start}
	out, err := Drive(c, b, 100)
	if err != nil || !out.Aborted || out.Retransmits != 2 || !strings.Contains(out.Reason, "no progress") {
		t.Fatalf("continuous receives starved timer: outcome=%+v error=%v", out, err)
	}
}

func TestConversationIgnoresInvalidEstablishedFlags(t *testing.T) {
	c, _ := reliabilityConversation(t, ConvConfig{Verify: VerifyStrict})
	c.Poll(Event{Kind: EvStart})
	synack := frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9000, c.clientNext.Uint32(), wire.FlagSYN|wire.FlagACK, 9, 0, nil)
	c.Poll(Event{Kind: EvRecv, Frame: synack})
	for _, flags := range []uint8{wire.FlagPSH, wire.FlagFIN, wire.FlagSYN | wire.FlagACK} {
		frame := frameTS("10.0.0.1", "10.0.0.9", 8080, 5000, 9001, c.clientNext.Uint32(), flags, 10, 0, []byte("response-bytes"))
		if acts := c.Poll(Event{Kind: EvRecv, Frame: frame}); c.serverRcvd != 9001 || c.verify.contig != 0 {
			t.Fatalf("flags %02x incorrectly delivered response: actions=%v rcvd=%d", flags, acts, c.serverRcvd)
		}
	}
}

func TestExtractFlowsSeparatesTupleReuseAndRetainsSYNRetry(t *testing.T) {
	first := session("10.0.0.9", "10.0.0.1", 5000, 8080, []byte("first"), []byte("response"))
	second := session("10.0.0.9", "10.0.0.1", 5000, 8080, []byte("second"), []byte("reply"))
	// Identical SYN retransmission before establishment belongs to this flow.
	records := append([]*pcapio.Record{first[0]}, first...)
	records = append(records, nil) // damaged caller input is ignored consistently
	records = append(records, second...)
	flows := ExtractFlows(records)
	if len(flows) != 2 || len(flows[0].Packets) != len(first)+1 || len(flows[1].Packets) != len(second) {
		t.Fatalf("closed four-tuple reuse merged connections: flows=%d", len(flows))
	}
	// A new ISN also starts a new incarnation when the earlier connection's
	// teardown was not captured.
	newFlow := ExtractFlows(second)[0]
	s := NewSession(newFlow, 12345, 100, 200)
	s.SetServerISN(54321)
	for i, cp := range newFlow.Packets {
		frame, _, err := s.Rewrite(cp)
		if err != nil {
			t.Fatal(err)
		}
		copyRec := *second[i]
		copyRec.Data = frame
		second[i] = &copyRec
	}
	flows = ExtractFlows(append(append([]*pcapio.Record(nil), first[:5]...), second...))
	if len(flows) != 2 || flows[0].CapClientISN != 1000 || flows[1].CapClientISN != 12345 || flows[1].CapServerISN != 54321 {
		t.Fatalf("new SYN overwrote an earlier connection's ISNs: %+v", flows)
	}
}
