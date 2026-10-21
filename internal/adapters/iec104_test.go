package adapters

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/replay"
)

func iec104Burst(sendSeq, recvSeq uint16, count int, cot uint8, stamp byte) []byte {
	asdu := []byte{30, byte(count), cot, 0, 1, 0}
	for i := 0; i < count; i++ {
		asdu = append(asdu, byte(0x26+i), 0x1e, 0x00, byte(i&1), stamp, 0x55, 0x25, 0x0c, 0x14, 0x0a, 0x1a)
	}
	f := dissect.IEC104{Raw: append([]byte{0x68, byte(4 + len(asdu)), 0, 0, 0, 0}, asdu...), Format: dissect.IEC104I, SendSeq: sendSeq, RecvSeq: recvSeq}
	return f.Encode()
}

var (
	iec104Reset    = []byte{0x68, 0x0e, 0x00, 0x00, 0x04, 0x00, 0x69, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01}
	iec104ResetNeg = []byte{0x68, 0x0e, 0x08, 0x00, 0x02, 0x00, 0x69, 0x01, 0x47, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01}
)

func iec104Session(port uint16, payload []byte) replay.Session {
	return replay.Session{Transport: replay.TransportTCP,
		Client: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.10"), Port: 40000},
		Server: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.20"), Port: port},
		Events: []replay.Event{{Direction: replay.ClientToServer, Payload: payload}}}
}

func TestIEC104Detection(t *testing.T) {
	a := IEC104{}
	if c := a.Detect(iec104Session(2404, nil)); c != 80 {
		t.Fatalf("port 2404: %d", c)
	}
	if c := a.Detect(iec104Session(19998, nil)); c != 80 {
		t.Fatalf("secure port 19998: %d", c)
	}
	if c := a.Detect(iec104Session(5000, dissect.IEC104UFrame(dissect.IEC104StartDTAct))); c != 70 {
		t.Fatalf("STARTDT content: %d", c)
	}
	if c := a.Detect(iec104Session(5000, iec104Reset)); c != 60 {
		t.Fatalf("command content: %d", c)
	}
	if c := a.Detect(iec104Session(5000, []byte("GET / HTTP/1.1\r\n"))); c != 0 {
		t.Fatalf("HTTP content: %d", c)
	}
	udp := iec104Session(2404, nil)
	udp.Transport = replay.TransportUDP
	if c := a.Detect(udp); c != 0 {
		t.Fatalf("UDP: %d", c)
	}
	best, score := DefaultRegistry().Best(iec104Session(2404, dissect.IEC104UFrame(dissect.IEC104StartDTAct)))
	if best == nil || best.Name() != "iec104" || score != 80 {
		t.Fatalf("registry: %v %d", best, score)
	}
	if Versions()["iec104"] != "1" {
		t.Fatalf("version: %v", Versions())
	}
}

func TestIEC104DecodeAndIncrementalFraming(t *testing.T) {
	a := IEC104{}
	stream := append(append([]byte(nil), dissect.IEC104UFrame(dissect.IEC104StartDTCon)...), iec104Burst(0, 1, 21, 3, 8)...)
	messages, err := a.Decode(replay.ServerToClient, stream)
	if err != nil || len(messages) != 2 || messages[0].Fields["format"] != "U" || messages[1].Fields["unsolicited"] != true {
		t.Fatalf("decode: %v %+v", err, messages)
	}
	if _, err := a.Decode(replay.ServerToClient, stream[:len(stream)-1]); err == nil {
		t.Fatal("truncated stream must not decode")
	}
	partial, n, err := a.DecodeAvailable(replay.ServerToClient, stream[:len(stream)-5], nil, false)
	if err != nil || n != 6 || len(partial) != 1 {
		t.Fatalf("incremental: n=%d messages=%d err=%v", n, len(partial), err)
	}
	if _, _, err := a.DecodeAvailable(replay.ServerToClient, []byte{0x00, 0x04}, nil, false); err == nil {
		t.Fatal("malformed start byte must be an error, not need-more-data")
	}
}

func TestIEC104PrepareRegeneratesLiveSequenceNumbers(t *testing.T) {
	a := IEC104{}
	state := replay.NewRuntimeState(nil)
	// Three station I frames arrive before the captured command is sent.
	for i := uint16(0); i < 3; i++ {
		live, _ := a.Decode(replay.ServerToClient, iec104Burst(i, 0, 2, 3, 8))
		if err := a.Observe(replay.ServerToClient, live[0], live[0], state); err != nil {
			t.Fatal(err)
		}
	}
	captured, _ := a.Decode(replay.ClientToServer, iec104Reset)
	prepared, err := a.Prepare(replay.ClientToServer, captured[0], state)
	if err != nil {
		t.Fatal(err)
	}
	f, _, _ := dissect.ParseIEC104(prepared)
	if f.SendSeq != 0 || f.RecvSeq != 3 || !bytes.Equal(prepared[6:], iec104Reset[6:]) {
		t.Fatalf("prepared control field: %+v", f)
	}
	live, _ := a.Decode(replay.ClientToServer, prepared)
	if err := a.Observe(replay.ClientToServer, captured[0], live[0], state); err != nil {
		t.Fatal(err)
	}
	ack, _ := a.Decode(replay.ClientToServer, []byte{0x68, 0x04, 0x01, 0x00, 0x04, 0x00})
	prepared, _ = a.Prepare(replay.ClientToServer, ack[0], state)
	if !bytes.Equal(prepared, dissect.IEC104SFrame(3)) {
		t.Fatalf("S frame: %x", prepared)
	}
	second, _ := a.Prepare(replay.ClientToServer, captured[0], state)
	f, _, _ = dissect.ParseIEC104(second)
	if f.SendSeq != 1 {
		t.Fatalf("second command N(S): %+v", f)
	}
	u, _ := a.Decode(replay.ClientToServer, dissect.IEC104UFrame(dissect.IEC104StopDTAct))
	prepared, _ = a.Prepare(replay.ClientToServer, u[0], state)
	if !bytes.Equal(prepared, u[0].Raw) {
		t.Fatalf("U frames are sent as captured: %x", prepared)
	}
	if _, err := a.Prepare(replay.ClientToServer, replay.Message{Raw: []byte{0x68, 0x04, 0x07, 0x00, 0x00, 0x00, 0xff}}, state); err == nil {
		t.Fatal("trailing bytes must fail preparation")
	}
}

func TestIEC104NormalizeConversationDropsStationScheduledTraffic(t *testing.T) {
	turns := []replay.ConversationTurn{
		{Direction: replay.ClientToServer, Payload: dissect.IEC104UFrame(dissect.IEC104StartDTAct), At: 1},
		{Direction: replay.ServerToClient, Payload: dissect.IEC104UFrame(dissect.IEC104StartDTCon), At: 2},
		{Direction: replay.ServerToClient, Payload: iec104Burst(0, 0, 21, 3, 8)[:100], At: 3},
		{Direction: replay.ServerToClient, Payload: append(iec104Burst(0, 0, 21, 3, 8)[100:], iec104Burst(1, 0, 21, 3, 9)...), At: 4},
		{Direction: replay.ServerToClient, Payload: dissect.IEC104UFrame(dissect.IEC104TestFRAct), At: 5},
		{Direction: replay.ClientToServer, Payload: dissect.IEC104UFrame(dissect.IEC104TestFRCon), At: 6},
		// A confirmation for a command from an earlier connection arrives
		// before this connection carried any command.
		{Direction: replay.ServerToClient, Payload: iec104ResetNeg, At: 6},
		{Direction: replay.ClientToServer, Payload: iec104Reset, At: 7},
		{Direction: replay.ServerToClient, Payload: append(iec104ResetNeg, iec104Burst(3, 1, 21, 3, 10)...), At: 8},
		{Direction: replay.ServerToClient, Payload: dissect.IEC104SFrame(1), At: 9},
		{Direction: replay.ClientToServer, Payload: dissect.IEC104UFrame(dissect.IEC104StopDTAct), At: 10},
		{Direction: replay.ServerToClient, Payload: dissect.IEC104UFrame(dissect.IEC104StopDTCon), At: 11},
	}
	a := IEC104{}
	out, err := a.NormalizeConversation(turns)
	if err != nil {
		t.Fatal(err)
	}
	want := []replay.ConversationTurn{turns[0], turns[1], turns[7], {Direction: replay.ServerToClient, Payload: iec104ResetNeg, At: 8}, turns[10], turns[11]}
	if len(out) != len(want) {
		t.Fatalf("normalized %d turns, want %d: %+v", len(out), len(want), out)
	}
	for i := range want {
		if out[i].Direction != want[i].Direction || out[i].At != want[i].At || !bytes.Equal(out[i].Payload, want[i].Payload) {
			t.Fatalf("turn %d: %+v want %+v", i, out[i], want[i])
		}
	}
	if _, err := a.NormalizeConversation(turns[:3]); err == nil {
		t.Fatal("incomplete captured APDU must be rejected")
	}
}

func TestIEC104LiveEventsAcknowledgeAndAnswerLinkTests(t *testing.T) {
	a := IEC104{}
	state := replay.NewRuntimeState(nil)
	for i := 0; i < iec104StandardW; i++ {
		event, _ := a.Decode(replay.ServerToClient, iec104Burst(uint16(i), 0, 1, 3, 8))
		replies, handled, err := a.LiveEvent(event[0], state)
		if err != nil || !handled {
			t.Fatalf("event %d: handled=%v err=%v", i, handled, err)
		}
		if i < iec104StandardW-1 && len(replies) != 0 {
			t.Fatalf("event %d acknowledged early", i)
		}
		if i == iec104StandardW-1 && (len(replies) != 1 || !bytes.Equal(replies[0].Raw, dissect.IEC104SFrame(iec104StandardW))) {
			t.Fatalf("window acknowledgement: %+v", replies)
		}
	}
	stop, _ := a.Decode(replay.ClientToServer, dissect.IEC104UFrame(dissect.IEC104StopDTAct))
	if err := a.Observe(replay.ClientToServer, stop[0], stop[0], state); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2*iec104StandardW; i++ {
		event, _ := a.Decode(replay.ServerToClient, iec104Burst(uint16(iec104StandardW+i), 0, 1, 3, 8))
		if replies, handled, err := a.LiveEvent(event[0], state); err != nil || !handled || len(replies) != 0 {
			t.Fatalf("data after STOPDT act is observed without acknowledgement: %+v %v %v", replies, handled, err)
		}
	}
	test, _ := a.Decode(replay.ServerToClient, dissect.IEC104UFrame(dissect.IEC104TestFRAct))
	replies, handled, err := a.LiveEvent(test[0], state)
	if err != nil || !handled || len(replies) != 1 || !bytes.Equal(replies[0].Raw, dissect.IEC104UFrame(dissect.IEC104TestFRCon)) {
		t.Fatalf("TESTFR: %+v %v %v", replies, handled, err)
	}
	ack, _ := a.Decode(replay.ServerToClient, dissect.IEC104SFrame(1))
	if _, handled, _ := a.LiveEvent(ack[0], state); !handled {
		t.Fatal("station acknowledgements are live events")
	}
	con, _ := a.Decode(replay.ServerToClient, dissect.IEC104UFrame(dissect.IEC104StopDTCon))
	if _, handled, _ := a.LiveEvent(con[0], state); handled {
		t.Fatal("STOPDT con belongs to the captured exchange")
	}
}

func TestIEC104CorrelateAndCompare(t *testing.T) {
	a := IEC104{}
	expected, _ := a.Decode(replay.ServerToClient, iec104ResetNeg)
	live, _ := a.Decode(replay.ServerToClient, iec104Burst(9, 1, 2, 3, 8))
	if a.Correlate(expected[0], live[0], nil).Matched {
		t.Fatal("spontaneous data must not satisfy a command confirmation")
	}
	renumbered, _ := a.Decode(replay.ServerToClient, dissect.IEC104{Raw: iec104ResetNeg, Format: dissect.IEC104I, SendSeq: 77, RecvSeq: 5}.Encode())
	if m := a.Correlate(expected[0], renumbered[0], nil); !m.Matched {
		t.Fatalf("live sequence numbers must not break correlation: %+v", m)
	}
	state := replay.NewRuntimeState(nil)
	if m := a.Correlate(expected[0], renumbered[0], state); m.Matched {
		t.Fatalf("a reply before any command on this connection is station-originated: %+v", m)
	}
	state.Protocol[iec104SendSeqKey] = uint16(1)
	if m := a.Correlate(expected[0], renumbered[0], state); !m.Matched {
		t.Fatalf("reply after a command: %+v", m)
	}
	if diffs := a.Compare(expected[0], renumbered[0], replay.VerifyStrict); len(diffs) != 0 {
		t.Fatalf("sequence numbers are never compared: %+v", diffs)
	}
	positive := append([]byte(nil), iec104ResetNeg...)
	positive[8] = 0x07
	other, _ := a.Decode(replay.ServerToClient, positive)
	diffs := a.Compare(expected[0], other[0], replay.VerifyLenient)
	if len(diffs) != 1 || diffs[0].Field != "cot" || !diffs[0].Structural || diffs[0].Expected != "7 negative" {
		t.Fatalf("cot comparison: %+v", diffs)
	}
	u, _ := a.Decode(replay.ServerToClient, dissect.IEC104UFrame(dissect.IEC104StopDTCon))
	if m := a.Correlate(expected[0], u[0], nil); m.Matched || m.Reason != "frame format differs" {
		t.Fatalf("format correlation: %+v", m)
	}
	if a.Compare(expected[0], other[0], replay.VerifyOff) != nil {
		t.Fatal("verify off compares nothing")
	}
	if !a.RestartSafe(u[0]) || a.RestartSafe(expected[0]) {
		t.Fatal("restart safety")
	}
}
