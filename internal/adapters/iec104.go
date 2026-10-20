package adapters

import (
	"errors"
	"fmt"

	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/replay"
)

// IEC104 replays IEC 60870-5-104 controlling-station sessions, plain or inside
// TLS (IEC 62351-3, usually port 19998). The send and receive sequence numbers
// in every I and S frame are regenerated for the live connection, because a
// controlled station closes a connection whose numbers do not follow its own
// traffic. Periodic, background-scan and spontaneous server data is serviced
// as live events: a device does not repeat captured event bursts, so only the
// responses to the captured client frames are compared.
type IEC104 struct{}

const (
	iec104SendSeqKey  = "iec104.sendSeq"
	iec104RecvSeqKey  = "iec104.recvSeq"
	iec104UnackedKey  = "iec104.unacked"
	iec104StoppingKey = "iec104.stopping"
	iec104StandardW   = 8 // acknowledge after this many unacknowledged I frames
	iec104Modulus     = 1 << 15
	iec104DefaultPort = 2404
	iec104TLSPort     = 19998
)

func (IEC104) Name() string    { return "iec104" }
func (IEC104) Version() string { return "1" }

func (IEC104) Detect(s replay.Session) replay.Confidence {
	if s.Transport != replay.TransportTCP {
		return 0
	}
	if c := portConfidence(s, iec104DefaultPort, iec104TLSPort); c > 0 {
		return c
	}
	frames, rest, err := dissect.ParseIEC104Stream(firstPayload(s))
	if err != nil || rest != 0 || len(frames) == 0 {
		return 0
	}
	first := frames[0]
	if first.Format == dissect.IEC104U && first.UFunc == dissect.IEC104StartDTAct {
		return 70
	}
	if first.Format == dissect.IEC104I && first.HasASDU && first.TypeID >= 45 && first.TypeID <= 113 {
		return 60
	}
	return 0
}

func (IEC104) Decode(_ replay.Direction, data []byte) ([]replay.Message, error) {
	frames, leftover, err := dissect.ParseIEC104Stream(data)
	if err != nil {
		return nil, err
	}
	if leftover != 0 {
		return nil, fmt.Errorf("iec104: %d trailing byte(s)", leftover)
	}
	out := make([]replay.Message, 0, len(frames))
	for _, f := range frames {
		out = append(out, iec104Message(f))
	}
	return out, nil
}

// DecodeAvailable consumes complete APDUs and leaves a partial tail for the
// next read. Live stations send event bursts that TCP segments arbitrarily.
func (IEC104) DecodeAvailable(_ replay.Direction, data []byte, _ []replay.Message, _ bool) ([]replay.Message, int, error) {
	var out []replay.Message
	off := 0
	for off < len(data) {
		f, n, err := dissect.ParseIEC104(data[off:])
		if err != nil {
			if errors.Is(err, dissect.ErrIEC104Short) || errors.Is(err, dissect.ErrIEC104Truncated) {
				break
			}
			return nil, 0, err
		}
		out = append(out, iec104Message(f))
		off += n
	}
	return out, off, nil
}

func iec104Message(f dissect.IEC104) replay.Message {
	fields := map[string]any{
		"format": f.Format.String(), "sendSeq": f.SendSeq, "recvSeq": f.RecvSeq, "frame": f,
	}
	switch f.Format {
	case dissect.IEC104U:
		fields["function"] = dissect.IEC104UFunctionName(f.UFunc)
	case dissect.IEC104I:
		if f.HasASDU {
			fields["typeId"] = f.TypeID
			fields["cot"] = f.COT
			fields["negative"] = f.Negative
			fields["commonAddress"] = f.CA
			fields["objects"] = f.ObjectCount()
			fields["unsolicited"] = f.Unsolicited()
		}
	}
	return replay.Message{Kind: "iec104", Raw: append([]byte(nil), f.Raw...), Fields: fields}
}

func iec104Frame(m replay.Message) (dissect.IEC104, error) {
	if f, ok := m.Fields["frame"].(dissect.IEC104); ok {
		return f, nil
	}
	f, n, err := dissect.ParseIEC104(m.Raw)
	if err != nil {
		return f, err
	}
	if n != len(m.Raw) {
		return f, fmt.Errorf("iec104: message holds %d trailing byte(s)", len(m.Raw)-n)
	}
	return f, nil
}

func iec104Counter(state *replay.RuntimeState, key string) uint16 {
	if state == nil {
		return 0
	}
	v, _ := state.Protocol[key].(uint16)
	return v
}

// Prepare rewrites the live send and receive sequence numbers into client I
// and S frames. U frames and the ASDU are sent as captured, after variable
// substitution.
func (IEC104) Prepare(dir replay.Direction, msg replay.Message, state *replay.RuntimeState) ([]byte, error) {
	raw := substitute(msg.Raw, state)
	f, n, err := dissect.ParseIEC104(raw)
	if err != nil {
		return nil, fmt.Errorf("iec104: prepare request: %w", err)
	}
	if n != len(raw) {
		return nil, fmt.Errorf("iec104: prepared request holds %d trailing byte(s)", len(raw)-n)
	}
	if dir != replay.ClientToServer || state == nil || f.Format == dissect.IEC104U {
		return raw, nil
	}
	if state.Protocol == nil {
		state.Protocol = map[string]any{}
	}
	f.RecvSeq = iec104Counter(state, iec104RecvSeqKey)
	if f.Format == dissect.IEC104I {
		f.SendSeq = iec104Counter(state, iec104SendSeqKey)
	}
	return f.Encode(), nil
}

// Observe tracks the live sequence numbers: every I frame we send advances the
// send counter, every I frame we receive advances the receive counter, and any
// frame carrying N(R) clears the count of unacknowledged peer frames.
func (IEC104) Observe(dir replay.Direction, _, actual replay.Message, state *replay.RuntimeState) error {
	f, err := iec104Frame(actual)
	if err != nil {
		return err
	}
	iec104Track(dir, f, state)
	return nil
}

func iec104Track(dir replay.Direction, f dissect.IEC104, state *replay.RuntimeState) {
	if state == nil {
		return
	}
	if state.Protocol == nil {
		state.Protocol = map[string]any{}
	}
	switch {
	case dir == replay.ClientToServer && f.Format == dissect.IEC104I:
		state.Protocol[iec104SendSeqKey] = uint16((int(f.SendSeq) + 1) % iec104Modulus)
		state.Protocol[iec104UnackedKey] = 0
	case dir == replay.ClientToServer && f.Format == dissect.IEC104S:
		state.Protocol[iec104UnackedKey] = 0
	case dir == replay.ClientToServer && f.Format == dissect.IEC104U:
		switch f.UFunc {
		case dissect.IEC104StopDTAct:
			state.Protocol[iec104StoppingKey] = true
		case dissect.IEC104StartDTAct:
			delete(state.Protocol, iec104StoppingKey)
		}
	case dir == replay.ServerToClient && f.Format == dissect.IEC104I:
		state.Protocol[iec104RecvSeqKey] = uint16((int(f.SendSeq) + 1) % iec104Modulus)
		unacked, _ := state.Protocol[iec104UnackedKey].(int)
		state.Protocol[iec104UnackedKey] = unacked + 1
	}
}

// LiveEvent services station-originated frames that no captured response
// describes: unsolicited or in-flight data, acknowledgements, and link tests.
// Received data is acknowledged with an S frame once the standard window of
// eight unacknowledged frames is reached, so the station keeps sending. Data
// still in flight after STOPDT act is only observed: the station is closing
// the data transfer and may already have released the connection.
func (a IEC104) LiveEvent(m replay.Message, state *replay.RuntimeState) ([]replay.Message, bool, error) {
	f, err := iec104Frame(m)
	if err != nil {
		return nil, false, err
	}
	switch f.Format {
	case dissect.IEC104I:
		iec104Track(replay.ServerToClient, f, state)
		unacked, _ := state.Protocol[iec104UnackedKey].(int)
		if stopping, _ := state.Protocol[iec104StoppingKey].(bool); unacked < iec104StandardW || stopping {
			return nil, true, nil
		}
		reply, err := a.Decode(replay.ClientToServer, dissect.IEC104SFrame(iec104Counter(state, iec104RecvSeqKey)))
		return reply, true, err
	case dissect.IEC104S:
		return nil, true, nil
	case dissect.IEC104U:
		switch f.UFunc {
		case dissect.IEC104TestFRAct:
			reply, err := a.Decode(replay.ClientToServer, dissect.IEC104UFrame(dissect.IEC104TestFRCon))
			return reply, true, err
		case dissect.IEC104TestFRCon:
			return nil, true, nil
		}
	}
	return nil, false, nil
}

// NormalizeConversation keeps the frames a controlling station drives and the
// responses they solicit. Station-scheduled traffic is removed from the
// script: unsolicited data, server acknowledgements and server link tests are
// handled live instead, together with the client replies they provoked.
func (IEC104) NormalizeConversation(turns []replay.ConversationTurn) ([]replay.ConversationTurn, error) {
	buffers := map[replay.Direction][]byte{}
	var out []replay.ConversationTurn
	commandSent := false
	for _, turn := range turns {
		buffer := append(buffers[turn.Direction], turn.Payload...)
		if len(buffer) > maxRuleFrame {
			return nil, fmt.Errorf("iec104: capture frame buffer exceeds limit")
		}
		frames, left, err := dissect.ParseIEC104Stream(buffer)
		if err != nil {
			return nil, err
		}
		buffers[turn.Direction] = append([]byte(nil), buffer[len(buffer)-left:]...)
		var payload []byte
		for _, f := range frames {
			if iec104StationScheduled(turn.Direction, f, commandSent) {
				continue
			}
			commandSent = commandSent || turn.Direction == replay.ClientToServer && f.Format == dissect.IEC104I
			payload = append(payload, f.Raw...)
		}
		if len(payload) > 0 || turn.CloseWrite {
			turn.Payload = payload
			out = append(out, turn)
		}
	}
	for _, buffer := range buffers {
		if len(buffer) > 0 {
			return nil, fmt.Errorf("iec104: incomplete captured APDU")
		}
	}
	return out, nil
}

// iec104StationScheduled reports traffic the controlled station originates on
// its own: unsolicited data, acknowledgements, link tests, and any data sent
// before this connection carried a command. A station may still answer a
// command from an earlier connection after STARTDT; a live replay cannot
// expect that stale reply, so it is observed rather than compared.
func iec104StationScheduled(dir replay.Direction, f dissect.IEC104, commandSent bool) bool {
	if dir == replay.ServerToClient {
		return f.Unsolicited() || f.Format == dissect.IEC104I && !commandSent || f.Format == dissect.IEC104S || f.Format == dissect.IEC104U && f.UFunc == dissect.IEC104TestFRAct
	}
	return f.Format == dissect.IEC104U && f.UFunc == dissect.IEC104TestFRCon
}

func (IEC104) Correlate(expected, actual replay.Message, state *replay.RuntimeState) replay.Match {
	w, werr := iec104Frame(expected)
	g, gerr := iec104Frame(actual)
	if werr != nil || gerr != nil {
		return replay.Match{Reason: "invalid IEC 104 APDU"}
	}
	if w.Format != g.Format {
		return replay.Match{Key: w.Format.String(), Reason: "frame format differs"}
	}
	switch w.Format {
	case dissect.IEC104S:
		return replay.Match{Matched: true, Key: "S"}
	case dissect.IEC104U:
		key := dissect.IEC104UFunctionName(w.UFunc)
		if w.UFunc != g.UFunc {
			return replay.Match{Key: key, Reason: "U-frame function differs"}
		}
		return replay.Match{Matched: true, Key: key}
	}
	if g.Unsolicited() && !w.Unsolicited() || state != nil && iec104Counter(state, iec104SendSeqKey) == 0 {
		return replay.Match{Key: dissect.IEC104TypeName(w.TypeID), Reason: "station-originated information"}
	}
	return replay.Match{Matched: true, Key: dissect.IEC104TypeName(w.TypeID)}
}

func (IEC104) Compare(expected, actual replay.Message, mode replay.VerifyMode) []replay.Difference {
	if mode == replay.VerifyOff {
		return nil
	}
	w, werr := iec104Frame(expected)
	g, gerr := iec104Frame(actual)
	if werr != nil || gerr != nil {
		return rawCompare(expected, actual, mode)
	}
	var out []replay.Difference
	for _, d := range dissect.CompareIEC104(w, g, mode == replay.VerifyStrict) {
		out = append(out, replay.Difference{Field: d.Field, Expected: d.Expected, Actual: d.Actual, Structural: d.Structural})
	}
	return out
}

// RestartSafe permits automatic restart only for connection control and
// interrogation, read or test commands; control and parameter commands change
// the process.
func (IEC104) RestartSafe(m replay.Message) bool {
	f, err := iec104Frame(m)
	return err == nil && f.ReadOnly()
}

func (IEC104) Capabilities() replay.Capabilities {
	return replay.Capabilities{Incremental: true, Stateful: true, Recovery: "read-only restart"}
}
