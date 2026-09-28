package adapters

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/replay"
)

type dnpMessageDecoder struct {
	transport   dissect.DNP3TransportAssembler
	application dissect.DNP3MessageAssembler
}

func dnpApplicationMessage(a dissect.DNP3Application) replay.Message {
	return replay.Message{Kind: "dnp3", Raw: a.Raw, Fields: map[string]any{"source": a.Source, "destination": a.Dest, "appSeq": a.Sequence(), "function": a.Function, "application": a}}
}

func (r *dnpMessageDecoder) push(f dissect.DNP3) (*dissect.DNP3Application, *dissect.DNP3Application, error) {
	a, err := r.transport.Push(f)
	if err != nil || a == nil {
		return nil, nil, err
	}
	m, err := r.application.Push(*a)
	return a, m, err
}

func (r *dnpMessageDecoder) incomplete() bool {
	return r.transport.Incomplete() || r.application.Incomplete()
}

func decodeDNP3Messages(data []byte) ([]replay.Message, error) {
	frames, left, err := dissect.ParseDNP3Stream(data)
	if err != nil {
		return nil, err
	}
	if left != 0 {
		return nil, io.ErrUnexpectedEOF
	}
	var decoder dnpMessageDecoder
	var out []replay.Message
	for _, f := range frames {
		_, m, err := decoder.push(f)
		if err != nil {
			return nil, err
		}
		if m != nil {
			out = append(out, dnpApplicationMessage(*m))
		}
	}
	if decoder.incomplete() {
		return nil, io.ErrUnexpectedEOF
	}
	return out, nil
}

func (a DNP3) NormalizeConversation(turns []replay.ConversationTurn) ([]replay.ConversationTurn, error) {
	decoders := map[replay.Direction]*dnpMessageDecoder{}
	buffers := map[replay.Direction][]byte{}
	var out []replay.ConversationTurn
	for _, turn := range turns {
		d := decoders[turn.Direction]
		if d == nil {
			d = &dnpMessageDecoder{}
			decoders[turn.Direction] = d
		}
		buffer := append(buffers[turn.Direction], turn.Payload...)
		if len(buffer) > maxRuleFrame {
			return nil, fmt.Errorf("dnp3: capture frame buffer exceeds limit")
		}
		frames, left, err := dissect.ParseDNP3Stream(buffer)
		if err != nil {
			return nil, err
		}
		buffers[turn.Direction] = append([]byte(nil), buffer[len(buffer)-left:]...)
		var payload []byte
		for _, frame := range frames {
			_, m, err := d.push(frame)
			if err != nil {
				return nil, err
			}
			if m == nil {
				continue
			}
			if turn.Direction == replay.ClientToServer && (m.Function == 0 && !m.LinkOnly || m.LinkOnly && m.LinkControl&0x40 == 0) {
				continue
			}
			payload = append(payload, m.Raw...)
		}
		if len(payload) > 0 || turn.CloseWrite {
			turn.Payload = payload
			out = append(out, turn)
		}
	}
	for _, d := range decoders {
		if d.incomplete() {
			return nil, fmt.Errorf("dnp3: incomplete captured application response")
		}
	}
	for _, buffer := range buffers {
		if len(buffer) > 0 {
			return nil, fmt.Errorf("dnp3: incomplete captured link frame")
		}
	}
	return out, nil
}

func (a DNP3) DecodeAvailableState(dir replay.Direction, data []byte, _ []replay.Message, eof bool, state *replay.RuntimeState) ([]replay.Message, int, error) {
	key := "dnp3.decoder." + dir.String()
	d, _ := state.Protocol[key].(*dnpMessageDecoder)
	if d == nil {
		d = &dnpMessageDecoder{}
		state.Protocol[key] = d
	}
	f, n, err := dissect.ParseDNP3(data)
	if err != nil {
		if errors.Is(err, dissect.ErrDNP3Short) || errors.Is(err, dissect.ErrDNP3Truncated) {
			if !eof {
				return nil, 0, nil
			}
			return nil, 0, io.ErrUnexpectedEOF
		}
		return nil, 0, err
	}
	fragment, message, err := d.push(f)
	if err != nil {
		return nil, 0, err
	}
	if fragment != nil && !fragment.LinkOnly {
		_, secure, err := dissect.DNP3ObjectBytes(*fragment)
		if err != nil {
			return nil, 0, err
		}
		if secure {
			return nil, 0, fmt.Errorf("dnp3: Secure Authentication requires a security-aware adapter")
		}
		if dir == replay.ServerToClient && fragment.Control&0x20 != 0 {
			state.Pending = append(state.Pending, dnpConfirmation(*fragment, state))
		}
	}
	if message == nil {
		return nil, n, nil
	}
	if message.LinkOnly {
		// Data-link acknowledgements/status are connection maintenance, not
		// application responses. Unsupported primary link requests stop safely.
		if message.LinkControl&0x40 != 0 {
			return nil, 0, fmt.Errorf("dnp3: primary link control requires a link-state adapter")
		}
		return nil, n, nil
	}
	return []replay.Message{dnpApplicationMessage(*message)}, n, nil
}

func dnpTxKey(source, dest uint16) string { return fmt.Sprintf("dnp3.txseq.%d.%d", source, dest) }

func dnpConfirmation(a dissect.DNP3Application, state *replay.RuntimeState) replay.Message {
	seq, _ := state.Protocol[dnpTxKey(a.Dest, a.Source)].(uint8)
	control := byte(0xc0) | (a.Control & 0x1f)
	f := dissect.DNP3{Control: 0xc4, Source: a.Dest, Dest: a.Source, UserData: []byte{0xc0 | seq, control, 0}}
	msgs, _ := decodeDNP3Messages(f.Encode())
	return msgs[0]
}

func compareDNP3Applications(w, g dissect.DNP3Application, mode replay.VerifyMode) []replay.Difference {
	if mode == replay.VerifyOff {
		return nil
	}
	var out []replay.Difference
	if w.Function != g.Function {
		out = append(out, replay.Difference{Field: "function", Expected: fmt.Sprint(w.Function), Actual: fmt.Sprint(g.Function), Structural: true})
	}
	if w.IIN != g.IIN {
		out = append(out, replay.Difference{Field: "indications", Expected: fmt.Sprintf("%x", w.IIN), Actual: fmt.Sprintf("%x", g.IIN), Structural: true})
	}
	wObjects, ws, we := dissect.DNP3ObjectBytes(w)
	gObjects, gs, ge := dissect.DNP3ObjectBytes(g)
	if we != nil || ge != nil || ws || gs {
		out = append(out, replay.Difference{Field: "objects", Expected: "supported plaintext object layout", Actual: "unsupported or authenticated object layout", Structural: true})
	} else if !bytes.Equal(wObjects, gObjects) {
		wLayout, we := dissect.DNP3ObjectLayout(wObjects)
		gLayout, ge := dissect.DNP3ObjectLayout(gObjects)
		structural := mode == replay.VerifyStrict || we != nil || ge != nil || !bytes.Equal(wLayout, gLayout)
		out = append(out, replay.Difference{Field: "objects", Expected: bodyDigest(wObjects), Actual: bodyDigest(gObjects), Structural: structural})
	}
	return out
}

func (a DNP3) LiveEvent(m replay.Message, state *replay.RuntimeState) ([]replay.Message, bool, error) {
	app, ok := m.Fields["application"].(dissect.DNP3Application)
	if !ok || !app.Unsolicited() {
		return nil, false, nil
	}
	return nil, true, nil // requested confirms were queued during live decoding
}

func (DNP3) ConsumedPeers(dir replay.Direction, messages []replay.Message) int {
	if dir != replay.ServerToClient {
		return len(messages)
	}
	n := 0
	for _, m := range messages {
		app, ok := m.Fields["application"].(dissect.DNP3Application)
		if !ok || !app.Unsolicited() {
			n++
		}
	}
	return n
}
