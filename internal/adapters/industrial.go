package adapters

import (
	"bytes"
	"fmt"

	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/replay"
)

type Modbus struct{}

func (Modbus) Name() string { return "modbus-tcp" }
func (Modbus) Detect(s replay.Session) replay.Confidence {
	if s.Transport != replay.TransportTCP {
		return 0
	}
	if c := portConfidence(s, 502); c > 0 {
		return c
	}
	if adus, rest, err := dissect.ParseModbusStream(firstPayload(s)); err == nil && len(adus) > 0 && rest == 0 {
		return 65
	}
	return 0
}
func (Modbus) Decode(_ replay.Direction, data []byte) ([]replay.Message, error) {
	adus, leftover, err := dissect.ParseModbusStream(data)
	if err != nil {
		return nil, err
	}
	if leftover != 0 {
		return nil, fmt.Errorf("modbus: %d trailing bytes", leftover)
	}
	out := make([]replay.Message, 0, len(adus))
	for _, a := range adus {
		out = append(out, replay.Message{Kind: "modbus", Raw: append([]byte(nil), a.Raw...), Fields: map[string]any{
			"transactionId": a.TransactionID, "unitId": a.UnitID, "function": a.Function, "data": append([]byte(nil), a.Data...),
		}})
	}
	return out, nil
}
func (Modbus) Prepare(_ replay.Direction, msg replay.Message, state *replay.RuntimeState) ([]byte, error) {
	return substitute(msg.Raw, state), nil
}
func (Modbus) Correlate(expected, actual replay.Message, _ *replay.RuntimeState) replay.Match {
	id := fmt.Sprint(expected.Fields["transactionId"])
	if id != fmt.Sprint(actual.Fields["transactionId"]) || fmt.Sprint(expected.Fields["unitId"]) != fmt.Sprint(actual.Fields["unitId"]) {
		return replay.Match{Key: id, Reason: "transaction or unit differs"}
	}
	w, _ := expected.Fields["function"].(uint8)
	g, _ := actual.Fields["function"].(uint8)
	return replay.Match{Matched: w&0x7f == g&0x7f, Key: id, Reason: "function differs"}
}

func (Modbus) ResponseKey(m replay.Message) string {
	return fmt.Sprint(m.Fields["transactionId"]) + ":" + fmt.Sprint(m.Fields["unitId"])
}
func (Modbus) Compare(expected, actual replay.Message, mode replay.VerifyMode) []replay.Difference {
	w, _, ew := dissect.ParseMBAP(expected.Raw)
	g, _, eg := dissect.ParseMBAP(actual.Raw)
	if ew != nil || eg != nil {
		return rawCompare(expected, actual, mode)
	}
	var out []replay.Difference
	for _, d := range dissect.CompareADU(w, g) {
		out = append(out, replay.Difference{Field: "adu", Expected: d.Detail, Structural: d.Structural || mode == replay.VerifyStrict})
	}
	return out
}

type DNP3 struct{}

func (DNP3) Name() string { return "dnp3" }
func (DNP3) Detect(s replay.Session) replay.Confidence {
	if c := portConfidence(s, 20000); c > 0 {
		return c
	}
	p := firstPayload(s)
	if len(p) >= 2 && p[0] == 0x05 && p[1] == 0x64 {
		return 70
	}
	return 0
}
func (DNP3) Decode(_ replay.Direction, data []byte) ([]replay.Message, error) {
	return decodeDNP3Messages(data)
}
func (DNP3) Prepare(dir replay.Direction, msg replay.Message, state *replay.RuntimeState) ([]byte, error) {
	raw := substitute(msg.Raw, state)
	frames, rest, err := dissect.ParseDNP3Stream(raw)
	if err != nil {
		return nil, err
	}
	if rest != 0 {
		return nil, fmt.Errorf("dnp3: incomplete request frame")
	}
	var out []byte
	next := map[string]uint8{}
	for _, d := range frames {
		if state != nil && d.HasApp && d.TransportFIR && d.AppFunc == 0 && d.AppUNS {
			// A confirmation travels in the reverse direction of the unsolicited
			// response; other outstations may concurrently use the same sequence.
			if seq := state.Learned[dnpUnsolicitedKey(d.Dest, d.Source, d.AppSeq)]; len(seq) == 1 {
				d.AppSeq = seq[0]
			}
		}
		if state != nil && dir == replay.ClientToServer && d.HasTransport {
			key := dnpTxKey(d.Source, d.Dest)
			seq, exists := next[key]
			if !exists {
				seq, exists = state.Protocol[key].(uint8)
			}
			if exists {
				d.TransportSeq = seq
			}
			next[key] = (d.TransportSeq + 1) & 63
		}
		out = append(out, d.Encode()...)
	}
	return out, nil
}
func (DNP3) Correlate(expected, actual replay.Message, _ *replay.RuntimeState) replay.Match {
	if w, ok := expected.Fields["application"].(dissect.DNP3Application); ok {
		g, valid := actual.Fields["application"].(dissect.DNP3Application)
		if !valid {
			return replay.Match{Reason: "incomplete application message"}
		}
		if w.Source != g.Source || w.Dest != g.Dest {
			return replay.Match{Reason: "link address differs"}
		}
		if w.LinkOnly != g.LinkOnly {
			return replay.Match{Reason: "link/application phase differs"}
		}
		if w.Unsolicited() != g.Unsolicited() {
			return replay.Match{Reason: "unsolicited response phase differs"}
		}
		if !w.Unsolicited() && w.Sequence() != g.Sequence() {
			return replay.Match{Reason: "application sequence differs"}
		}
		return replay.Match{Matched: true, Key: fmt.Sprintf("%d:%d:%d", w.Source, w.Dest, w.Sequence())}
	}
	wf, _, we := dissect.ParseDNP3(expected.Raw)
	gf, _, ge := dissect.ParseDNP3(actual.Raw)
	if we != nil || ge != nil {
		return replay.Match{Reason: "invalid DNP3 frame"}
	}
	if wf.Source != gf.Source || wf.Dest != gf.Dest {
		return replay.Match{Reason: "link address differs"}
	}
	if wf.HasTransport != gf.HasTransport || wf.TransportFIR != gf.TransportFIR || wf.TransportFIN != gf.TransportFIN || wf.HasApp != gf.HasApp {
		return replay.Match{Reason: "transport fragment boundary differs"}
	}
	if wf.AppUNS != gf.AppUNS {
		return replay.Match{Reason: "unsolicited response phase differs"}
	}
	if wf.AppUNS && gf.AppUNS && wf.AppFunc == gf.AppFunc {
		return replay.Match{Matched: true, Key: "unsolicited"}
	}
	w, g := fmt.Sprint(expected.Fields["appSeq"]), fmt.Sprint(actual.Fields["appSeq"])
	return replay.Match{Matched: w == g, Key: w}
}
func (DNP3) Compare(expected, actual replay.Message, mode replay.VerifyMode) []replay.Difference {
	if w, ok := expected.Fields["application"].(dissect.DNP3Application); ok {
		g, valid := actual.Fields["application"].(dissect.DNP3Application)
		if !valid {
			return []replay.Difference{{Field: "application", Structural: true, Actual: "incomplete application message"}}
		}
		return compareDNP3Applications(w, g, mode)
	}
	w, _, ew := dissect.ParseDNP3(expected.Raw)
	g, _, eg := dissect.ParseDNP3(actual.Raw)
	if ew != nil || eg != nil {
		return rawCompare(expected, actual, mode)
	}
	if w.AppUNS && g.AppUNS && w.TransportFIR && g.TransportFIR {
		g.AppSeq = w.AppSeq
		g.TransportSeq = w.TransportSeq
		normalized := g.Encode()
		g, _, _ = dissect.ParseDNP3(normalized)
		actual.Raw = normalized
	}
	var out []replay.Difference
	for _, d := range dissect.CompareDNP3(w, g) {
		out = append(out, replay.Difference{Field: "frame", Expected: d.Detail, Structural: d.Structural || mode == replay.VerifyStrict})
	}
	if mode == replay.VerifyStrict && !bytes.Equal(expected.Raw, actual.Raw) && len(out) == 0 {
		out = append(out, replay.Difference{Field: "frame", Expected: "byte-identical", Actual: "different bytes", Structural: true})
	}
	return out
}
