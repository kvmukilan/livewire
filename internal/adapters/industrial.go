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
	return replay.Match{Matched: id == fmt.Sprint(actual.Fields["transactionId"]), Key: id}
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
	frames, leftover, err := dissect.ParseDNP3Stream(data)
	if err != nil {
		return nil, err
	}
	if leftover != 0 {
		return nil, fmt.Errorf("dnp3: %d trailing bytes", leftover)
	}
	out := make([]replay.Message, 0, len(frames))
	for _, d := range frames {
		raw := d.Encode()
		out = append(out, replay.Message{Kind: "dnp3", Raw: raw, Fields: map[string]any{
			"source": d.Source, "destination": d.Dest, "transportSeq": d.TransportSeq, "appSeq": d.AppSeq, "function": d.AppFunc,
		}})
	}
	return out, nil
}
func (DNP3) Prepare(_ replay.Direction, msg replay.Message, state *replay.RuntimeState) ([]byte, error) {
	return substitute(msg.Raw, state), nil
}
func (DNP3) Correlate(expected, actual replay.Message, _ *replay.RuntimeState) replay.Match {
	w, g := fmt.Sprint(expected.Fields["appSeq"]), fmt.Sprint(actual.Fields["appSeq"])
	return replay.Match{Matched: w == g, Key: w}
}
func (DNP3) Compare(expected, actual replay.Message, mode replay.VerifyMode) []replay.Difference {
	w, _, ew := dissect.ParseDNP3(expected.Raw)
	g, _, eg := dissect.ParseDNP3(actual.Raw)
	if ew != nil || eg != nil {
		return rawCompare(expected, actual, mode)
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
