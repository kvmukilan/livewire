package adapters

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/kvmukilan/livewire/internal/replay"
)

type DNS struct {
	Transport replay.Transport
}

func (d DNS) Name() string {
	switch d.Transport {
	case replay.TransportTCP:
		return "dns/tcp"
	case replay.TransportUDP:
		return "dns/udp"
	default:
		return "dns"
	}
}
func (d DNS) Detect(s replay.Session) replay.Confidence {
	if d.Transport != "" && s.Transport != d.Transport {
		return 0
	}
	if c := portConfidence(s, 53); c > 0 {
		return c
	}
	p := firstPayload(s)
	if s.Transport == replay.TransportTCP {
		if msgs, err := (DNS{Transport: replay.TransportTCP}).Decode(replay.ClientToServer, p); err == nil && len(msgs) > 0 {
			return 40
		}
	}
	if s.Transport == replay.TransportUDP && len(p) >= 12 {
		return 25
	}
	return 0
}

func (d DNS) Decode(_ replay.Direction, data []byte) ([]replay.Message, error) {
	if d.Transport != replay.TransportTCP {
		fields, err := parseDNS(data)
		if err != nil {
			return nil, err
		}
		return []replay.Message{{Kind: "dns", Raw: append([]byte(nil), data...), Fields: fields}}, nil
	}
	var out []replay.Message
	for len(data) > 0 {
		if len(data) < 2 {
			return nil, fmt.Errorf("dns/tcp: truncated length prefix")
		}
		n := int(binary.BigEndian.Uint16(data[:2]))
		if n < 12 || n > len(data)-2 {
			return nil, fmt.Errorf("dns/tcp: incomplete or invalid message length %d", n)
		}
		raw := data[2 : 2+n]
		data = data[2+n:]
		fields, err := parseDNS(raw)
		if err != nil {
			return nil, err
		}
		msgRaw := append([]byte(nil), raw...)
		msgRaw = binary.BigEndian.AppendUint16(nil, uint16(len(raw)))
		msgRaw = append(msgRaw, raw...)
		fields["tcp"] = true
		out = append(out, replay.Message{Kind: "dns", Raw: msgRaw, Fields: fields})
	}
	return out, nil
}

func parseDNS(raw []byte) (map[string]any, error) {
	if len(raw) < 12 {
		return nil, fmt.Errorf("dns: message shorter than 12-byte header")
	}
	flags := binary.BigEndian.Uint16(raw[2:4])
	f := map[string]any{
		"id": binary.BigEndian.Uint16(raw[:2]), "qr": flags>>15 == 1,
		"rcode": uint8(flags & 0xf), "qdcount": binary.BigEndian.Uint16(raw[4:6]),
		"ancount": binary.BigEndian.Uint16(raw[6:8]),
	}
	if binary.BigEndian.Uint16(raw[4:6]) > 0 {
		name, off, err := dnsName(raw, 12, 0)
		if err != nil || off+4 > len(raw) {
			return nil, fmt.Errorf("dns: malformed question")
		}
		f["qname"], f["qtype"], f["qclass"] = name, binary.BigEndian.Uint16(raw[off:off+2]), binary.BigEndian.Uint16(raw[off+2:off+4])
	}
	normalized, err := normalizeDNS(raw)
	if err != nil {
		return nil, err
	}
	f["normalized"] = normalized
	return f, nil
}

func normalizeDNS(raw []byte) ([]byte, error) {
	if len(raw) < 12 {
		return nil, fmt.Errorf("dns: message shorter than 12-byte header")
	}
	out := append([]byte(nil), raw...)
	out[0], out[1] = 0, 0 // transaction ID is per-run state
	off := 12
	questions := int(binary.BigEndian.Uint16(raw[4:6]))
	for i := 0; i < questions; i++ {
		_, next, err := dnsName(raw, off, 0)
		if err != nil || next+4 > len(raw) {
			return nil, fmt.Errorf("dns: malformed question %d", i)
		}
		off = next + 4
	}
	records := int(binary.BigEndian.Uint16(raw[6:8])) + int(binary.BigEndian.Uint16(raw[8:10])) + int(binary.BigEndian.Uint16(raw[10:12]))
	for i := 0; i < records; i++ {
		_, next, err := dnsName(raw, off, 0)
		if err != nil || next+10 > len(raw) {
			return nil, fmt.Errorf("dns: malformed resource record %d", i)
		}
		// NAME is followed by TYPE, CLASS, TTL, RDLENGTH. TTL is expected to
		// drift between capture and replay and is the only RR field normalized.
		for j := next + 4; j < next+8; j++ {
			out[j] = 0
		}
		rdlen := int(binary.BigEndian.Uint16(raw[next+8 : next+10]))
		off = next + 10 + rdlen
		if off > len(raw) {
			return nil, fmt.Errorf("dns: truncated resource record %d", i)
		}
	}
	if off != len(raw) {
		return nil, fmt.Errorf("dns: %d trailing bytes", len(raw)-off)
	}
	return out, nil
}

func dnsName(msg []byte, off, depth int) (string, int, error) {
	if depth > 16 || off >= len(msg) {
		return "", off, fmt.Errorf("invalid name")
	}
	var labels []string
	next := off
	for {
		if next >= len(msg) {
			return "", off, fmt.Errorf("truncated name")
		}
		n := int(msg[next])
		if n == 0 {
			return strings.Join(labels, "."), next + 1, nil
		}
		if n&0xc0 == 0xc0 {
			if next+1 >= len(msg) {
				return "", off, fmt.Errorf("truncated pointer")
			}
			ptr := (n&0x3f)<<8 | int(msg[next+1])
			tail, _, err := dnsName(msg, ptr, depth+1)
			if err != nil {
				return "", off, err
			}
			labels = append(labels, tail)
			return strings.Join(labels, "."), next + 2, nil
		}
		if n > 63 || next+1+n > len(msg) {
			return "", off, fmt.Errorf("invalid label")
		}
		labels = append(labels, string(msg[next+1:next+1+n]))
		next += n + 1
	}
}

func (DNS) Prepare(_ replay.Direction, msg replay.Message, state *replay.RuntimeState) ([]byte, error) {
	out := substitute(msg.Raw, state)
	if state == nil || state.Variables["dns.name"] == "" {
		return out, nil
	}
	tcp := false
	raw := out
	if v, _ := msg.Fields["tcp"].(bool); v {
		tcp, raw = true, out[2:]
	}
	_, qend, err := dnsName(raw, 12, 0)
	if err != nil || qend+4 > len(raw) {
		return nil, fmt.Errorf("dns: cannot substitute malformed question")
	}
	enc, err := encodeDNSName(state.Variables["dns.name"])
	if err != nil {
		return nil, err
	}
	rebuilt := append(append(append([]byte(nil), raw[:12]...), enc...), raw[qend:]...)
	if tcp {
		out = binary.BigEndian.AppendUint16(nil, uint16(len(rebuilt)))
		out = append(out, rebuilt...)
		return out, nil
	}
	return rebuilt, nil
}

func encodeDNSName(name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return []byte{0}, nil
	}
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || len(out)+len(label)+2 > 255 {
			return nil, fmt.Errorf("dns: invalid name %q", name)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0), nil
}

func (d DNS) NormalizeExpected(direction replay.Direction, msg replay.Message, state *replay.RuntimeState) (replay.Message, error) {
	prepared, err := d.Prepare(direction, msg, state)
	if err != nil {
		return replay.Message{}, err
	}
	decoded, err := d.Decode(direction, prepared)
	if err != nil {
		return replay.Message{}, err
	}
	if len(decoded) != 1 {
		return replay.Message{}, fmt.Errorf("dns: expected exactly one normalized message, got %d", len(decoded))
	}
	return decoded[0], nil
}

func (DNS) Correlate(expected, actual replay.Message, _ *replay.RuntimeState) replay.Match {
	wid, wok := expected.Fields["id"].(uint16)
	gid, gok := actual.Fields["id"].(uint16)
	wq, gq := stringField(expected, "qname"), stringField(actual, "qname")
	wt, _ := expected.Fields["qtype"].(uint16)
	gt, _ := actual.Fields["qtype"].(uint16)
	key := fmt.Sprintf("id=%d question=%s/%d", wid, wq, wt)
	if !wok || !gok || wid != gid {
		return replay.Match{Key: key, Reason: fmt.Sprintf("transaction ID differs: got %d", gid)}
	}
	if !strings.EqualFold(wq, gq) || wt != gt {
		return replay.Match{Key: key, Reason: fmt.Sprintf("question differs: got %s/%d", gq, gt)}
	}
	return replay.Match{Matched: true, Key: key}
}

func (DNS) Compare(expected, actual replay.Message, mode replay.VerifyMode) []replay.Difference {
	var out []replay.Difference
	for _, key := range []string{"qname"} {
		if !strings.EqualFold(stringField(expected, key), stringField(actual, key)) {
			out = append(out, replay.Difference{Field: key, Expected: stringField(expected, key), Actual: stringField(actual, key), Structural: true})
		}
	}
	for _, key := range []string{"qtype", "rcode", "ancount"} {
		if fmt.Sprint(expected.Fields[key]) != fmt.Sprint(actual.Fields[key]) {
			out = append(out, replay.Difference{Field: key, Expected: fmt.Sprint(expected.Fields[key]), Actual: fmt.Sprint(actual.Fields[key]), Structural: true})
		}
	}
	if mode != replay.VerifyStrict {
		want, _ := expected.Fields["normalized"].([]byte)
		got, _ := actual.Fields["normalized"].([]byte)
		if !bytes.Equal(want, got) {
			out = append(out, replay.Difference{Field: "records", Expected: "same records ignoring transaction ID and TTL", Actual: "record data differs", Structural: true})
		}
	}
	if mode == replay.VerifyStrict && !bytes.Equal(expected.Raw, actual.Raw) {
		out = append(out, replay.Difference{Field: "message", Expected: "byte-identical including ID and TTL", Actual: "different bytes", Structural: true})
	}
	return out
}
