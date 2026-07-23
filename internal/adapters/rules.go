package adapters

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/kvmukilan/livewire/internal/replay"
)

const (
	maxRuleFrame    = 16 << 20
	maxRulePackJSON = 1 << 20
)

type RulePack struct {
	Name        string             `json:"name"`
	Match       RuleMatch          `json:"match"`
	Framing     RuleFraming        `json:"framing"`
	Correlation []RuleField        `json:"correlation,omitempty"`
	Volatile    []RuleRange        `json:"volatile,omitempty"`
	CopyLive    []RuleCopyFromLive `json:"copyFromLive,omitempty"`
}

type RuleMatch struct {
	Transport string   `json:"transport"`
	Ports     []uint16 `json:"ports,omitempty"`
	PrefixHex string   `json:"prefixHex,omitempty"`
}

type RuleFraming struct {
	Type                 string `json:"type"` // datagram | fixed | delimited | length-field
	Size                 int    `json:"size,omitempty"`
	DelimiterHex         string `json:"delimiterHex,omitempty"`
	LengthOffset         int    `json:"lengthOffset,omitempty"`
	LengthSize           int    `json:"lengthSize,omitempty"`
	Endian               string `json:"endian,omitempty"`
	LengthIncludesHeader bool   `json:"lengthIncludesHeader,omitempty"`
	HeaderSize           int    `json:"headerSize,omitempty"`
}

type RuleField struct {
	Name   string `json:"name"`
	Offset int    `json:"offset"`
	Length int    `json:"length"`
}

type RuleRange struct {
	Offset int `json:"offset"`
	Length int `json:"length"`
}

type RuleCopyFromLive struct {
	Key        string `json:"key"`
	FromOffset int    `json:"fromOffset"`
	ToOffset   int    `json:"toOffset"`
	Length     int    `json:"length"`
}

type RuleAdapter struct {
	pack      RulePack
	prefix    []byte
	delimiter []byte
	version   string
}

func CompileRulePackJSON(data []byte) (*RuleAdapter, error) {
	if len(data) > maxRulePackJSON {
		return nil, fmt.Errorf("rule pack: JSON exceeds %d bytes", maxRulePackJSON)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p RulePack
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("rule pack: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("rule pack: trailing JSON value")
	}
	return CompileRulePack(p)
}

func CompileRulePack(p RulePack) (*RuleAdapter, error) {
	if !validRuleName(p.Name) {
		return nil, fmt.Errorf("rule pack: name must be 1..64 letters, digits, dots, underscores, or hyphens")
	}
	switch p.Match.Transport {
	case "tcp", "udp":
	default:
		return nil, fmt.Errorf("rule pack: transport must be tcp or udp")
	}
	if len(p.Match.Ports) > 256 || len(p.Correlation) > 1024 || len(p.Volatile) > 1024 || len(p.CopyLive) > 1024 {
		return nil, fmt.Errorf("rule pack: too many match or field rules")
	}
	canonical, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("rule pack: canonicalize: %w", err)
	}
	digest := sha256.Sum256(canonical)
	a := &RuleAdapter{pack: p, version: fmt.Sprintf("sha256:%x", digest)}
	if p.Match.PrefixHex != "" {
		a.prefix, err = hex.DecodeString(strings.ReplaceAll(p.Match.PrefixHex, " ", ""))
		if err != nil {
			return nil, fmt.Errorf("rule pack: prefixHex: %w", err)
		}
	}
	if p.Framing.DelimiterHex != "" {
		a.delimiter, err = hex.DecodeString(strings.ReplaceAll(p.Framing.DelimiterHex, " ", ""))
		if err != nil {
			return nil, fmt.Errorf("rule pack: delimiterHex: %w", err)
		}
	}
	switch p.Framing.Type {
	case "datagram":
	case "fixed":
		if p.Framing.Size <= 0 || p.Framing.Size > maxRuleFrame {
			return nil, fmt.Errorf("rule pack: fixed size must be 1..%d", maxRuleFrame)
		}
	case "delimited":
		if len(a.delimiter) == 0 {
			return nil, fmt.Errorf("rule pack: delimited framing needs delimiterHex")
		}
	case "length-field":
		if p.Framing.LengthSize != 1 && p.Framing.LengthSize != 2 && p.Framing.LengthSize != 4 {
			return nil, fmt.Errorf("rule pack: length field size must be 1, 2, or 4")
		}
		if p.Framing.LengthOffset < 0 || p.Framing.LengthOffset > maxRuleFrame-p.Framing.LengthSize {
			return nil, fmt.Errorf("rule pack: length field needs a non-negative offset and size 1, 2, or 4")
		}
		if p.Framing.HeaderSize < 0 || p.Framing.HeaderSize > maxRuleFrame {
			return nil, fmt.Errorf("rule pack: header size must be 0..%d", maxRuleFrame)
		}
		if p.Framing.Endian != "" && p.Framing.Endian != "big" && p.Framing.Endian != "little" {
			return nil, fmt.Errorf("rule pack: endian must be big or little")
		}
	default:
		return nil, fmt.Errorf("rule pack: unsupported framing %q", p.Framing.Type)
	}
	for _, f := range p.Correlation {
		if f.Name == "" || !validRange(f.Offset, f.Length) {
			return nil, fmt.Errorf("rule pack: invalid correlation field")
		}
	}
	for _, r := range p.Volatile {
		if !validRange(r.Offset, r.Length) {
			return nil, fmt.Errorf("rule pack: invalid volatile range")
		}
	}
	for _, c := range p.CopyLive {
		if c.Key == "" || !validRange(c.FromOffset, c.Length) || !validRange(c.ToOffset, c.Length) {
			return nil, fmt.Errorf("rule pack: invalid copyFromLive rule")
		}
	}
	return a, nil
}

func validRuleName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !(r == '.' || r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func validRange(off, length int) bool { return off >= 0 && length > 0 && off <= maxRuleFrame-length }

func (a *RuleAdapter) Name() string    { return "rule:" + a.pack.Name }
func (a *RuleAdapter) Version() string { return a.version }
func (a *RuleAdapter) Detect(s replay.Session) replay.Confidence {
	if string(s.Transport) != a.pack.Match.Transport {
		return 0
	}
	if len(a.pack.Match.Ports) > 0 && portConfidence(s, a.pack.Match.Ports...) == 0 {
		return 0
	}
	if len(a.prefix) > 0 && !bytes.HasPrefix(firstPayload(s), a.prefix) {
		return 0
	}
	return 90
}

func (a *RuleAdapter) Decode(_ replay.Direction, data []byte) ([]replay.Message, error) {
	frames, err := a.frame(data)
	if err != nil {
		return nil, err
	}
	out := make([]replay.Message, 0, len(frames))
	for _, raw := range frames {
		fields := map[string]any{}
		for _, f := range a.pack.Correlation {
			if f.Offset+f.Length > len(raw) {
				return nil, fmt.Errorf("%s: correlation field %s exceeds frame", a.Name(), f.Name)
			}
			fields[f.Name] = hex.EncodeToString(raw[f.Offset : f.Offset+f.Length])
		}
		out = append(out, replay.Message{Kind: a.pack.Name, Raw: append([]byte(nil), raw...), Fields: fields})
	}
	return out, nil
}

func (a *RuleAdapter) frame(data []byte) ([][]byte, error) {
	var out [][]byte
	for len(data) > 0 {
		n := len(data)
		switch a.pack.Framing.Type {
		case "datagram":
		case "fixed":
			n = a.pack.Framing.Size
		case "delimited":
			i := bytes.Index(data, a.delimiter)
			if i < 0 {
				return nil, fmt.Errorf("%s: missing delimiter", a.Name())
			}
			n = i + len(a.delimiter)
		case "length-field":
			f := a.pack.Framing
			if f.LengthOffset+f.LengthSize > len(data) {
				return nil, fmt.Errorf("%s: truncated length field", a.Name())
			}
			value := readRuleUint(data[f.LengthOffset:f.LengthOffset+f.LengthSize], f.Endian)
			if value > maxRuleFrame {
				return nil, fmt.Errorf("%s: declared frame is too large", a.Name())
			}
			n = int(value)
			if !f.LengthIncludesHeader {
				header := f.HeaderSize
				if header == 0 {
					header = f.LengthOffset + f.LengthSize
				}
				n += header
			}
		}
		if n <= 0 || n > len(data) || n > maxRuleFrame {
			return nil, fmt.Errorf("%s: incomplete or invalid frame length %d", a.Name(), n)
		}
		out = append(out, data[:n])
		data = data[n:]
		if a.pack.Framing.Type == "datagram" {
			break
		}
	}
	return out, nil
}

func readRuleUint(b []byte, endian string) uint64 {
	if endian == "little" {
		switch len(b) {
		case 1:
			return uint64(b[0])
		case 2:
			return uint64(binary.LittleEndian.Uint16(b))
		case 4:
			return uint64(binary.LittleEndian.Uint32(b))
		}
	}
	switch len(b) {
	case 1:
		return uint64(b[0])
	case 2:
		return uint64(binary.BigEndian.Uint16(b))
	case 4:
		return uint64(binary.BigEndian.Uint32(b))
	}
	return 0
}

func (a *RuleAdapter) Prepare(_ replay.Direction, msg replay.Message, state *replay.RuntimeState) ([]byte, error) {
	out := substitute(msg.Raw, state)
	if state == nil {
		return out, nil
	}
	for _, c := range a.pack.CopyLive {
		value := state.Learned[c.Key]
		if len(value) == 0 {
			continue
		}
		if len(value) != c.Length || c.ToOffset+c.Length > len(out) {
			return nil, fmt.Errorf("%s: copy %s does not fit target frame", a.Name(), c.Key)
		}
		copy(out[c.ToOffset:c.ToOffset+c.Length], value)
	}
	return out, nil
}

func (a *RuleAdapter) Correlate(expected, actual replay.Message, state *replay.RuntimeState) replay.Match {
	for _, f := range a.pack.Correlation {
		if fmt.Sprint(expected.Fields[f.Name]) != fmt.Sprint(actual.Fields[f.Name]) {
			return replay.Match{Reason: f.Name + " differs"}
		}
	}
	if state != nil {
		if state.Learned == nil {
			state.Learned = map[string][]byte{}
		}
		for _, c := range a.pack.CopyLive {
			if c.FromOffset+c.Length <= len(actual.Raw) {
				state.Learned[c.Key] = append([]byte(nil), actual.Raw[c.FromOffset:c.FromOffset+c.Length]...)
			}
		}
	}
	return replay.Match{Matched: true}
}

func (a *RuleAdapter) Compare(expected, actual replay.Message, mode replay.VerifyMode) []replay.Difference {
	if mode == replay.VerifyOff {
		return nil
	}
	want, got := append([]byte(nil), expected.Raw...), append([]byte(nil), actual.Raw...)
	if mode == replay.VerifyLenient {
		for _, r := range a.pack.Volatile {
			if r.Offset+r.Length <= len(want) && r.Offset+r.Length <= len(got) {
				for i := 0; i < r.Length; i++ {
					want[r.Offset+i], got[r.Offset+i] = 0, 0
				}
			}
		}
	}
	if bytes.Equal(want, got) {
		return nil
	}
	wantDigest, gotDigest := sha256.Sum256(want), sha256.Sum256(got)
	return []replay.Difference{{
		Field:      "frame",
		Expected:   fmt.Sprintf("%d bytes, sha256:%x", len(want), wantDigest),
		Actual:     fmt.Sprintf("%d bytes, sha256:%x", len(got), gotDigest),
		Structural: true,
	}}
}
