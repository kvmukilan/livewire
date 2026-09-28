package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/kvmukilan/livewire/internal/replay"
	"io"
	"strconv"
	"strings"
)

func (a HTTP) ComparePolicy(w, g replay.Message, mode replay.VerifyMode, p replay.ComparisonPolicy) []replay.Difference {
	diffs := a.Compare(w, g, mode)
	if mode == replay.VerifyOff {
		return nil
	}
	for _, header := range p.Headers {
		want := httpHeaders(w.Raw)[strings.ToLower(header)]
		got := httpHeaders(g.Raw)[strings.ToLower(header)]
		if want != got {
			diffs = append(diffs, replay.Difference{Field: "header." + strings.ToLower(header), Expected: bodyDigest([]byte(want)), Actual: bodyDigest([]byte(got)), Structural: true})
		}
	}
	if mode == replay.VerifyStrict || !p.NormalizeJSON && len(p.IgnoreJSON) == 0 {
		return diffs
	}
	want, we := canonicalBody(w, p)
	got, ge := canonicalBody(g, p)
	if we != nil || ge != nil {
		return append(diffs, replay.Difference{Field: "body.policy", Actual: "JSON comparison policy could not be applied", Structural: true})
	}
	out := diffs[:0]
	for _, d := range diffs {
		if d.Field != "body" {
			out = append(out, d)
		}
	}
	if !bytes.Equal(want, got) {
		out = append(out, replay.Difference{Field: "body", Expected: bodyDigest(want), Actual: bodyDigest(got), Structural: true})
	}
	return out
}
func canonicalBody(m replay.Message, p replay.ComparisonPolicy) ([]byte, error) {
	b, err := decodedHTTPBody(m)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var value any
	if err = d.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return nil, fmt.Errorf("trailing JSON body content")
	}
	for _, path := range p.IgnoreJSON {
		if path == "" || !strings.HasPrefix(path, "/") {
			return nil, fmt.Errorf("ignored JSON pointer must name a field")
		}
		parts := strings.Split(path[1:], "/")
		for i := range parts {
			parts[i] = strings.ReplaceAll(strings.ReplaceAll(parts[i], "~1", "/"), "~0", "~")
		}
		if err = ignoreJSON(value, parts); err != nil {
			return nil, err
		}
	}
	return json.Marshal(value)
}
func ignoreJSON(v any, path []string) error {
	key := path[0]
	switch node := v.(type) {
	case map[string]any:
		child, ok := node[key]
		if !ok {
			return fmt.Errorf("ignored JSON pointer is missing")
		}
		if len(path) == 1 {
			delete(node, key)
			return nil
		}
		return ignoreJSON(child, path[1:])
	case []any:
		i, e := strconv.Atoi(key)
		if e != nil || i < 0 || i >= len(node) {
			return fmt.Errorf("ignored JSON index is invalid")
		}
		if len(path) == 1 {
			node[i] = nil
			return nil
		}
		return ignoreJSON(node[i], path[1:])
	default:
		return fmt.Errorf("ignored JSON pointer is invalid")
	}
}
