// Package adapters contains Livewire's compiled-in application protocol
// adapters. They are deliberately deterministic and never execute scripts.
package adapters

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/kvmukilan/livewire/internal/replay"
)

func substitute(raw []byte, state *replay.RuntimeState) []byte {
	out := append([]byte(nil), raw...)
	if state == nil {
		return out
	}
	keys := make([]string, 0, len(state.Variables))
	for k := range state.Variables {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = bytes.ReplaceAll(out, []byte("${"+k+"}"), []byte(state.Variables[k]))
	}
	return out
}

func rawCompare(expected, actual replay.Message, mode replay.VerifyMode) []replay.Difference {
	if mode == replay.VerifyOff || bytes.Equal(expected.Raw, actual.Raw) {
		return nil
	}
	return []replay.Difference{{Field: "payload", Expected: fmt.Sprintf("%d bytes", len(expected.Raw)), Actual: fmt.Sprintf("%d bytes", len(actual.Raw)), Structural: mode == replay.VerifyStrict}}
}

func portConfidence(s replay.Session, ports ...uint16) replay.Confidence {
	for _, p := range ports {
		if s.Client.Port == p || s.Server.Port == p {
			return 80
		}
	}
	return 0
}

func firstPayload(s replay.Session) []byte {
	for _, e := range s.Events {
		if len(e.Payload) > 0 {
			return e.Payload
		}
	}
	return nil
}

func stringField(m replay.Message, key string) string {
	if m.Fields == nil {
		return ""
	}
	v, _ := m.Fields[key].(string)
	return v
}

func replaceHeader(raw []byte, name, value string) []byte {
	sep := []byte("\r\n\r\n")
	i := bytes.Index(raw, sep)
	if i < 0 {
		return raw
	}
	lines := strings.Split(string(raw[:i]), "\r\n")
	found := false
	for n := 1; n < len(lines); n++ {
		key, _, ok := strings.Cut(lines[n], ":")
		if ok && strings.EqualFold(strings.TrimSpace(key), name) {
			lines[n] = name + ": " + value
			found = true
		}
	}
	if !found {
		lines = append(lines, name+": "+value)
	}
	return append(append([]byte(strings.Join(lines, "\r\n")), sep...), raw[i+len(sep):]...)
}
