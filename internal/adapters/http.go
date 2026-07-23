package adapters

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/kvmukilan/livewire/internal/replay"
)

type HTTP struct{}

func (HTTP) Name() string { return "http/1" }
func (HTTP) Detect(s replay.Session) replay.Confidence {
	p := firstPayload(s)
	line := string(p)
	if bytes.HasPrefix(p, []byte("HTTP/1.")) || strings.Contains(line, " HTTP/1.0\r\n") || strings.Contains(line, " HTTP/1.1\r\n") {
		return 100
	}
	return portConfidence(s, 80, 8080, 8000)
}

func (HTTP) Decode(dir replay.Direction, data []byte) ([]replay.Message, error) {
	return (HTTP{}).DecodeExchange(dir, data, nil)
}

func (HTTP) DecodeExchange(dir replay.Direction, data []byte, peers []replay.Message) ([]replay.Message, error) {
	var out []replay.Message
	peerIndex := 0
	for len(data) > 0 {
		responseTo := ""
		if dir == replay.ServerToClient && peerIndex < len(peers) {
			responseTo = stringField(peers[peerIndex], "method")
		}
		n, fields, err := httpMessageLen(data, dir, responseTo)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, fmt.Errorf("http/1: incomplete message")
		}
		raw := append([]byte(nil), data[:n]...)
		fields["body"] = append([]byte(nil), raw[fields["bodyOffset"].(int):]...)
		out = append(out, replay.Message{Kind: "http", Raw: raw, Fields: fields})
		if dir == replay.ServerToClient && responseConsumesRequest(fields) {
			peerIndex++
		}
		data = data[n:]
	}
	return out, nil
}

func httpMessageLen(data []byte, dir replay.Direction, responseTo string) (int, map[string]any, error) {
	h := bytes.Index(data, []byte("\r\n\r\n"))
	if h < 0 {
		return 0, nil, nil
	}
	headEnd := h + 4
	lines := strings.Split(string(data[:h]), "\r\n")
	if len(lines) == 0 {
		return 0, nil, fmt.Errorf("http/1: empty start line")
	}
	f := map[string]any{"bodyOffset": headEnd, "start": lines[0]}
	if dir == replay.ClientToServer {
		parts := strings.SplitN(lines[0], " ", 3)
		if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/1.") {
			return 0, nil, fmt.Errorf("http/1: malformed request line")
		}
		f["method"], f["path"], f["version"] = parts[0], parts[1], parts[2]
	} else {
		parts := strings.SplitN(lines[0], " ", 3)
		if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/1.") {
			return 0, nil, fmt.Errorf("http/1: malformed status line")
		}
		f["version"], f["status"] = parts[0], parts[1]
	}
	headers := map[string]string{}
	for _, line := range lines[1:] {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			return 0, nil, fmt.Errorf("http/1: malformed header")
		}
		name := strings.ToLower(strings.TrimSpace(k))
		value := strings.TrimSpace(v)
		if previous, exists := headers[name]; exists {
			if name == "content-length" && previous != value {
				return 0, nil, fmt.Errorf("http/1: conflicting Content-Length fields")
			}
			if name != "content-length" {
				headers[name] = previous + ", " + value
			}
		} else {
			headers[name] = value
		}
	}
	f["headers"] = headers
	if dir == replay.ServerToClient {
		status, _ := strconv.Atoi(stringFieldFromMap(f, "status"))
		method := strings.ToUpper(responseTo)
		if method == "HEAD" || method == "CONNECT" && status >= 200 && status < 300 || status >= 100 && status < 200 || status == 204 || status == 304 {
			f["noBody"] = true
			return headEnd, f, nil
		}
	}
	transferEncoding := strings.ToLower(headers["transfer-encoding"])
	if transferEncoding != "" {
		codings := strings.Split(transferEncoding, ",")
		last := strings.TrimSpace(codings[len(codings)-1])
		if last == "chunked" {
			n, ok := chunkedEnd(data[headEnd:])
			if !ok {
				return 0, nil, nil
			}
			return headEnd + n, f, nil
		}
		if dir == replay.ClientToServer {
			return 0, nil, fmt.Errorf("http/1: request Transfer-Encoding must end in chunked")
		}
		f["closeDelimited"] = true
		return len(data), f, nil
	}
	if value, exists := headers["content-length"]; exists {
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			return 0, nil, fmt.Errorf("http/1: invalid Content-Length %q", value)
		}
		if n < 0 || headEnd+n > len(data) {
			return 0, nil, nil
		}
		return headEnd + n, f, nil
	}
	if dir == replay.ServerToClient {
		f["closeDelimited"] = true
		return len(data), f, nil
	}
	return headEnd, f, nil
}

func responseConsumesRequest(fields map[string]any) bool {
	status, _ := strconv.Atoi(stringFieldFromMap(fields, "status"))
	return status < 100 || status >= 200
}

func stringFieldFromMap(fields map[string]any, key string) string {
	v, _ := fields[key].(string)
	return v
}

func (HTTP) RequiresEOF(dir replay.Direction, msg replay.Message) bool {
	if dir != replay.ServerToClient {
		return false
	}
	closeDelimited, _ := msg.Fields["closeDelimited"].(bool)
	return closeDelimited
}

func (HTTP) ConsumedPeers(dir replay.Direction, messages []replay.Message) int {
	if dir != replay.ServerToClient {
		return len(messages)
	}
	n := 0
	for _, msg := range messages {
		if responseConsumesRequest(msg.Fields) {
			n++
		}
	}
	return n
}

func chunkedEnd(body []byte) (int, bool) {
	off := 0
	for {
		i := bytes.Index(body[off:], []byte("\r\n"))
		if i < 0 {
			return 0, false
		}
		line := string(body[off : off+i])
		if semi := strings.IndexByte(line, ';'); semi >= 0 {
			line = line[:semi]
		}
		n, err := strconv.ParseUint(strings.TrimSpace(line), 16, 64)
		if err != nil {
			return 0, false
		}
		off += i + 2
		if n == 0 {
			// An empty trailer section is one CRLF. Otherwise trailers end at
			// CRLF CRLF, just like an HTTP header block (RFC 9112 section 7.1).
			if bytes.HasPrefix(body[off:], []byte("\r\n")) {
				return off + 2, true
			}
			trailEnd := bytes.Index(body[off:], []byte("\r\n\r\n"))
			if trailEnd < 0 {
				return 0, false
			}
			return off + trailEnd + 4, true
		}
		if uint64(len(body)-off) < n+2 {
			return 0, false
		}
		off += int(n)
		if !bytes.HasPrefix(body[off:], []byte("\r\n")) {
			return 0, false
		}
		off += 2
	}
}

func (HTTP) Prepare(dir replay.Direction, msg replay.Message, state *replay.RuntimeState) ([]byte, error) {
	out := substitute(msg.Raw, state)
	if state == nil {
		return out, nil
	}
	if host := state.Variables["http.host"]; host != "" {
		out = replaceHeader(out, "Host", host)
	}
	for key, value := range state.Variables {
		if strings.HasPrefix(strings.ToLower(key), "http.header.") {
			out = replaceHeader(out, key[len("http.header."):], value)
		}
	}
	if body, ok := state.Variables["http.body"]; ok {
		return replaceHTTPBody(out, dir, []byte(body))
	}
	// Generic ${name} substitutions inside a fixed-length body are safe only
	// after repairing Content-Length. Chunked substitutions need explicit
	// re-framing through http.body so chunk sizes cannot silently become stale.
	originalBody := httpBodyBytes(msg.Raw)
	preparedBody := httpBodyBytes(out)
	if !bytes.Equal(originalBody, preparedBody) {
		headers := httpHeaders(out)
		if strings.Contains(strings.ToLower(headers["transfer-encoding"]), "chunked") {
			return nil, fmt.Errorf("http/1: variable substitution changed a chunked body; use -set http.body=... so chunks can be reframed")
		}
		if _, exists := headers["content-length"]; exists {
			out = replaceHeader(out, "Content-Length", strconv.Itoa(len(preparedBody)))
		}
	}
	return out, nil
}

func replaceHTTPBody(raw []byte, dir replay.Direction, body []byte) ([]byte, error) {
	sep := []byte("\r\n\r\n")
	i := bytes.Index(raw, sep)
	if i < 0 {
		return nil, fmt.Errorf("http/1: cannot replace body without a complete header block")
	}
	headers := httpHeaders(raw)
	head := append([]byte(nil), raw[:i+len(sep)]...)
	if strings.Contains(strings.ToLower(headers["transfer-encoding"]), "chunked") {
		framed := []byte(fmt.Sprintf("%x\r\n", len(body)))
		framed = append(framed, body...)
		framed = append(framed, []byte("\r\n0\r\n\r\n")...)
		return append(head, framed...), nil
	}
	out := append(head, body...)
	if _, exists := headers["content-length"]; exists || dir == replay.ClientToServer {
		out = replaceHeader(out, "Content-Length", strconv.Itoa(len(body)))
	}
	return out, nil
}

func httpBodyBytes(raw []byte) []byte {
	i := bytes.Index(raw, []byte("\r\n\r\n"))
	if i < 0 {
		return nil
	}
	return raw[i+4:]
}

func httpHeaders(raw []byte) map[string]string {
	out := map[string]string{}
	i := bytes.Index(raw, []byte("\r\n\r\n"))
	if i < 0 {
		return out
	}
	lines := strings.Split(string(raw[:i]), "\r\n")
	for _, line := range lines[1:] {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			out[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
		}
	}
	return out
}

func (HTTP) Correlate(expected, actual replay.Message, _ *replay.RuntimeState) replay.Match {
	for _, key := range []string{"method", "path", "status"} {
		if want := stringField(expected, key); want != "" && want != stringField(actual, key) {
			return replay.Match{Reason: key + " differs"}
		}
	}
	return replay.Match{Matched: true, Key: stringField(expected, "path")}
}

func (HTTP) Compare(expected, actual replay.Message, mode replay.VerifyMode) []replay.Difference {
	var out []replay.Difference
	for _, key := range []string{"method", "path", "status"} {
		want, got := stringField(expected, key), stringField(actual, key)
		if want != got {
			out = append(out, replay.Difference{Field: key, Expected: want, Actual: got, Structural: true})
		}
	}
	if mode == replay.VerifyStrict && !bytes.Equal(expected.Raw, actual.Raw) {
		out = append(out, replay.Difference{Field: "message", Expected: "byte-identical", Actual: "different bytes", Structural: true})
	}
	return out
}
