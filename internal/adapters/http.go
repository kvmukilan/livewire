package adapters

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"

	"github.com/kvmukilan/livewire/internal/replay"
)

type HTTP struct{}

func (HTTP) Name() string { return "http/1" }
func (HTTP) Detect(s replay.Session) replay.Confidence {
	if s.Transport != replay.TransportTCP {
		return 0
	}
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
			if n < 0 {
				return 0, nil, fmt.Errorf("http/1: malformed or oversized chunk")
			}
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
		// Subtract the already validated header size before comparing so a
		// hostile or corrupt Content-Length cannot overflow the slice boundary.
		if n > len(data)-headEnd {
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
		if err != nil || n > maxRuleFrame {
			return -1, false
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
			return -1, false
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
	if dir == replay.ClientToServer {
		if jar, ok := state.Protocol["http.cookies"].(http.CookieJar); ok {
			if u, err := requestURL(out, state); err == nil {
				var values []string
				for _, c := range jar.Cookies(u) {
					values = append(values, c.Name+"="+c.Value)
				}
				out = replaceHeader(out, "Cookie", strings.Join(values, "; "))
			}
		}
	}
	for key, value := range state.Variables {
		if strings.HasPrefix(strings.ToLower(key), "http.header.") {
			if strings.ContainsAny(value, "\r\n") {
				return nil, fmt.Errorf("http: substituted header contains line breaks")
			}
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
		if len(body) == 0 {
			return append(head, []byte("0\r\n\r\n")...), nil
		}
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
	if stringField(expected, "status") != "" && responseConsumesRequest(expected.Fields) != responseConsumesRequest(actual.Fields) {
		return replay.Match{Reason: "informational/final response phase differs"}
	}
	for _, key := range []string{"method", "path"} {
		if want := stringField(expected, key); want != "" && want != stringField(actual, key) {
			return replay.Match{Reason: key + " differs"}
		}
	}
	return replay.Match{Matched: true, Key: stringField(expected, "path")}
}

func (HTTP) Compare(expected, actual replay.Message, mode replay.VerifyMode) []replay.Difference {
	if mode == replay.VerifyOff {
		return nil
	}
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
	if mode == replay.VerifyLenient {
		want, we := decodedHTTPBody(expected)
		got, ge := decodedHTTPBody(actual)
		if we != nil || ge != nil {
			out = append(out, replay.Difference{Field: "body", Expected: "decodable body", Actual: "body decoding failed", Structural: true})
		} else if !bytes.Equal(want, got) {
			out = append(out, replay.Difference{Field: "body", Expected: bodyDigest(want), Actual: bodyDigest(got), Structural: true})
		}
	}
	return out
}

func bodyDigest(data []byte) string {
	return fmt.Sprintf("%d bytes, sha256:%x", len(data), sha256.Sum256(data))
}

func decodedHTTPBody(msg replay.Message) ([]byte, error) {
	if noBody, _ := msg.Fields["noBody"].(bool); noBody {
		return nil, nil
	}
	var body io.ReadCloser
	var header http.Header
	if strings.HasPrefix(string(msg.Raw), "HTTP/") {
		r, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(msg.Raw)), nil)
		if err != nil {
			return nil, err
		}
		body, header = r.Body, r.Header
	} else {
		r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(msg.Raw)))
		if err != nil {
			return nil, err
		}
		body, header = r.Body, r.Header
	}
	defer body.Close()
	var reader io.Reader = body
	switch strings.ToLower(header.Get("Content-Encoding")) {
	case "", "identity":
	case "gzip":
		r, err := gzip.NewReader(body)
		if err != nil {
			return nil, err
		}
		defer r.Close()
		reader = r
	case "deflate":
		r, err := zlib.NewReader(body)
		if err != nil {
			return nil, err
		}
		defer r.Close()
		reader = r
	default:
		return nil, fmt.Errorf("unsupported Content-Encoding")
	}
	b, err := io.ReadAll(io.LimitReader(reader, maxRuleFrame+1))
	if len(b) > maxRuleFrame {
		return nil, fmt.Errorf("decoded body too large")
	}
	return b, err
}

func requestURL(raw []byte, state *replay.RuntimeState) (*url.URL, error) {
	r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return nil, err
	}
	r.Body.Close()
	u := *r.URL
	if u.Scheme == "" {
		u.Scheme = "http"
		if s, ok := state.Protocol["http.scheme"].(string); ok {
			u.Scheme = s
		}
	}
	if u.Host == "" {
		u.Host = r.Host
	}
	return &u, nil
}

func (HTTP) Observe(dir replay.Direction, _, actual replay.Message, state *replay.RuntimeState) error {
	queue, _ := state.Protocol["http.requests"].([]*url.URL)
	if dir == replay.ClientToServer {
		u, err := requestURL(actual.Raw, state)
		if err != nil {
			return err
		}
		state.Protocol["http.requests"] = append(queue, u)
		return nil
	}
	if !responseConsumesRequest(actual.Fields) || len(queue) == 0 {
		return nil
	}
	state.Protocol["http.requests"] = queue[1:]
	r, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(actual.Raw)), nil)
	if err != nil {
		return err
	}
	r.Body.Close()
	if len(r.Cookies()) == 0 {
		return nil
	}
	jar, ok := state.Protocol["http.cookies"].(http.CookieJar)
	if !ok {
		jar, _ = cookiejar.New(nil)
		state.Protocol["http.cookies"] = jar
	}
	jar.SetCookies(queue[0], r.Cookies())
	state.Transformations = append(state.Transformations, "http: cookies learned from live response")
	return nil
}

func (HTTP) ExtractField(m replay.Message, e replay.Extraction) (string, error) {
	if e.Header != "" {
		headers, _ := m.Fields["headers"].(map[string]string)
		v, ok := headers[strings.ToLower(e.Header)]
		if !ok {
			return "", fmt.Errorf("header is absent")
		}
		return v, nil
	}
	b, err := decodedHTTPBody(m)
	if err != nil {
		return "", err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err = d.Decode(&v); err != nil {
		return "", fmt.Errorf("invalid JSON body")
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return "", fmt.Errorf("trailing JSON body content")
	}
	if e.JSONPointer == nil {
		return "", fmt.Errorf("missing extraction selector")
	}
	path := *e.JSONPointer
	if path != "" {
		if !strings.HasPrefix(path, "/") {
			return "", fmt.Errorf("JSON pointer must begin with /")
		}
		for _, key := range strings.Split(path[1:], "/") {
			key = strings.ReplaceAll(strings.ReplaceAll(key, "~1", "/"), "~0", "~")
			switch node := v.(type) {
			case map[string]any:
				var ok bool
				v, ok = node[key]
				if !ok {
					return "", fmt.Errorf("JSON pointer not found")
				}
			case []any:
				i, e := strconv.Atoi(key)
				if e != nil || i < 0 || i >= len(node) {
					return "", fmt.Errorf("invalid JSON array index")
				}
				v = node[i]
			default:
				return "", fmt.Errorf("JSON pointer not found")
			}
		}
	}
	switch value := v.(type) {
	case string:
		return value, nil
	case json.Number:
		return value.String(), nil
	case bool:
		return strconv.FormatBool(value), nil
	default:
		return "", fmt.Errorf("extraction requires a scalar value")
	}
}
