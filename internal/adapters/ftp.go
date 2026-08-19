package adapters

import (
	"bytes"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/kvmukilan/livewire/internal/replay"
)

// FTP adapts the line-oriented control channel. Negotiated data connections
// are executed by ftpreplay.Coordinator, not as independent TCP sessions.
type FTP struct{}

func (FTP) DiscoverGroups(trace *replay.Trace) []replay.SessionGroup {
	if trace == nil {
		return nil
	}
	var groups []replay.SessionGroup
	for _, control := range trace.Sessions {
		if control.Transport != replay.TransportTCP || (FTP{}).Detect(*control) < 100 {
			continue
		}
		expected, err := ftpTransferExpectations(control)
		if err != nil {
			groups = append(groups, replay.SessionGroup{ID: "ftp:" + control.ID, ControlSessionID: control.ID, Blockers: []string{err.Error()}})
			continue
		}
		if len(expected) == 0 {
			continue
		}
		group := replay.SessionGroup{ID: "ftp:" + control.ID, ControlSessionID: control.ID}
		used := map[string]bool{control.ID: true}
		for i, want := range expected {
			before := int(^uint(0) >> 1)
			if i+1 < len(expected) {
				before = expected[i+1].after
			}
			var candidates []*replay.Session
			for _, candidate := range trace.Sessions {
				if used[candidate.ID] || candidate.Transport != replay.TransportTCP {
					continue
				}
				start := ftpSessionStart(candidate)
				if start >= want.after && start < before && ftpDataSessionMatches(candidate, control, want.endpoint) {
					candidates = append(candidates, candidate)
				}
			}
			switch len(candidates) {
			case 1:
				used[candidates[0].ID] = true
				group.RelatedSessionIDs = append(group.RelatedSessionIDs, candidates[0].ID)
			case 0:
				group.Blockers = append(group.Blockers, "FTP negotiation has no captured data session for "+want.endpoint.String())
			default:
				group.Blockers = append(group.Blockers, "FTP data-session mapping is ambiguous for "+want.endpoint.String())
			}
		}
		groups = append(groups, group)
	}
	return groups
}

type ftpTransferExpectation struct {
	endpoint netip.AddrPort
	after    int
}

func ftpTransferExpectations(control *replay.Session) ([]ftpTransferExpectation, error) {
	client, server, err := replay.TCPPayloadTimelines(control)
	if err != nil {
		return nil, err
	}
	type timedMessage struct {
		direction replay.Direction
		message   replay.Message
		point     replay.CapturePoint
	}
	var timeline []timedMessage
	for _, half := range []struct {
		direction replay.Direction
		stream    replay.TCPStreamTimeline
	}{{replay.ClientToServer, client}, {replay.ServerToClient, server}} {
		messages, err := (FTP{}).Decode(half.direction, half.stream.Data)
		if err != nil {
			return nil, err
		}
		offset := 0
		for _, message := range messages {
			end := offset + len(message.Raw)
			point, ok := half.stream.CompletionPoint(offset, end)
			if !ok {
				return nil, fmt.Errorf("FTP control message has no capture chronology")
			}
			timeline = append(timeline, timedMessage{direction: half.direction, message: message, point: point})
			offset = end
		}
	}
	sort.SliceStable(timeline, func(i, j int) bool {
		if timeline[i].point.At != timeline[j].point.At {
			return timeline[i].point.At < timeline[j].point.At
		}
		return timeline[i].point.PacketIndex < timeline[j].point.PacketIndex
	})
	var expected []ftpTransferExpectation
	var unresolved []int
	var endpoint netip.AddrPort
	negotiatedAt := -1
	setEndpoint := func(parsed netip.AddrPort, at int) {
		if len(unresolved) > 0 {
			index := unresolved[0]
			unresolved = unresolved[1:]
			expected[index].endpoint, expected[index].after = parsed, at
			return
		}
		endpoint, negotiatedAt = parsed, at
	}
	for _, item := range timeline {
		line := strings.TrimSpace(string(item.message.Raw))
		if item.direction == replay.ServerToClient {
			if port, ok := parseEPSV(line); ok {
				setEndpoint(netip.AddrPortFrom(control.Server.IP, port), item.point.PacketIndex)
			} else if parsed, ok := parsePASV(line); ok {
				setEndpoint(parsed, item.point.PacketIndex)
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "PORT":
			if len(fields) > 1 {
				if parsed, ok := parsePORT(fields[1]); ok {
					setEndpoint(parsed, item.point.PacketIndex)
				}
			}
		case "EPRT":
			if len(fields) > 1 {
				if parsed, ok := parseEPRT(fields[1]); ok {
					setEndpoint(parsed, item.point.PacketIndex)
				}
			}
		case "LIST", "NLST", "RETR", "STOR", "APPE", "STOU":
			expected = append(expected, ftpTransferExpectation{endpoint: endpoint, after: negotiatedAt})
			if !endpoint.IsValid() {
				unresolved = append(unresolved, len(expected)-1)
			}
			endpoint, negotiatedAt = netip.AddrPort{}, -1
		}
	}
	if len(unresolved) > 0 {
		return nil, fmt.Errorf("FTP capture has %d transfer command(s) without a negotiated data endpoint", len(unresolved))
	}
	return expected, nil
}

func ftpSessionStart(session *replay.Session) int {
	if session == nil || len(session.Events) == 0 {
		return int(^uint(0) >> 1)
	}
	return session.Events[0].PacketIndex
}

func parseEPSV(line string) (uint16, bool) {
	start, end := strings.LastIndex(line, "("), strings.LastIndex(line, ")")
	if start < 0 || end <= start+4 {
		return 0, false
	}
	value := line[start+1 : end]
	delim := value[0]
	parts := strings.Split(value, string(delim))
	if len(parts) < 5 {
		return 0, false
	}
	port, err := strconv.ParseUint(parts[len(parts)-2], 10, 16)
	return uint16(port), err == nil && port > 0
}

func parsePASV(line string) (netip.AddrPort, bool) {
	start, end := strings.LastIndex(line, "("), strings.LastIndex(line, ")")
	if start < 0 || end <= start {
		return netip.AddrPort{}, false
	}
	parts := strings.Split(line[start+1:end], ",")
	if len(parts) != 6 {
		return netip.AddrPort{}, false
	}
	values := make([]uint64, 6)
	for i := range parts {
		value, err := strconv.ParseUint(strings.TrimSpace(parts[i]), 10, 8)
		if err != nil {
			return netip.AddrPort{}, false
		}
		values[i] = value
	}
	ip := netip.AddrFrom4([4]byte{byte(values[0]), byte(values[1]), byte(values[2]), byte(values[3])})
	port := uint16(values[4]<<8 | values[5])
	return netip.AddrPortFrom(ip, port), port != 0
}

func parsePORT(value string) (netip.AddrPort, bool) { return parsePASV("(" + value + ")") }

func parseEPRT(value string) (netip.AddrPort, bool) {
	if len(value) < 5 {
		return netip.AddrPort{}, false
	}
	delim := value[0]
	parts := strings.Split(value, string(delim))
	if len(parts) < 5 {
		return netip.AddrPort{}, false
	}
	ip, err := netip.ParseAddr(parts[2])
	if err != nil {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(parts[3], 10, 16)
	return netip.AddrPortFrom(ip, uint16(port)), err == nil && port > 0
}

func ftpDataSessionMatches(candidate, control *replay.Session, endpoint netip.AddrPort) bool {
	if endpoint.Port() == 0 {
		return false
	}
	match := func(e replay.Endpoint) bool {
		if e.Port != endpoint.Port() {
			return false
		}
		return e.IP == endpoint.Addr() || e.IP == control.Client.IP || e.IP == control.Server.IP
	}
	return match(candidate.Client) || match(candidate.Server)
}

func (FTP) Name() string { return "ftp" }

func (FTP) Detect(s replay.Session) replay.Confidence {
	line := strings.ToUpper(string(firstLine(firstPayload(s))))
	if ftpReplyCode(line) != 0 || ftpCommand(line) != "" {
		return 100
	}
	return portConfidence(s, 21, 990)
}

func (FTP) Decode(dir replay.Direction, data []byte) ([]replay.Message, error) {
	var out []replay.Message
	for len(data) > 0 {
		lineEnd := bytes.Index(data, []byte("\r\n"))
		if lineEnd < 0 {
			return nil, fmt.Errorf("ftp: incomplete control line")
		}
		first := string(data[:lineEnd])
		end := lineEnd + 2
		fields := map[string]any{}
		kind := "ftp-command"
		if dir == replay.ServerToClient {
			kind = "ftp-reply"
			code := ftpReplyCode(first)
			if code == 0 {
				return nil, fmt.Errorf("ftp: malformed reply line %q", first)
			}
			fields["code"], fields["class"], fields["text"] = code, code/100, ftpReplyText(first)
			if len(first) >= 4 && first[3] == '-' {
				terminator := fmt.Sprintf("%03d ", code)
				for {
					nextEnd := bytes.Index(data[end:], []byte("\r\n"))
					if nextEnd < 0 {
						return nil, fmt.Errorf("ftp: incomplete multiline reply %03d", code)
					}
					line := string(data[end : end+nextEnd])
					end += nextEnd + 2
					if strings.HasPrefix(line, terminator) {
						fields["multiline"] = true
						break
					}
				}
			}
		} else {
			command := ftpCommand(first)
			if command == "" {
				return nil, fmt.Errorf("ftp: malformed command line %q", first)
			}
			fields["command"] = command
			argument := strings.TrimSpace(first[len(command):])
			if command == "PASS" || command == "ACCT" {
				fields["argument"] = "[REDACTED]"
			} else if argument != "" {
				fields["argument"] = argument
			}
		}
		raw := append([]byte(nil), data[:end]...)
		out = append(out, replay.Message{Kind: kind, Raw: raw, Fields: fields})
		data = data[end:]
	}
	return out, nil
}

func (FTP) Prepare(dir replay.Direction, msg replay.Message, state *replay.RuntimeState) ([]byte, error) {
	out := substitute(msg.Raw, state)
	if dir != replay.ClientToServer || state == nil {
		return out, nil
	}
	command := stringField(msg, "command")
	key := map[string]string{"USER": "ftp.user", "PASS": "ftp.password", "ACCT": "ftp.account"}[command]
	if key == "" || state.Variables[key] == "" {
		return out, nil
	}
	return []byte(command + " " + state.Variables[key] + "\r\n"), nil
}

func (FTP) Correlate(expected, actual replay.Message, _ *replay.RuntimeState) replay.Match {
	if expected.Kind != actual.Kind {
		return replay.Match{Reason: "FTP message direction differs"}
	}
	if expected.Kind == "ftp-command" {
		want, got := stringField(expected, "command"), stringField(actual, "command")
		return replay.Match{Matched: want == got, Key: want, Reason: differenceReason("command", want, got)}
	}
	want, got := intField(expected, "class"), intField(actual, "class")
	return replay.Match{Matched: want == got, Key: strconv.Itoa(want), Reason: differenceReason("reply class", want, got)}
}

func (FTP) Compare(expected, actual replay.Message, mode replay.VerifyMode) []replay.Difference {
	if expected.Kind != actual.Kind {
		return []replay.Difference{{Field: "kind", Expected: expected.Kind, Actual: actual.Kind, Structural: true}}
	}
	var out []replay.Difference
	if expected.Kind == "ftp-command" {
		want, got := stringField(expected, "command"), stringField(actual, "command")
		if want != got {
			out = append(out, replay.Difference{Field: "command", Expected: want, Actual: got, Structural: true})
		}
	} else {
		wantClass, gotClass := intField(expected, "class"), intField(actual, "class")
		if wantClass != gotClass {
			out = append(out, replay.Difference{Field: "replyClass", Expected: strconv.Itoa(wantClass), Actual: strconv.Itoa(gotClass), Structural: true})
		} else if mode == replay.VerifyStrict {
			want, got := intField(expected, "code"), intField(actual, "code")
			if want != got {
				out = append(out, replay.Difference{Field: "replyCode", Expected: strconv.Itoa(want), Actual: strconv.Itoa(got), Structural: true})
			}
		}
	}
	if mode == replay.VerifyStrict && expected.Kind == "ftp-command" && !bytes.Equal(expected.Raw, actual.Raw) {
		out = append(out, replay.Difference{Field: "message", Expected: "byte-identical", Actual: "different bytes", Structural: true})
	}
	return out
}

func firstLine(data []byte) []byte {
	if i := bytes.Index(data, []byte("\r\n")); i >= 0 {
		return data[:i]
	}
	return data
}

func ftpCommand(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	command := strings.ToUpper(fields[0])
	for _, known := range []string{
		"USER", "PASS", "ACCT", "AUTH", "PBSZ", "PROT", "PASV", "EPSV", "PORT", "EPRT",
		"LIST", "NLST", "RETR", "STOR", "APPE", "STOU", "TYPE", "MODE", "STRU", "CWD", "PWD",
		"CDUP", "DELE", "MKD", "RMD", "RNFR", "RNTO", "SIZE", "MDTM", "REST", "FEAT", "OPTS",
		"SYST", "STAT", "HELP", "NOOP", "QUIT",
	} {
		if command == known {
			return command
		}
	}
	return ""
}

func ftpReplyCode(line string) int {
	if len(line) < 3 || line[0] < '1' || line[0] > '5' {
		return 0
	}
	for i := 1; i < 3; i++ {
		if line[i] < '0' || line[i] > '9' {
			return 0
		}
	}
	if len(line) > 3 && line[3] != ' ' && line[3] != '-' {
		return 0
	}
	code, _ := strconv.Atoi(line[:3])
	return code
}

func ftpReplyText(line string) string {
	if len(line) <= 4 {
		return ""
	}
	return line[4:]
}

func intField(msg replay.Message, key string) int {
	switch value := msg.Fields[key].(type) {
	case int:
		return value
	case float64:
		return int(value)
	default:
		return 0
	}
}

func differenceReason[T comparable](field string, expected, actual T) string {
	if expected == actual {
		return ""
	}
	return fmt.Sprintf("%s differs", field)
}
