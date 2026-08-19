package ftpreplay

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/kvmukilan/livewire/internal/replay"
)

// MatchDataSessions maps each transfer command to the uniquely negotiated TCP
// data session in capture order.
func MatchDataSessions(trace *replay.Trace, control *replay.Session, script Script) ([]*replay.Session, error) {
	if trace == nil || control == nil {
		return nil, fmt.Errorf("ftpreplay: trace and control session are required")
	}
	type expectation struct {
		endpoint netip.AddrPort
		after    int
	}
	var expected []expectation
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
	for _, turn := range script.Turns {
		line := strings.TrimSpace(string(turn.Message.Raw))
		if turn.Direction == replay.ClientToServer {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			switch strings.ToUpper(fields[0]) {
			case "PORT":
				if len(fields) > 1 {
					if parsed, ok := capturedPORT(fields[1]); ok {
						setEndpoint(parsed, turn.CapturedAt.PacketIndex)
					}
				}
			case "EPRT":
				if len(fields) > 1 {
					if parsed, ok := capturedEPRT(fields[1]); ok {
						setEndpoint(parsed, turn.CapturedAt.PacketIndex)
					}
				}
			case "LIST", "NLST", "RETR", "STOR", "APPE", "STOU":
				expected = append(expected, expectation{endpoint: endpoint, after: negotiatedAt})
				if !endpoint.IsValid() {
					unresolved = append(unresolved, len(expected)-1)
				}
				endpoint, negotiatedAt = netip.AddrPort{}, -1
			}
		} else {
			if port, ok := capturedPassivePort(line); ok {
				setEndpoint(netip.AddrPortFrom(control.Server.IP, port), turn.CapturedAt.PacketIndex)
			}
		}
	}
	if len(expected) == 0 {
		return nil, nil
	}
	if len(unresolved) > 0 {
		return nil, fmt.Errorf("ftpreplay: %d transfer command(s) have no PASV, EPSV, PORT, or EPRT negotiation", len(unresolved))
	}
	used := map[string]bool{control.ID: true}
	var matched []*replay.Session
	for i, want := range expected {
		before := int(^uint(0) >> 1)
		if i+1 < len(expected) {
			before = expected[i+1].after
		}
		var candidates []*replay.Session
		for _, session := range trace.Sessions {
			if used[session.ID] || session.Transport != replay.TransportTCP {
				continue
			}
			start := sessionStart(session)
			if start >= want.after && start < before && dataSessionMatches(session, control, want.endpoint) {
				candidates = append(candidates, session)
			}
		}
		if len(candidates) > 1 {
			return nil, fmt.Errorf("ftpreplay: ambiguous data sessions on port %d between capture packets %d and %d", want.endpoint.Port(), want.after, before)
		}
		if len(candidates) == 0 {
			return nil, fmt.Errorf("ftpreplay: mapped %d of %d data sessions; no match for port %d after capture packet %d", len(matched), len(expected), want.endpoint.Port(), want.after)
		}
		used[candidates[0].ID] = true
		matched = append(matched, candidates[0])
	}
	return matched, nil
}

func dataSessionMatches(session, control *replay.Session, endpoint netip.AddrPort) bool {
	match := func(candidate replay.Endpoint) bool {
		return candidate.Port == endpoint.Port() && (candidate.IP == endpoint.Addr() || candidate.IP == control.Client.IP || candidate.IP == control.Server.IP)
	}
	return match(session.Client) || match(session.Server)
}

func capturedPassivePort(line string) (uint16, bool) {
	start, end := strings.LastIndex(line, "("), strings.LastIndex(line, ")")
	if start < 0 || end <= start {
		return 0, false
	}
	value := line[start+1 : end]
	if strings.Contains(value, "|||") {
		parts := strings.Split(value, "|")
		port, err := strconv.ParseUint(parts[len(parts)-2], 10, 16)
		return uint16(port), err == nil && port > 0
	}
	parts := strings.Split(value, ",")
	if len(parts) != 6 {
		return 0, false
	}
	p1, err1 := strconv.ParseUint(strings.TrimSpace(parts[4]), 10, 8)
	p2, err2 := strconv.ParseUint(strings.TrimSpace(parts[5]), 10, 8)
	port := uint16(p1<<8 | p2)
	return port, err1 == nil && err2 == nil && port > 0
}

func capturedPORT(value string) (netip.AddrPort, bool) {
	parts := strings.Split(value, ",")
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
	return netip.AddrPortFrom(ip, port), port > 0
}

func capturedEPRT(value string) (netip.AddrPort, bool) {
	if len(value) < 5 {
		return netip.AddrPort{}, false
	}
	parts := strings.Split(value, string(value[0]))
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

func sessionStart(session *replay.Session) int {
	if session == nil || len(session.Events) == 0 {
		return int(^uint(0) >> 1)
	}
	return session.Events[0].PacketIndex
}
