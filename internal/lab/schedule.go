package lab

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net/netip"
	"sort"
	"time"

	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/wire"
)

type ScheduledFrame struct {
	At          time.Duration    `json:"at"`
	OriginalAt  time.Duration    `json:"originalAt"`
	SessionID   string           `json:"sessionId"`
	PacketIndex int              `json:"packetIndex"`
	Direction   replay.Direction `json:"direction"`
	Side        string           `json:"side"`
	Data        []byte           `json:"-"`
	LinkType    wire.LinkType    `json:"linkType"`
	Faults      []string         `json:"faults,omitempty"`
	reorder     int
	reorderKey  string
}

type ScheduleReport struct {
	InputFrames     int      `json:"inputFrames"`
	ScheduledFrames int      `json:"scheduledFrames"`
	DroppedFrames   int      `json:"droppedFrames"`
	Duplicated      int      `json:"duplicatedFrames"`
	Fragmented      int      `json:"fragmentedFrames"`
	Limitations     []string `json:"limitations,omitempty"`
}

func CompileSchedule(trace *replay.Trace, scenario Scenario, topology ...Topology) ([]ScheduledFrame, ScheduleReport, error) {
	if trace == nil {
		return nil, ScheduleReport{}, fmt.Errorf("lab: nil trace")
	}
	if err := scenario.Validate(); err != nil {
		return nil, ScheduleReport{}, err
	}
	type item struct {
		session string
		event   replay.Event
	}
	var items []item
	for _, s := range trace.Sessions {
		for _, e := range s.Events {
			items = append(items, item{s.ID, e})
		}
	}
	for _, e := range trace.Raw {
		items = append(items, item{"raw-0", e})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].event.At < items[j].event.At })
	report := ScheduleReport{InputFrames: len(items)}
	rateNext := map[string]time.Duration{}
	var out []ScheduledFrame
	for _, in := range items {
		e := in.event
		if in.session == "raw-0" && e.Direction == replay.DirectionUnknown && len(topology) > 0 {
			if direction, ok := inferRawDirection(e, topology[0]); ok {
				e.Direction = direction
			} else {
				report.Limitations = appendUniqueString(report.Limitations, "one or more raw-lane frames could not be assigned to a topology endpoint and defaulted to the client side")
			}
		}
		at := e.At
		duplicates, mtu, reorder := 0, 0, 0
		reorderKey := ""
		var faults []string
		dropped := false
		for ri, rule := range scenario.Rules {
			if !rule.Match.matches(in.session, e) {
				continue
			}
			a := rule.Action
			at += a.Delay.Duration
			if a.Delay.Duration != 0 {
				faults = append(faults, "delay="+a.Delay.String())
			}
			if a.Jitter.Duration != 0 {
				j := deterministicSigned(scenario.Seed, in.session, e.PacketIndex, ri)
				delta := time.Duration(float64(a.Jitter.Duration) * j)
				at += delta
				faults = append(faults, "jitter="+delta.String())
			}
			if a.Drop > 0 && deterministicUnit(scenario.Seed, in.session, e.PacketIndex, ri, 1) < a.Drop {
				dropped = true
				faults = append(faults, "drop")
			}
			duplicates += a.Duplicate
			if a.MTU > 0 && (mtu == 0 || a.MTU < mtu) {
				mtu = a.MTU
			}
			if a.Reorder > reorder {
				reorder, reorderKey = a.Reorder, fmt.Sprintf("%s/%s/%d", in.session, e.Direction, ri)
			}
			if a.RateBPS > 0 {
				key := fmt.Sprintf("%d/%s", ri, e.Direction)
				if at < rateNext[key] {
					at = rateNext[key]
				}
				bits := int64(len(e.Record.Data) * 8)
				rateNext[key] = at + time.Duration(float64(time.Second)*float64(bits)/float64(a.RateBPS))
				faults = append(faults, fmt.Sprintf("rate=%dbps", a.RateBPS))
			}
		}
		if dropped {
			report.DroppedFrames++
			continue
		}
		if at < 0 {
			at = 0
		}
		frames := [][]byte{append([]byte(nil), e.Record.Data...)}
		if mtu > 0 {
			var limitation string
			frames, limitation = fragmentForMTU(frames[0], e.Record.LinkType, mtu, uint32(e.PacketIndex+1))
			if limitation != "" {
				report.Limitations = appendUniqueString(report.Limitations, limitation)
			}
			if len(frames) > 1 {
				report.Fragmented += len(frames) - 1
				faults = append(faults, fmt.Sprintf("mtu=%d", mtu))
			}
		}
		for copyIndex := 0; copyIndex <= duplicates; copyIndex++ {
			for fi, frame := range frames {
				copyFaults := append([]string(nil), faults...)
				if copyIndex > 0 {
					copyFaults = append(copyFaults, fmt.Sprintf("duplicate=%d", copyIndex))
					report.Duplicated++
				}
				side := "client"
				if e.Direction == replay.ServerToClient {
					side = "server"
				}
				out = append(out, ScheduledFrame{
					At: at + time.Duration(fi+copyIndex)*time.Nanosecond, OriginalAt: e.At,
					SessionID: in.session, PacketIndex: e.PacketIndex, Direction: e.Direction,
					Side: side, Data: frame, LinkType: e.Record.LinkType, Faults: copyFaults,
					reorder: reorder, reorderKey: reorderKey,
				})
			}
		}
	}
	applyReorder(out)
	sort.SliceStable(out, func(i, j int) bool { return out[i].At < out[j].At })
	report.ScheduledFrames = len(out)
	return out, report, nil
}

func inferRawDirection(event replay.Event, topology Topology) (replay.Direction, bool) {
	if event.Record == nil {
		return replay.DirectionUnknown, false
	}
	packet, err := wire.Parse(event.Record.Data, event.Record.LinkType)
	if err != nil || !packet.SrcIP().IsValid() || !packet.DstIP().IsValid() {
		return replay.DirectionUnknown, false
	}
	sourceRole := capturedIPRole(topology, packet.SrcIP())
	destinationRole := capturedIPRole(topology, packet.DstIP())
	switch {
	case sourceRole == "client" && destinationRole != "client":
		return replay.ClientToServer, true
	case sourceRole == "server" && destinationRole != "server":
		return replay.ServerToClient, true
	case destinationRole == "server" && sourceRole != "server":
		return replay.ClientToServer, true
	case destinationRole == "client" && sourceRole != "client":
		return replay.ServerToClient, true
	default:
		return replay.DirectionUnknown, false
	}
}

func capturedIPRole(topology Topology, address netip.Addr) string {
	role := ""
	for _, mapping := range topology.Mappings {
		if mapping.Captured.IP != address {
			continue
		}
		if role != "" && role != mapping.Role {
			return "ambiguous"
		}
		role = mapping.Role
	}
	return role
}

func deterministicUnit(seed int64, session string, packet, rule, salt int) float64 {
	h := fnv.New64a()
	_, _ = fmt.Fprintf(h, "%d/%s/%d/%d/%d", seed, session, packet, rule, salt)
	return float64(h.Sum64()>>11) / float64(uint64(1)<<53)
}

func deterministicSigned(seed int64, session string, packet, rule int) float64 {
	return deterministicUnit(seed, session, packet, rule, 0)*2 - 1
}

func applyReorder(frames []ScheduledFrame) {
	groups := map[string][]int{}
	for i := range frames {
		if frames[i].reorder > 1 {
			groups[frames[i].reorderKey] = append(groups[frames[i].reorderKey], i)
		}
	}
	for _, idxs := range groups {
		window := frames[idxs[0]].reorder
		for start := 0; start < len(idxs); start += window {
			end := start + window
			if end > len(idxs) {
				end = len(idxs)
			}
			for left, right := start, end-1; left < right; left, right = left+1, right-1 {
				i, j := idxs[left], idxs[right]
				frames[i].At, frames[j].At = frames[j].At, frames[i].At
				frames[i].Faults = append(frames[i].Faults, fmt.Sprintf("reorder-window=%d", window))
				frames[j].Faults = append(frames[j].Faults, fmt.Sprintf("reorder-window=%d", window))
			}
		}
	}
}

func fragmentForMTU(frame []byte, link wire.LinkType, mtu int, id uint32) ([][]byte, string) {
	p, err := wire.Parse(frame, link)
	if err != nil || (!p.IsIPv4() && !p.IsIPv6()) {
		return [][]byte{frame}, "MTU rule skipped a non-IP or malformed frame"
	}
	ipLen := len(frame) - p.L3Offset()
	if ipLen <= mtu {
		return [][]byte{frame}, ""
	}
	if p.IsIPv4() {
		if p.DontFragment() {
			return nil, "MTU rule dropped an IPv4 DF packet that exceeded the configured MTU"
		}
		return fragmentIPv4(frame, p, mtu), ""
	}
	if p.L3HeaderLen() != 40 {
		return [][]byte{frame}, "IPv6 MTU fragmentation currently requires no pre-existing extension headers"
	}
	return fragmentIPv6(frame, p, mtu, id), ""
}

func fragmentIPv4(frame []byte, p *wire.Packet, mtu int) [][]byte {
	l3, ihl := p.L3Offset(), p.L3HeaderLen()
	end := l3 + int(binary.BigEndian.Uint16(frame[l3+2:l3+4]))
	if end > len(frame) {
		end = len(frame)
	}
	payload := frame[l3+ihl : end]
	chunk := ((mtu - ihl) / 8) * 8
	if chunk <= 0 {
		return nil
	}
	var out [][]byte
	for off := 0; off < len(payload); off += chunk {
		n := chunk
		if n > len(payload)-off {
			n = len(payload) - off
		}
		f := append([]byte(nil), frame[:l3+ihl]...)
		f = append(f, payload[off:off+n]...)
		binary.BigEndian.PutUint16(f[l3+2:l3+4], uint16(ihl+n))
		word := uint16(off/8) & 0x1fff
		if off+n < len(payload) {
			word |= 0x2000
		}
		binary.BigEndian.PutUint16(f[l3+6:l3+8], word)
		f[l3+10], f[l3+11] = 0, 0
		binary.BigEndian.PutUint16(f[l3+10:l3+12], checksum16(f[l3:l3+ihl]))
		out = append(out, f)
	}
	return out
}

func fragmentIPv6(frame []byte, p *wire.Packet, mtu int, id uint32) [][]byte {
	l3 := p.L3Offset()
	end := l3 + 40 + int(binary.BigEndian.Uint16(frame[l3+4:l3+6]))
	if end > len(frame) {
		end = len(frame)
	}
	payload := frame[l3+40 : end]
	chunk := ((mtu - 48) / 8) * 8
	if chunk <= 0 {
		return nil
	}
	next := frame[l3+6]
	var out [][]byte
	for off := 0; off < len(payload); off += chunk {
		n := chunk
		if n > len(payload)-off {
			n = len(payload) - off
		}
		f := append([]byte(nil), frame[:l3+40]...)
		f[l3+6] = 44
		fh := make([]byte, 8)
		fh[0] = next
		word := uint16(off/8) << 3
		if off+n < len(payload) {
			word |= 1
		}
		binary.BigEndian.PutUint16(fh[2:4], word)
		binary.BigEndian.PutUint32(fh[4:8], id)
		f = append(f, fh...)
		f = append(f, payload[off:off+n]...)
		binary.BigEndian.PutUint16(f[l3+4:l3+6], uint16(8+n))
		out = append(out, f)
	}
	return out
}

func checksum16(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func appendUniqueString(in []string, value string) []string {
	for _, x := range in {
		if x == value {
			return in
		}
	}
	return append(in, value)
}
