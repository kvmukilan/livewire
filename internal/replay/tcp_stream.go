package replay

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"github.com/kvmukilan/livewire/internal/wire"
)

const maxTCPApplicationStream = 64 << 20

type tcpPayloadSegment struct {
	direction Direction
	at        time.Duration
	packet    int
	offset    int64
	data      []byte
}

// TCPStreamTimeline is a sequence-reassembled TCP byte stream plus enough
// capture metadata to determine when any byte range became complete. It lets
// higher-level protocols restore cross-direction chronology after each TCP
// direction has been reassembled independently.
type TCPStreamTimeline struct {
	Data     []byte
	segments []tcpPayloadSegment
}

type CapturePoint struct {
	At          time.Duration
	PacketIndex int
}

// CompletionTime returns the earliest capture time at which every byte in the
// half-open stream range [start,end) had arrived. Retransmissions do not delay
// completion, while out-of-order segments contribute only after they fill the
// required range.
func (s TCPStreamTimeline) CompletionTime(start, end int) (time.Duration, bool) {
	point, ok := s.CompletionPoint(start, end)
	return point.At, ok
}

// CompletionPoint is CompletionTime with packet-index ordering for captures
// whose timestamps collide.
func (s TCPStreamTimeline) CompletionPoint(start, end int) (CapturePoint, bool) {
	if start < 0 || end <= start || end > len(s.Data) {
		return CapturePoint{}, false
	}
	segments := append([]tcpPayloadSegment(nil), s.segments...)
	sort.SliceStable(segments, func(i, j int) bool {
		if segments[i].at != segments[j].at {
			return segments[i].at < segments[j].at
		}
		return segments[i].packet < segments[j].packet
	})
	covered := make([]bool, end-start)
	remaining := len(covered)
	for _, segment := range segments {
		lo := maxInt64(int64(start), segment.offset)
		hi := minInt64(int64(end), segment.offset+int64(len(segment.data)))
		for pos := lo; pos < hi; pos++ {
			i := int(pos) - start
			if !covered[i] {
				covered[i] = true
				remaining--
			}
		}
		if remaining == 0 {
			return CapturePoint{At: segment.at, PacketIndex: segment.packet}, true
		}
	}
	return CapturePoint{}, false
}

type tcpStreamAssembly struct {
	stream   []byte
	segments []tcpPayloadSegment
}

// TCPPayloadStreams reconstructs both TCP byte streams by sequence number. It
// removes retransmissions, accepts consistent partial overlaps, handles the
// 32-bit sequence wrap, and rejects gaps or conflicting retransmissions rather
// than manufacturing an application stream that was not present in the capture.
func TCPPayloadStreams(s *Session) (client, server []byte, err error) {
	clientTimeline, serverTimeline, err := TCPPayloadTimelines(s)
	if err != nil {
		return nil, nil, err
	}
	return clientTimeline.Data, serverTimeline.Data, nil
}

// TCPPayloadTimelines reconstructs both directions and retains capture timing
// for consumers such as TLS that must merge application records back into the
// actual cross-direction order.
func TCPPayloadTimelines(s *Session) (client, server TCPStreamTimeline, err error) {
	assembled, fallback, err := assembleTCPStreams(s)
	if err != nil {
		return TCPStreamTimeline{}, TCPStreamTimeline{}, err
	}
	if fallback != nil {
		streams := map[Direction]*TCPStreamTimeline{ClientToServer: &client, ServerToClient: &server}
		for _, event := range s.Events {
			if len(event.Payload) == 0 {
				continue
			}
			stream := streams[event.Direction]
			offset := int64(len(stream.Data))
			data := append([]byte(nil), event.Payload...)
			stream.Data = append(stream.Data, data...)
			stream.segments = append(stream.segments, tcpPayloadSegment{direction: event.Direction, at: event.At, packet: event.PacketIndex, offset: offset, data: data})
		}
		return client, server, nil
	}
	client = TCPStreamTimeline{Data: assembled[ClientToServer].stream, segments: assembled[ClientToServer].segments}
	server = TCPStreamTimeline{Data: assembled[ServerToClient].stream, segments: assembled[ServerToClient].segments}
	return client, server, nil
}

func assembleTCPStreams(s *Session) (map[Direction]tcpStreamAssembly, map[Direction][]byte, error) {
	if s == nil || s.Transport != TransportTCP {
		return nil, nil, fmt.Errorf("TCP stream reconstruction requires a TCP session")
	}
	byDirection := map[Direction][]tcpPayloadSegment{}
	fallback := map[Direction][]byte{}
	starts := map[Direction]uint32{}
	ends := map[Direction]uint32{}
	sequenced, unsequenced := 0, 0
	for _, event := range s.Events {
		if len(event.Payload) == 0 && (event.Record == nil || len(event.Record.Data) == 0) {
			continue
		}
		if event.Direction != ClientToServer && event.Direction != ServerToClient {
			return nil, nil, fmt.Errorf("packet %d: TCP direction is unknown", event.PacketIndex)
		}
		if event.Record == nil || len(event.Record.Data) == 0 {
			unsequenced++
			if len(fallback[event.Direction])+len(event.Payload) > maxTCPApplicationStream {
				return nil, nil, fmt.Errorf("%s TCP application stream exceeds %d bytes", event.Direction, maxTCPApplicationStream)
			}
			fallback[event.Direction] = append(fallback[event.Direction], event.Payload...)
			continue
		}
		packet, parseErr := wire.Parse(event.Record.Data, event.Record.LinkType)
		if parseErr != nil || !packet.IsTCP() {
			return nil, nil, fmt.Errorf("%s packet %d: cannot recover TCP sequence metadata", event.Direction, event.PacketIndex)
		}
		sequence := packet.Seq().Uint32()
		if packet.HasFlags(wire.FlagSYN) {
			sequence++
			if start, ok := starts[event.Direction]; ok && start != sequence {
				return nil, nil, fmt.Errorf("%s TCP session has conflicting SYN sequences at packet %d", event.Direction, event.PacketIndex)
			}
			starts[event.Direction] = sequence
		}
		if packet.HasFlags(wire.FlagFIN) {
			end := sequence + uint32(len(event.Payload))
			if previous, ok := ends[event.Direction]; ok && previous != end {
				return nil, nil, fmt.Errorf("%s TCP session has conflicting FIN sequences at packet %d", event.Direction, event.PacketIndex)
			}
			ends[event.Direction] = end
		}
		if len(event.Payload) == 0 {
			continue
		}
		byDirection[event.Direction] = append(byDirection[event.Direction], tcpPayloadSegment{
			direction: event.Direction,
			at:        event.At,
			packet:    event.PacketIndex,
			offset:    int64(sequence),
			data:      append([]byte(nil), event.Payload...),
		})
		sequenced++
	}
	if sequenced == 0 && unsequenced > 0 {
		return nil, fallback, nil
	}
	if unsequenced > 0 {
		return nil, nil, fmt.Errorf("TCP session mixes sequenced capture records with %d payload event(s) lacking frame metadata", unsequenced)
	}

	result := map[Direction]tcpStreamAssembly{}
	for _, direction := range []Direction{ClientToServer, ServerToClient} {
		segments := byDirection[direction]
		if len(segments) == 0 {
			if start, ok := starts[direction]; ok {
				if end, ok := ends[direction]; ok && start != end {
					return nil, nil, fmt.Errorf("%s TCP stream gap between SYN and FIN: missing %d byte(s)", direction, uint32(end-start))
				}
			}
			result[direction] = tcpStreamAssembly{}
			continue
		}
		anchor := uint32(segments[0].offset)
		for i := range segments {
			// RFC serial arithmetic is unambiguous for capture streams smaller
			// than 2 GiB, well above the bounded reconstruction size here.
			segments[i].offset = int64(int32(uint32(segments[i].offset) - anchor))
		}
		sort.SliceStable(segments, func(i, j int) bool {
			if segments[i].offset != segments[j].offset {
				return segments[i].offset < segments[j].offset
			}
			return segments[i].packet < segments[j].packet
		})
		base := segments[0].offset
		if start, ok := starts[direction]; ok && anchor+uint32(base) != start {
			gap := int64(int32(anchor + uint32(base) - start))
			if gap > 0 {
				return nil, nil, fmt.Errorf("%s TCP stream gap after SYN: missing %d byte(s)", direction, gap)
			}
			return nil, nil, fmt.Errorf("%s TCP payload precedes captured SYN sequence", direction)
		}
		cursor := base
		stream := make([]byte, 0)
		for _, segment := range segments {
			if segment.offset > cursor {
				return nil, nil, fmt.Errorf("%s TCP stream gap before packet %d: missing %d byte(s)", direction, segment.packet, segment.offset-cursor)
			}
			overlap := cursor - segment.offset
			if overlap > 0 {
				check := int64(len(segment.data))
				if overlap < check {
					check = overlap
				}
				start := segment.offset - base
				if start < 0 || start+check > int64(len(stream)) || !bytes.Equal(stream[start:start+check], segment.data[:check]) {
					return nil, nil, fmt.Errorf("%s TCP stream has conflicting overlap at packet %d", direction, segment.packet)
				}
				if overlap >= int64(len(segment.data)) {
					continue
				}
				segment.data = segment.data[overlap:]
			}
			if len(stream)+len(segment.data) > maxTCPApplicationStream {
				return nil, nil, fmt.Errorf("%s TCP application stream exceeds %d bytes", direction, maxTCPApplicationStream)
			}
			stream = append(stream, segment.data...)
			cursor += int64(len(segment.data))
		}
		if end, ok := ends[direction]; ok && anchor+uint32(cursor) != end {
			gap := int64(int32(end - (anchor + uint32(cursor))))
			if gap > 0 {
				return nil, nil, fmt.Errorf("%s TCP stream gap before FIN: missing %d byte(s)", direction, gap)
			}
			return nil, nil, fmt.Errorf("%s TCP payload extends beyond captured FIN sequence", direction)
		}
		for i := range segments {
			segments[i].offset -= base
		}
		result[direction] = tcpStreamAssembly{stream: stream, segments: segments}
	}
	return result, nil, nil
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
