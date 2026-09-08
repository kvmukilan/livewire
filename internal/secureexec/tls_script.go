package secureexec

import (
	"fmt"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/tlsreplay"
	"sort"
)

func BuildTLSAdapterScript(messages []tlsreplay.AppMessage, adapter replay.Adapter, state *replay.RuntimeState) ([]tlsreplay.AppMessage, error) {
	var clientStream, serverStream []byte
	for _, msg := range messages {
		if msg.Role == tlsreplay.FromClient {
			clientStream = append(clientStream, msg.Data...)
		} else {
			serverStream = append(serverStream, msg.Data...)
		}
	}
	clientMessages, err := adapter.Decode(replay.ClientToServer, clientStream)
	if err != nil {
		return nil, fmt.Errorf("inner %s client stream: %w", adapter.Name(), err)
	}
	serverMessages, err := replay.DecodeWithContext(adapter, replay.ServerToClient, serverStream, clientMessages)
	if err != nil {
		return nil, fmt.Errorf("inner %s server stream: %w", adapter.Name(), err)
	}
	prepared := make([][]byte, len(clientMessages))
	for i, msg := range clientMessages {
		prepared[i], err = adapter.Prepare(replay.ClientToServer, msg, state)
		if err != nil {
			return nil, fmt.Errorf("inner %s prepare message %d: %w", adapter.Name(), i, err)
		}
	}
	clientPoints, err := ApplicationMessageCapturePoints(messages, tlsreplay.FromClient, clientMessages)
	if err != nil {
		return nil, fmt.Errorf("inner %s client chronology: %w", adapter.Name(), err)
	}
	serverPoints, err := ApplicationMessageCapturePoints(messages, tlsreplay.FromServer, serverMessages)
	if err != nil {
		return nil, fmt.Errorf("inner %s server chronology: %w", adapter.Name(), err)
	}
	type item struct {
		role  tlsreplay.AppRole
		index int
		point replay.CapturePoint
	}
	items := make([]item, 0, len(clientMessages)+len(serverMessages))
	for i, point := range clientPoints {
		items = append(items, item{role: tlsreplay.FromClient, index: i, point: point})
	}
	for i, point := range serverPoints {
		items = append(items, item{role: tlsreplay.FromServer, index: i, point: point})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].point.At != items[j].point.At {
			return items[i].point.At < items[j].point.At
		}
		return items[i].point.PacketIndex < items[j].point.PacketIndex
	})
	var script []tlsreplay.AppMessage
	var pendingPeers []replay.Message
	for i := 0; i < len(items); {
		item := items[i]
		if item.role == tlsreplay.FromClient {
			script = append(script, tlsreplay.AppMessage{Role: tlsreplay.FromClient, Data: prepared[item.index], CapturedAt: item.point.At, CapturedPacket: item.point.PacketIndex, HasCaptureTime: true})
			pendingPeers = append(pendingPeers, clientMessages[item.index])
			i++
			continue
		}
		var expected []replay.Message
		var raw []byte
		lastPoint := item.point
		for i < len(items) && items[i].role == tlsreplay.FromServer {
			message := serverMessages[items[i].index]
			expected = append(expected, message)
			raw = append(raw, message.Raw...)
			lastPoint = items[i].point
			i++
		}
		peers := append([]replay.Message(nil), pendingPeers...)
		script = append(script, tlsreplay.AppMessage{Role: tlsreplay.FromServer, Data: raw, Expected: expected, Peers: peers, CapturedAt: lastPoint.At, CapturedPacket: lastPoint.PacketIndex, HasCaptureTime: true})
		consumed := replay.ConsumePeers(adapter, replay.ServerToClient, expected, len(pendingPeers))
		pendingPeers = pendingPeers[consumed:]
	}
	return script, nil
}

func ApplicationMessageCapturePoints(records []tlsreplay.AppMessage, role tlsreplay.AppRole, messages []replay.Message) ([]replay.CapturePoint, error) {
	type boundary struct {
		end   int
		point replay.CapturePoint
	}
	var boundaries []boundary
	total := 0
	for _, record := range records {
		if record.Role != role {
			continue
		}
		if !record.HasCaptureTime {
			return nil, fmt.Errorf("decrypted record has no capture timeline")
		}
		total += len(record.Data)
		boundaries = append(boundaries, boundary{end: total, point: replay.CapturePoint{At: record.CapturedAt, PacketIndex: record.CapturedPacket}})
	}
	points := make([]replay.CapturePoint, len(messages))
	consumed := 0
	boundaryIndex := 0
	for i, message := range messages {
		if len(message.Raw) == 0 {
			return nil, fmt.Errorf("message %d has no raw framing bytes", i)
		}
		consumed += len(message.Raw)
		for boundaryIndex < len(boundaries) && boundaries[boundaryIndex].end < consumed {
			boundaryIndex++
		}
		if boundaryIndex >= len(boundaries) {
			return nil, fmt.Errorf("message framing consumes %d bytes but decrypted records contain %d", consumed, total)
		}
		points[i] = boundaries[boundaryIndex].point
	}
	if consumed != total {
		return nil, fmt.Errorf("adapter consumed %d of %d decrypted plaintext bytes", consumed, total)
	}
	return points, nil
}
