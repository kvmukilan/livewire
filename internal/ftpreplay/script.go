// Package ftpreplay coordinates FTP control and negotiated data connections,
// including fresh TLS re-termination for explicit and implicit FTPS captures.
package ftpreplay

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/tlsreplay"
)

type Turn struct {
	Direction  replay.Direction
	Message    replay.Message
	CapturedAt replay.CapturePoint
	FromTLS    bool
}

type Script struct {
	Turns       []Turn
	Explicit    bool
	Implicit    bool
	ProtectData bool
}

// BuildScript reconstructs the control chronology. keylog is required only
// when captured control bytes contain TLS records.
func BuildScript(session *replay.Session, keylog *tlsreplay.KeyLog) (Script, error) {
	if session == nil || session.Transport != replay.TransportTCP {
		return Script{}, fmt.Errorf("ftpreplay: a TCP control session is required")
	}
	client, server, err := replay.TCPPayloadTimelines(session)
	if err != nil {
		return Script{}, err
	}
	clientTLS := findTLSStart(client.Data, 0)
	serverTLS := findTLSStart(server.Data, 0)
	implicit := clientTLS == 0 && serverTLS == 0 && dissect.DetectTLS(client.Data).IsTLS
	authEnd := bytes.Index(bytes.ToUpper(client.Data), []byte("AUTH TLS\r\n"))
	explicit := authEnd >= 0
	if explicit {
		authEnd += len("AUTH TLS\r\n")
		clientTLS = findTLSStart(client.Data, authEnd)
		serverTLS = findTLSStart(server.Data, 0)
		if clientTLS < 0 || serverTLS < 0 {
			return Script{}, fmt.Errorf("ftpreplay: AUTH TLS is present but encrypted control records are incomplete")
		}
	}
	if !implicit && !explicit {
		turns, err := timedPlainTurns(client, server, len(client.Data), len(server.Data))
		if err != nil {
			return Script{}, err
		}
		return Script{Turns: turns, ProtectData: scriptProtectsData(turns)}, nil
	}
	if keylog == nil {
		return Script{}, fmt.Errorf("ftpreplay: FTPS capture requires a matching NSS key log")
	}
	var turns []Turn
	if explicit {
		plain, err := timedPlainTurns(client, server, clientTLS, serverTLS)
		if err != nil {
			return Script{}, err
		}
		turns = append(turns, plain...)
	}
	completion := func(timeline replay.TCPStreamTimeline, offset int) tlsreplay.RecordCompletion {
		return func(start, end int) (replay.CapturePoint, bool) {
			return timeline.CompletionPoint(offset+start, offset+end)
		}
	}
	messages, err := tlsreplay.NewDecryptor(keylog).DecryptFlowTimed(
		client.Data[clientTLS:], server.Data[serverTLS:],
		completion(client, clientTLS), completion(server, serverTLS),
	)
	if err != nil {
		return Script{}, fmt.Errorf("ftpreplay: decrypt control channel: %w", err)
	}
	ftp := adapters.FTP{}
	for _, app := range tlsreplay.ConversationOrder(messages) {
		direction := replay.ClientToServer
		if app.Role == tlsreplay.FromServer {
			direction = replay.ServerToClient
		}
		decoded, err := ftp.Decode(direction, app.Data)
		if err != nil {
			return Script{}, fmt.Errorf("ftpreplay: decode decrypted FTP: %w", err)
		}
		for _, message := range decoded {
			turns = append(turns, Turn{Direction: direction, Message: message, CapturedAt: replay.CapturePoint{At: app.CapturedAt, PacketIndex: app.CapturedPacket}, FromTLS: true})
		}
	}
	sortTurns(turns)
	return Script{Turns: turns, Explicit: explicit, Implicit: implicit, ProtectData: scriptProtectsData(turns)}, nil
}

func timedPlainTurns(client, server replay.TCPStreamTimeline, clientEnd, serverEnd int) ([]Turn, error) {
	ftp := adapters.FTP{}
	var turns []Turn
	for _, half := range []struct {
		direction replay.Direction
		timeline  replay.TCPStreamTimeline
		end       int
	}{{replay.ClientToServer, client, clientEnd}, {replay.ServerToClient, server, serverEnd}} {
		if half.end == 0 {
			continue
		}
		decoded, err := ftp.Decode(half.direction, half.timeline.Data[:half.end])
		if err != nil {
			return nil, err
		}
		offset := 0
		for _, message := range decoded {
			end := offset + len(message.Raw)
			point, ok := half.timeline.CompletionPoint(offset, end)
			if !ok {
				return nil, fmt.Errorf("ftpreplay: no capture point for control bytes %d..%d", offset, end)
			}
			turns = append(turns, Turn{Direction: half.direction, Message: message, CapturedAt: point})
			offset = end
		}
	}
	sortTurns(turns)
	return turns, nil
}

func sortTurns(turns []Turn) {
	sort.SliceStable(turns, func(i, j int) bool {
		if turns[i].CapturedAt.At != turns[j].CapturedAt.At {
			return turns[i].CapturedAt.At < turns[j].CapturedAt.At
		}
		return turns[i].CapturedAt.PacketIndex < turns[j].CapturedAt.PacketIndex
	})
}

func findTLSStart(data []byte, start int) int {
	for i := start; i+5 <= len(data); i++ {
		if data[i] < 20 || data[i] > 23 || data[i+1] != 3 {
			continue
		}
		n := int(data[i+3])<<8 | int(data[i+4])
		if n > 0 && i+5+n <= len(data) {
			return i
		}
	}
	return -1
}

func scriptProtectsData(turns []Turn) bool {
	for _, turn := range turns {
		if turn.Direction == replay.ClientToServer && strings.EqualFold(strings.TrimSpace(string(turn.Message.Raw)), "PROT P") {
			return true
		}
	}
	return false
}
