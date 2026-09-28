package ftpreplay

import (
	"fmt"

	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/tlsreplay"
)

// PrepareDataSessions decrypts captured FTPS data offline before an upload can
// be prepared or a download compared. It preserves session identity and never
// mutates the evidence trace. Missing keys or incomplete TLS are blockers.
func PrepareDataSessions(control *replay.Session, script Script, sessions []*replay.Session, keys *tlsreplay.KeyLog) ([]*replay.Session, error) {
	settings, err := transferSettings(script.Turns)
	if err != nil {
		return nil, err
	}
	if control == nil || len(settings) != len(sessions) {
		return nil, fmt.Errorf("ftpreplay: control session and one protection setting per mapped transfer are required")
	}
	prepared := make([]*replay.Session, 0, len(sessions))
	for i, session := range sessions {
		client, server, err := replay.TCPPayloadTimelines(session)
		if err != nil {
			return nil, err
		}
		if !settings[i].protected {
			// Clear FTP data can contain arbitrary bytes, including TLS-looking
			// prefixes. Only accepted control-channel PROT replies set policy.
			prepared = append(prepared, session)
			continue
		}
		if keys == nil {
			return nil, fmt.Errorf("ftpreplay: encrypted data session %s requires its matching NSS key log", session.ID)
		}
		// In active FTP the server initiates TCP, but the control client is
		// still the TLS client. TLS roles must follow FTP negotiation, not SYN.
		ftpClientIsTCPClient := dataFTPClientIsTCPClient(control, session, settings[i].active)
		if !ftpClientIsTCPClient {
			client, server = server, client
		}
		messages, err := tlsreplay.NewDecryptor(keys).DecryptFlowTimed(client.Data, server.Data, client.CompletionPoint, server.CompletionPoint)
		if err != nil {
			return nil, fmt.Errorf("ftpreplay: decrypt data session %s: %w", session.ID, err)
		}
		copy := *session
		copy.Events = nil
		for _, message := range tlsreplay.ConversationOrder(messages) {
			direction := replay.ClientToServer
			if message.Role == tlsreplay.FromServer {
				direction = replay.ServerToClient
			}
			if !ftpClientIsTCPClient {
				if direction == replay.ClientToServer {
					direction = replay.ServerToClient
				} else {
					direction = replay.ClientToServer
				}
			}
			copy.Events = append(copy.Events, replay.Event{Direction: direction, At: message.CapturedAt, PacketIndex: message.CapturedPacket, Payload: append([]byte(nil), message.Data...)})
		}
		prepared = append(prepared, &copy)
	}
	return prepared, nil
}
