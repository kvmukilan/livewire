package replay

import (
	"github.com/kvmukilan/livewire/internal/dissect"
)

// MarkIntrinsicBlockers records capture properties that cannot be adapted from
// packet bytes alone. Callers may clear a blocker only after validating the
// corresponding key log, credentials, or purpose-built adapter input.
func MarkIntrinsicBlockers(t *Trace) {
	for _, s := range t.Sessions {
		if s.Transport != TransportTCP {
			continue
		}
		client, server, streamErr := TCPPayloadStreams(s)
		if streamErr != nil {
			client, server = nil, nil
			for _, e := range s.Events {
				if e.Direction == ClientToServer {
					client = append(client, e.Payload...)
				} else if e.Direction == ServerToClient {
					server = append(server, e.Payload...)
				}
			}
		}
		switch {
		case dissect.DetectSSH(client):
			s.Blockers = appendUnique(s.Blockers, "SSH ciphertext requires supplied credentials and a command script; captured ciphertext is not replayable")
		case dissect.DetectTLS(client).IsTLS:
			s.Blockers = appendUnique(s.Blockers, "TLS requires a matching key log to recover plaintext before a fresh authenticated connection can be created")
		}
		for _, stream := range [][]byte{client, server} {
			if frames, _, err := dissect.ParseDNP3Stream(stream); err == nil {
				for _, frame := range frames {
					if frame.UsesSecureAuth() {
						s.Blockers = appendUnique(s.Blockers, "DNP3 Secure Authentication contains fresh challenge state and requires a security-aware adapter")
						break
					}
				}
			}
		}
	}
}

func appendUnique(in []string, value string) []string {
	for _, existing := range in {
		if existing == value {
			return in
		}
	}
	return append(in, value)
}
