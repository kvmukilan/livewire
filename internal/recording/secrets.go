// Package recording owns a TLS key-exporting child during packet recording.
// It never reads a pre-existing key log from the user's environment.
package recording

import (
	"bytes"
	"fmt"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/tlsreplay"
)

// MatchSecrets validates the child log and exports only secrets for complete,
// supported ClientHellos actually present in the recorded TCP streams. It does
// not imply that every conversation or application protocol is replayable.
func MatchSecrets(capture *pcapio.Capture, data []byte) ([]byte, int, error) {
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("application exported no TLS secrets; use an application that supports SSLKEYLOGFILE (or an explicit key-export integration)")
	}
	if len(data) > pcapio.MaxTLSKeyLogBytes {
		return nil, 0, fmt.Errorf("TLS key export exceeds the 1 MiB limit")
	}
	keys, err := tlsreplay.ParseKeyLogStrict(data)
	if err != nil {
		return nil, 0, err
	}
	hashes := map[string]bool{}
	trace := replay.ExtractTrace(capture.Records, replay.ExtractOptions{})
	for _, session := range trace.Sessions {
		if session.Transport != replay.TransportTCP {
			continue
		}
		client, _, err := replay.TCPPayloadStreams(session)
		if err != nil {
			continue
		}
		// Explicit FTPS changes to TLS immediately after the complete AUTH TLS
		// command. Never search arbitrary payload bytes for a supposed hello.
		if end := bytes.Index(bytes.ToUpper(client), []byte("AUTH TLS\r\n")); end >= 0 && (end == 0 || bytes.HasSuffix(client[:end], []byte("\r\n"))) {
			client = client[end+len("AUTH TLS\r\n"):]
		}
		hello, err := tlsreplay.ParseClientHello(client)
		if err == nil {
			hashes[hello.RandomSHA256] = true
		}
	}
	matched, count := keys.FilterClientRandoms(hashes)
	if count == 0 {
		return nil, 0, fmt.Errorf("no exported secrets match a complete supported captured TLS ClientHello; check the interface and record from connection start")
	}
	return matched, count, nil
}
