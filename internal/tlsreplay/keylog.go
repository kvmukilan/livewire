// Package tlsreplay re-terminates captured TLS sessions: rather than replaying
// ciphertext (which no fresh handshake would accept), it opens a new TLS
// connection to the device and replays the decrypted application-layer messages.
//
// This file parses an SSLKEYLOGFILE; without the session keys the captured
// application data can't be decrypted.
package tlsreplay

import (
	"bufio"
	"encoding/hex"
	"io"
	"strings"
)

// KeyLog holds NSS-format key material indexed by client random. TLS 1.2 uses
// CLIENT_RANDOM (the master secret); TLS 1.3 uses the *_TRAFFIC_SECRET labels.
type KeyLog struct {
	// entries maps client_random (lowercase hex) -> label -> secret bytes.
	entries map[string]map[string][]byte
}

// ParseKeyLog reads NSS SSLKEYLOGFILE lines, skipping comments and malformed lines.
func ParseKeyLog(r io.Reader) (*KeyLog, error) {
	kl := &KeyLog{entries: map[string]map[string][]byte{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		label, cr, secretHex := f[0], strings.ToLower(f[1]), f[2]
		secret, err := hex.DecodeString(secretHex)
		if err != nil {
			continue
		}
		if _, err := hex.DecodeString(cr); err != nil {
			continue
		}
		m := kl.entries[cr]
		if m == nil {
			m = map[string][]byte{}
			kl.entries[cr] = m
		}
		m[label] = secret
	}
	return kl, sc.Err()
}

// Secret returns the secret for a client random and label, if present.
func (kl *KeyLog) Secret(clientRandomHex, label string) ([]byte, bool) {
	m := kl.entries[strings.ToLower(clientRandomHex)]
	if m == nil {
		return nil, false
	}
	s, ok := m[label]
	return s, ok
}

// Has reports whether any key material exists for a client random.
func (kl *KeyLog) Has(clientRandomHex string) bool {
	_, ok := kl.entries[strings.ToLower(clientRandomHex)]
	return ok
}

// Count reports how many distinct sessions the log carries keys for.
func (kl *KeyLog) Count() int { return len(kl.entries) }
