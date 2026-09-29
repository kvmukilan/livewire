package replay

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
)

// FingerprintLength is the number of hex characters in a session fingerprint.
// Twelve characters (48 bits) keep it short enough to type while making an
// accidental collision inside one capture vanishingly unlikely.
const FingerprintLength = 12

// Fingerprint identifies a session by what was exchanged rather than by its
// position in the file. Session IDs such as tcp-0 are renumbered whenever a
// capture is trimmed or merged; the fingerprint of an exchange is the same in
// every capture that contains it, so a selection made from one inspection
// still names the same exchange after the file changes. It covers the
// transport, the server port, and every payload byte in order with its
// direction, and deliberately ignores addresses, client ports, and timing,
// which a rewrite or a re-recording legitimately changes.
func (s *Session) Fingerprint() string {
	if s == nil {
		return ""
	}
	return fingerprintOf(s.Transport, s.Server.Port, s.Events)
}

func fingerprintOf(transport Transport, serverPort uint16, events []Event) string {
	h := sha256.New()
	h.Write([]byte(transport))
	h.Write([]byte{0})
	h.Write(binary.BigEndian.AppendUint16(nil, serverPort))
	for _, e := range events {
		if len(e.Payload) == 0 {
			continue
		}
		h.Write([]byte{byte(e.Direction)})
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(e.Payload))))
		h.Write(e.Payload)
	}
	return hex.EncodeToString(h.Sum(nil))[:FingerprintLength]
}

// LooksLikeFingerprint reports whether a session selector is a fingerprint or
// a fingerprint prefix rather than a session ID. Session IDs always contain a
// transport name and a dash; fingerprints are lowercase hex only.
func LooksLikeFingerprint(selector string) bool {
	if len(selector) < 4 || len(selector) > FingerprintLength {
		return false
	}
	return strings.Trim(selector, "0123456789abcdef") == ""
}
