package tlsreplay

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"sort"

	"github.com/kvmukilan/livewire/internal/replay"
	"golang.org/x/crypto/chacha20poly1305"
)

// Recovers plaintext from captured TLS records + an SSLKEYLOGFILE.
// Handles TLS 1.2 with AES-GCM, ChaCha20-Poly1305 and AES-CBC (MAC-then-encrypt
// or encrypt-then-MAC), and TLS 1.3 with AES-GCM or ChaCha20-Poly1305,
// following KeyUpdate. The key exchange does not matter: the key log already
// carries the master or traffic secrets.

// tlsVersion tags the record layer in use.
type tlsVersion uint8

const (
	verTLS12 tlsVersion = iota
	verTLS13
)

// cbcMAC names the HMAC of a TLS 1.2 CBC suite; zero means an AEAD suite.
type cbcMAC uint8

const (
	macNone cbcMAC = iota
	macSHA1
	macSHA256
	macSHA384
)

// suiteParams describes the record protection of a negotiated cipher suite.
// sha384 selects the PRF/HKDF hash; mac is set only for TLS 1.2 CBC suites.
type suiteParams struct {
	keyLen  int
	sha384  bool
	isTLS13 bool
	chacha  bool
	mac     cbcMAC
}

// Suites we understand.
var cipherSuites = map[uint16]suiteParams{
	// TLS 1.2 AES-GCM (ECDHE, DHE and static-RSA key exchange).
	0xC02F: {keyLen: 16},               // ECDHE_RSA_AES_128_GCM_SHA256
	0xC02B: {keyLen: 16},               // ECDHE_ECDSA_AES_128_GCM_SHA256
	0xC030: {keyLen: 32, sha384: true}, // ECDHE_RSA_AES_256_GCM_SHA384
	0xC02C: {keyLen: 32, sha384: true}, // ECDHE_ECDSA_AES_256_GCM_SHA384
	0x009C: {keyLen: 16},               // RSA_AES_128_GCM_SHA256
	0x009D: {keyLen: 32, sha384: true}, // RSA_AES_256_GCM_SHA384
	0x009E: {keyLen: 16},               // DHE_RSA_AES_128_GCM_SHA256
	0x009F: {keyLen: 32, sha384: true}, // DHE_RSA_AES_256_GCM_SHA384
	// TLS 1.2 ChaCha20-Poly1305 (RFC 7905).
	0xCCA8: {keyLen: 32, chacha: true}, // ECDHE_RSA_CHACHA20_POLY1305_SHA256
	0xCCA9: {keyLen: 32, chacha: true}, // ECDHE_ECDSA_CHACHA20_POLY1305_SHA256
	0xCCAA: {keyLen: 32, chacha: true}, // DHE_RSA_CHACHA20_POLY1305_SHA256
	// TLS 1.2 AES-CBC with HMAC.
	0x002F: {keyLen: 16, mac: macSHA1},                 // RSA_AES_128_CBC_SHA
	0x0035: {keyLen: 32, mac: macSHA1},                 // RSA_AES_256_CBC_SHA
	0x003C: {keyLen: 16, mac: macSHA256},               // RSA_AES_128_CBC_SHA256
	0x003D: {keyLen: 32, mac: macSHA256},               // RSA_AES_256_CBC_SHA256
	0x0033: {keyLen: 16, mac: macSHA1},                 // DHE_RSA_AES_128_CBC_SHA
	0x0039: {keyLen: 32, mac: macSHA1},                 // DHE_RSA_AES_256_CBC_SHA
	0x0067: {keyLen: 16, mac: macSHA256},               // DHE_RSA_AES_128_CBC_SHA256
	0x006B: {keyLen: 32, mac: macSHA256},               // DHE_RSA_AES_256_CBC_SHA256
	0xC009: {keyLen: 16, mac: macSHA1},                 // ECDHE_ECDSA_AES_128_CBC_SHA
	0xC00A: {keyLen: 32, mac: macSHA1},                 // ECDHE_ECDSA_AES_256_CBC_SHA
	0xC013: {keyLen: 16, mac: macSHA1},                 // ECDHE_RSA_AES_128_CBC_SHA
	0xC014: {keyLen: 32, mac: macSHA1},                 // ECDHE_RSA_AES_256_CBC_SHA
	0xC023: {keyLen: 16, mac: macSHA256},               // ECDHE_ECDSA_AES_128_CBC_SHA256
	0xC027: {keyLen: 16, mac: macSHA256},               // ECDHE_RSA_AES_128_CBC_SHA256
	0xC024: {keyLen: 32, sha384: true, mac: macSHA384}, // ECDHE_ECDSA_AES_256_CBC_SHA384
	0xC028: {keyLen: 32, sha384: true, mac: macSHA384}, // ECDHE_RSA_AES_256_CBC_SHA384
	// TLS 1.3.
	0x1301: {keyLen: 16, isTLS13: true},               // AES_128_GCM_SHA256
	0x1302: {keyLen: 32, sha384: true, isTLS13: true}, // AES_256_GCM_SHA384
	0x1303: {keyLen: 32, isTLS13: true, chacha: true}, // CHACHA20_POLY1305_SHA256
}

// Decryptor recovers plaintext from captured TLS records using a keylog.
type Decryptor struct {
	kl *KeyLog
}

// RecordCompletion returns the capture time at which the TLS record byte range
// [start,end) became complete in its reassembled TCP direction.
type RecordCompletion func(start, end int) (replay.CapturePoint, bool)

// NewDecryptor builds a decryptor over the parsed keylog.
func NewDecryptor(kl *KeyLog) *Decryptor { return &Decryptor{kl: kl} }

// DecryptFlow recovers the application messages from one connection's two
// reassembled record streams. Messages come back per direction, in order.
func (d *Decryptor) DecryptFlow(c2s, s2c []byte) ([]AppMessage, error) {
	return d.decryptFlow(c2s, s2c, nil, nil, false)
}

// DecryptFlowTimed decrypts both directions and restores their real capture
// chronology using TCP byte-range completion times. Unlike the legacy helper,
// it never guesses by alternation when chronology is unavailable.
func (d *Decryptor) DecryptFlowTimed(c2s, s2c []byte, clientCompletion, serverCompletion RecordCompletion) ([]AppMessage, error) {
	if clientCompletion == nil || serverCompletion == nil {
		return nil, fmt.Errorf("tlsreplay: both TCP record timelines are required")
	}
	return d.decryptFlow(c2s, s2c, clientCompletion, serverCompletion, true)
}

func (d *Decryptor) decryptFlow(c2s, s2c []byte, clientCompletion, serverCompletion RecordCompletion, timed bool) ([]AppMessage, error) {
	clientRandom, suite, ver, err := handshakeParams(c2s, s2c)
	if err != nil {
		return nil, err
	}
	sp, ok := cipherSuites[suite]
	if !ok {
		return nil, fmt.Errorf("tlsreplay: unsupported cipher suite 0x%04x", suite)
	}
	crHex := hex.EncodeToString(clientRandom)
	if !d.kl.Has(crHex) {
		return nil, fmt.Errorf("tlsreplay: no keylog entry for client random %s; cannot decrypt", crHex)
	}

	newHash, _ := hashForSuite(sp.sha384)
	var out []AppMessage
	if ver == verTLS13 {
		cli, err := d.decrypt13(c2s, crHex, "CLIENT", sp, newHash, FromClient, clientCompletion)
		if err != nil {
			return nil, err
		}
		srv, err := d.decrypt13(s2c, crHex, "SERVER", sp, newHash, FromServer, serverCompletion)
		if err != nil {
			return nil, err
		}
		out = append(append(out, cli...), srv...)
	} else {
		msgs, err := d.decrypt12(c2s, s2c, clientRandom, suite, sp, newHash, clientCompletion, serverCompletion)
		if err != nil {
			return nil, err
		}
		out = msgs
	}
	if timed {
		for _, message := range out {
			if !message.HasCaptureTime {
				return nil, fmt.Errorf("tlsreplay: capture chronology is incomplete for a decrypted application record")
			}
		}
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].CapturedAt != out[j].CapturedAt {
				return out[i].CapturedAt < out[j].CapturedAt
			}
			return out[i].CapturedPacket < out[j].CapturedPacket
		})
	}
	return out, nil
}

// --- TLS 1.3 ---

func (d *Decryptor) decrypt13(stream []byte, crHex, side string, sp suiteParams, newHash func() hash.Hash, role AppRole, completion RecordCompletion) ([]AppMessage, error) {
	appSecret, ok := d.kl.Secret(crHex, side+"_TRAFFIC_SECRET_0")
	if !ok {
		return nil, fmt.Errorf("tlsreplay: keylog missing %s_TRAFFIC_SECRET_0", side)
	}
	hsSecret, _ := d.kl.Secret(crHex, side+"_HANDSHAKE_TRAFFIC_SECRET")

	appAEAD, appIV, err := tls13KeyIV(appSecret, sp, newHash)
	if err != nil {
		return nil, err
	}
	var hsAEAD cipher.AEAD
	var hsIV []byte
	if hsSecret != nil {
		hsAEAD, hsIV, err = tls13KeyIV(hsSecret, sp, newHash)
		if err != nil {
			return nil, err
		}
	}

	_, hashLen := hashForSuite(sp.sha384)
	var out []AppMessage
	var appCtr, hsCtr uint64
	records, err := parseRecords(stream)
	if err != nil {
		return nil, err
	}
	for _, rec := range records {
		if rec.typ != 23 { // pre-encryption plaintext handshake records
			continue
		}
		// Try the app secret first; a wrong key fails GCM auth, so trial is safe.
		// Handshake-phase records fall through to the hs secret.
		if pt, innerType, ok := tryOpen13(appAEAD, appIV, appCtr, rec); ok {
			appCtr++
			if innerType == 22 && isKeyUpdate(pt) {
				// RFC 8446 section 7.2: the sender's next record uses the next
				// generation of its application traffic secret, from sequence 0.
				appSecret = hkdfExpandLabel(newHash, appSecret, "traffic upd", nil, hashLen)
				if appAEAD, appIV, err = tls13KeyIV(appSecret, sp, newHash); err != nil {
					return nil, err
				}
				appCtr = 0
				continue
			}
			if innerType == 23 && len(pt) > 0 {
				message := AppMessage{Role: role, Data: pt}
				if completion != nil {
					if point, ok := completion(rec.start, rec.end); ok {
						message.CapturedAt, message.CapturedPacket, message.HasCaptureTime = point.At, point.PacketIndex, true
					}
				}
				out = append(out, message)
			}
			continue
		}
		if hsAEAD != nil {
			if _, _, ok := tryOpen13(hsAEAD, hsIV, hsCtr, rec); ok {
				hsCtr++ // encrypted handshake (EncryptedExtensions/Cert/Finished): skip
				continue
			}
		}
		return nil, fmt.Errorf("tlsreplay: TLS 1.3 %s record failed to decrypt under both handshake and application secrets", side)
	}
	return out, nil
}

// isKeyUpdate reports whether a decrypted post-handshake record is exactly one
// KeyUpdate message (type 24, one-byte request_update body).
func isKeyUpdate(handshake []byte) bool {
	return len(handshake) == 5 && handshake[0] == 24 && handshake[1] == 0 && handshake[2] == 0 && handshake[3] == 1 && handshake[4] <= 1
}

// tryOpen13 opens one TLS 1.3 record at seq, returning the inner plaintext, its
// content type, and whether auth succeeded.
func tryOpen13(aead cipher.AEAD, iv []byte, seq uint64, rec record) ([]byte, uint8, bool) {
	nonce := tls13Nonce(iv, seq)
	aad := []byte{rec.typ, byte(rec.ver >> 8), byte(rec.ver), byte(len(rec.body) >> 8), byte(len(rec.body))}
	inner, err := aead.Open(nil, nonce, rec.body, aad)
	if err != nil {
		return nil, 0, false
	}
	// Inner = content || content_type(1) || zero padding. Strip trailing zeros.
	i := len(inner) - 1
	for i >= 0 && inner[i] == 0 {
		i--
	}
	if i < 0 {
		return nil, 0, true // all padding
	}
	return inner[:i], inner[i], true
}

func tls13KeyIV(secret []byte, sp suiteParams, newHash func() hash.Hash) (cipher.AEAD, []byte, error) {
	key := hkdfExpandLabel(newHash, secret, "key", nil, sp.keyLen)
	iv := hkdfExpandLabel(newHash, secret, "iv", nil, 12)
	if sp.chacha {
		aead, err := chacha20poly1305.New(key)
		return aead, iv, err
	}
	aead, err := newGCM(key)
	return aead, iv, err
}

// tls13Nonce XORs the seq number into the low 8 bytes of the write IV (RFC 8446 §5.3).
func tls13Nonce(iv []byte, seq uint64) []byte {
	nonce := append([]byte{}, iv...)
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-8+i] ^= s[i]
	}
	return nonce
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
