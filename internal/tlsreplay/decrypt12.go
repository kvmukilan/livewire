package tlsreplay

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- HMAC-SHA1 is what the captured TLS 1.2 CBC suites negotiated; nothing new is protected with it.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
)

// extEncryptThenMAC is the RFC 7366 extension. When the ServerHello echoes it,
// CBC records carry the MAC over the ciphertext instead of inside it.
const extEncryptThenMAC = 0x0016

// recordOpener removes the protection of one TLS 1.2 record of one direction.
type recordOpener interface {
	open(seq uint64, rec record) ([]byte, error)
}

func (d *Decryptor) decrypt12(c2s, s2c, clientRandom []byte, suite uint16, sp suiteParams, newHash func() hash.Hash, clientCompletion, serverCompletion RecordCompletion) ([]AppMessage, error) {
	master, ok := d.kl.Secret(hex.EncodeToString(clientRandom), "CLIENT_RANDOM")
	if !ok || len(master) != 48 {
		return nil, fmt.Errorf("tlsreplay: TLS 1.2 needs a 48-byte CLIENT_RANDOM master secret in the keylog")
	}
	hello, err := firstHandshake(s2c, 2)
	if err != nil {
		return nil, err
	}
	if len(hello) < 2+32 {
		return nil, fmt.Errorf("tlsreplay: ServerHello too short for random")
	}
	// TLS 1.0 and 1.1 derive keys with a different PRF and chain CBC IVs.
	if version := binary.BigEndian.Uint16(hello[:2]); version != 0x0303 {
		return nil, fmt.Errorf("tlsreplay: negotiated protocol version 0x%04x is not supported; only TLS 1.2 and 1.3 can be decrypted", version)
	}
	serverRandom := hello[2 : 2+32]
	encryptThenMAC := sp.mac != macNone && serverHelloHasExtension(hello, extEncryptThenMAC)

	// key_block = PRF(master, "key expansion", server_random + client_random),
	// cut as client MAC, server MAC, client key, server key, client IV, server IV.
	macLen, ivLen := 0, 4
	var newMAC func() hash.Hash
	switch {
	case sp.mac != macNone:
		newMAC, macLen = cbcMACHash(sp.mac)
		ivLen = 0 // TLS 1.2 CBC records carry an explicit IV
	case sp.chacha:
		ivLen = 12
	}
	seed := append(append([]byte{}, serverRandom...), clientRandom...)
	kb := prf12(newHash, master, "key expansion", seed, 2*(macLen+sp.keyLen+ivLen))
	take := func(n int) []byte {
		part := kb[:n]
		kb = kb[n:]
		return part
	}
	cliMAC, srvMAC := take(macLen), take(macLen)
	cliKey, srvKey := take(sp.keyLen), take(sp.keyLen)
	cliIV, srvIV := take(ivLen), take(ivLen)

	opener := func(key, iv, macKey []byte) (recordOpener, error) {
		switch {
		case sp.mac != macNone:
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cbcOpener{block: block, newMAC: newMAC, macKey: macKey, macLen: macLen, encryptThenMAC: encryptThenMAC}, nil
		case sp.chacha:
			aead, err := chacha20poly1305.New(key)
			return chachaOpener{aead: aead, iv: iv}, err
		default:
			aead, err := newGCM(key)
			return gcmOpener{aead: aead, implicitIV: iv}, err
		}
	}
	cliOpener, err := opener(cliKey, cliIV, cliMAC)
	if err != nil {
		return nil, err
	}
	srvOpener, err := opener(srvKey, srvIV, srvMAC)
	if err != nil {
		return nil, err
	}
	cli, err := decrypt12Dir(c2s, cliOpener, FromClient, clientCompletion)
	if err != nil {
		return nil, err
	}
	srv, err := decrypt12Dir(s2c, srvOpener, FromServer, serverCompletion)
	if err != nil {
		return nil, err
	}
	return append(cli, srv...), nil
}

// decrypt12Dir decrypts one direction of a TLS 1.2 stream. The sequence number
// starts at 0 after ChangeCipherSpec; application data records are returned,
// the encrypted Finished and alerts are authenticated and dropped.
func decrypt12Dir(stream []byte, opener recordOpener, role AppRole, completion RecordCompletion) ([]AppMessage, error) {
	var out []AppMessage
	var seq uint64
	encrypting := false
	records, err := parseRecords(stream)
	if err != nil {
		return nil, err
	}
	for _, rec := range records {
		if rec.typ == 20 && !encrypting { // ChangeCipherSpec: everything after is encrypted
			encrypting = true
			continue
		}
		if !encrypting {
			continue // plaintext handshake (ClientHello/ServerHello/...)
		}
		pt, err := opener.open(seq, rec)
		if err != nil {
			return nil, fmt.Errorf("tlsreplay: TLS 1.2 record %d: %w", seq, err)
		}
		seq++
		if rec.typ == 23 && len(pt) > 0 {
			message := AppMessage{Role: role, Data: pt}
			if completion != nil {
				if point, ok := completion(rec.start, rec.end); ok {
					message.CapturedAt, message.CapturedPacket, message.HasCaptureTime = point.At, point.PacketIndex, true
				}
			}
			out = append(out, message)
		}
	}
	return out, nil
}

// aad12 is the TLS 1.2 additional data and MAC header:
// seq_num || type || version || length.
func aad12(seq uint64, rec record, length int) []byte {
	aad := make([]byte, 13)
	binary.BigEndian.PutUint64(aad[0:8], seq)
	aad[8] = rec.typ
	binary.BigEndian.PutUint16(aad[9:11], rec.ver)
	binary.BigEndian.PutUint16(aad[11:13], uint16(length))
	return aad
}

// gcmOpener handles AES-GCM: a 4-byte implicit IV plus an 8-byte explicit nonce
// at the start of every record (RFC 5288).
type gcmOpener struct {
	aead       cipher.AEAD
	implicitIV []byte
}

func (o gcmOpener) open(seq uint64, rec record) ([]byte, error) {
	if len(rec.body) < 8+o.aead.Overhead() {
		return nil, fmt.Errorf("short GCM record")
	}
	nonce := append(append([]byte{}, o.implicitIV...), rec.body[:8]...)
	ct := rec.body[8:]
	pt, err := o.aead.Open(nil, nonce, ct, aad12(seq, rec, len(ct)-o.aead.Overhead()))
	if err != nil {
		return nil, fmt.Errorf("auth failed: %w", err)
	}
	return pt, nil
}

// chachaOpener handles ChaCha20-Poly1305: no explicit nonce; the 12-byte write
// IV is XORed with the sequence number (RFC 7905).
type chachaOpener struct {
	aead cipher.AEAD
	iv   []byte
}

func (o chachaOpener) open(seq uint64, rec record) ([]byte, error) {
	if len(rec.body) < o.aead.Overhead() {
		return nil, fmt.Errorf("short ChaCha20-Poly1305 record")
	}
	pt, err := o.aead.Open(nil, tls13Nonce(o.iv, seq), rec.body, aad12(seq, rec, len(rec.body)-o.aead.Overhead()))
	if err != nil {
		return nil, fmt.Errorf("auth failed: %w", err)
	}
	return pt, nil
}

// cbcOpener handles AES-CBC with an explicit per-record IV, in either
// MAC-then-encrypt (RFC 5246) or encrypt-then-MAC (RFC 7366) layout. This is
// offline decryption of a capture the operator holds the secrets for, so
// timing is not a concern, but a record that fails its MAC or padding check is
// never returned.
type cbcOpener struct {
	block          cipher.Block
	newMAC         func() hash.Hash
	macKey         []byte
	macLen         int
	encryptThenMAC bool
}

func (o cbcOpener) open(seq uint64, rec record) ([]byte, error) {
	size := o.block.BlockSize()
	body := rec.body
	if o.encryptThenMAC {
		if len(body) < o.macLen {
			return nil, fmt.Errorf("short CBC record")
		}
		protected, mac := body[:len(body)-o.macLen], body[len(body)-o.macLen:]
		if !o.verify(seq, rec, protected, mac) {
			return nil, fmt.Errorf("auth failed: bad record MAC")
		}
		body = protected
	}
	if len(body) < 2*size || len(body)%size != 0 {
		return nil, fmt.Errorf("CBC record is not a whole number of blocks")
	}
	pt := make([]byte, len(body)-size)
	cipher.NewCBCDecrypter(o.block, body[:size]).CryptBlocks(pt, body[size:])
	pad := int(pt[len(pt)-1])
	if pad+1 > len(pt) {
		return nil, fmt.Errorf("auth failed: bad CBC padding")
	}
	for _, b := range pt[len(pt)-pad-1:] {
		if int(b) != pad {
			return nil, fmt.Errorf("auth failed: bad CBC padding")
		}
	}
	pt = pt[:len(pt)-pad-1]
	if o.encryptThenMAC {
		return pt, nil
	}
	if len(pt) < o.macLen {
		return nil, fmt.Errorf("auth failed: CBC record shorter than its MAC")
	}
	content, mac := pt[:len(pt)-o.macLen], pt[len(pt)-o.macLen:]
	if !o.verify(seq, rec, content, mac) {
		return nil, fmt.Errorf("auth failed: bad record MAC")
	}
	return content, nil
}

func (o cbcOpener) verify(seq uint64, rec record, data, mac []byte) bool {
	h := hmac.New(o.newMAC, o.macKey)
	h.Write(aad12(seq, rec, len(data)))
	h.Write(data)
	return hmac.Equal(h.Sum(nil), mac)
}

func cbcMACHash(mac cbcMAC) (func() hash.Hash, int) {
	switch mac {
	case macSHA256:
		return sha256.New, sha256.Size
	case macSHA384:
		return sha512.New384, sha512.Size384
	default:
		return sha1.New, sha1.Size
	}
}

// serverHelloHasExtension reports whether a ServerHello body, already
// validated by serverHelloParams, carries the given extension.
func serverHelloHasExtension(hello []byte, want uint16) bool {
	p := 2 + 32
	if p >= len(hello) {
		return false
	}
	p += 1 + int(hello[p]) + 2 + 1 // session id, cipher suite, compression
	if p+2 > len(hello) {
		return false
	}
	end := p + 2 + int(binary.BigEndian.Uint16(hello[p:p+2]))
	p += 2
	if end > len(hello) {
		return false
	}
	for p+4 <= end {
		if binary.BigEndian.Uint16(hello[p:p+2]) == want {
			return true
		}
		p += 4 + int(binary.BigEndian.Uint16(hello[p+2:p+4]))
	}
	return false
}
