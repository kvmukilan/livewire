package tlsreplay

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
)

// The TLS key-derivation functions the decryptor needs, on stdlib crypto/hmac
// only (no golang.org/x/crypto/hkdf): TLS 1.2 PRF and TLS 1.3 HKDF-Expand-Label.

// pHash implements P_hash(secret, seed) for the TLS 1.2 PRF (RFC 5246 §5).
func pHash(newHash func() hash.Hash, secret, seed []byte, length int) []byte {
	out := make([]byte, 0, length)
	// A(0) = seed; A(i) = HMAC(secret, A(i-1)).
	a := seed
	for len(out) < length {
		h := hmac.New(newHash, secret)
		h.Write(a)
		a = h.Sum(nil)

		h = hmac.New(newHash, secret)
		h.Write(a)
		h.Write(seed)
		out = append(out, h.Sum(nil)...)
	}
	return out[:length]
}

// prf12 is the TLS 1.2 PRF: P_hash over label||seed (RFC 5246 §5).
func prf12(newHash func() hash.Hash, secret []byte, label string, seed []byte, length int) []byte {
	ls := make([]byte, 0, len(label)+len(seed))
	ls = append(ls, label...)
	ls = append(ls, seed...)
	return pHash(newHash, secret, ls, length)
}

// hkdfExpand implements HKDF-Expand (RFC 5869 §2.3). No Extract step: keylog
// traffic secrets are already pseudo-random.
func hkdfExpand(newHash func() hash.Hash, secret, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	var t []byte
	for i := byte(1); len(out) < length; i++ {
		m := hmac.New(newHash, secret)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{i})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

// hkdfExpandLabel implements HKDF-Expand-Label (RFC 8446 §7.1):
//
//	struct { uint16 length; opaque label<7..255>; opaque context<0..255> }
//	with label prefixed by "tls13 ".
func hkdfExpandLabel(newHash func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 2+1+len(full)+1+len(context))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	return hkdfExpand(newHash, secret, info, length)
}

// hashForSuite returns the suite's PRF/HKDF hash constructor and size.
func hashForSuite(sha384 bool) (func() hash.Hash, int) {
	if sha384 {
		return sha512.New384, sha512.Size384
	}
	return sha256.New, sha256.Size
}
