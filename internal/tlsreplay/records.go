package tlsreplay

import (
	"encoding/binary"
	"fmt"
)

// record is one complete TLS record split from a reassembled stream.
type record struct {
	typ        uint8
	ver        uint16
	body       []byte
	start, end int
}

// parseRecords walks a reassembled TLS byte stream into complete records. A
// partial header or body is an explicit error: silently discarding it could
// make an incomplete encrypted capture look replayable.
func parseRecords(stream []byte) ([]record, error) {
	var recs []record
	for off := 0; off < len(stream); {
		if len(stream)-off < 5 {
			return nil, fmt.Errorf("tlsreplay: truncated TLS record header at stream offset %d", off)
		}
		typ := stream[off]
		ver := binary.BigEndian.Uint16(stream[off+1 : off+3])
		n := int(binary.BigEndian.Uint16(stream[off+3 : off+5]))
		end := off + 5 + n
		if end > len(stream) {
			return nil, fmt.Errorf("tlsreplay: truncated TLS record body at stream offset %d: need %d byte(s), have %d", off, n, len(stream)-off-5)
		}
		recs = append(recs, record{typ: typ, ver: ver, body: stream[off+5 : end], start: off, end: end})
		off = end
	}
	return recs, nil
}

// handshakeParams pulls the client random, cipher suite, and version from the
// plaintext ClientHello and ServerHello.
func handshakeParams(c2s, s2c []byte) (clientRandom []byte, suite uint16, ver tlsVersion, err error) {
	cr, e := clientHelloRandom(c2s)
	if e != nil {
		return nil, 0, 0, e
	}
	suite, isTLS13, e := serverHelloParams(s2c)
	if e != nil {
		return nil, 0, 0, e
	}
	v := verTLS12
	if isTLS13 {
		v = verTLS13
	}
	return cr, suite, v, nil
}

// firstHandshake returns the complete first handshake message body. Handshake
// messages may span multiple TLS records, so record framing and handshake
// framing are reassembled independently and truncation is never accepted.
func firstHandshake(stream []byte, wantType uint8) ([]byte, error) {
	recs, parseErr := parseRecords(stream)
	if parseErr != nil {
		return nil, parseErr
	}
	if len(recs) == 0 || recs[0].typ != 22 {
		return nil, fmt.Errorf("tlsreplay: stream does not begin with a TLS handshake record")
	}
	const maxHandshake = 16 << 20
	var hs []byte
	for _, rec := range recs {
		if rec.typ != 22 {
			break
		}
		if len(hs)+len(rec.body) > maxHandshake+4 {
			return nil, fmt.Errorf("tlsreplay: opening handshake exceeds %d bytes", maxHandshake)
		}
		hs = append(hs, rec.body...)
		if len(hs) < 4 {
			continue
		}
		if hs[0] != wantType {
			return nil, fmt.Errorf("tlsreplay: expected handshake type %d, got %d", wantType, hs[0])
		}
		length := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		if length > maxHandshake {
			return nil, fmt.Errorf("tlsreplay: opening handshake declares %d bytes", length)
		}
		if len(hs) >= 4+length {
			return hs[4 : 4+length], nil
		}
	}
	if len(hs) < 4 {
		return nil, fmt.Errorf("tlsreplay: truncated handshake header: have %d byte(s)", len(hs))
	}
	length := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	return nil, fmt.Errorf("tlsreplay: truncated handshake body: need %d byte(s), have %d", length, len(hs)-4)
}

// clientHelloRandom returns the 32-byte client random from a ClientHello (type 1).
func clientHelloRandom(c2s []byte) ([]byte, error) {
	body, err := firstHandshake(c2s, 1)
	if err != nil {
		return nil, err
	}
	if len(body) < 2+32 {
		return nil, fmt.Errorf("tlsreplay: ClientHello too short for random")
	}
	return body[2 : 2+32], nil // client_version(2) then random(32)
}

// serverHelloRandom returns the 32-byte server random from a ServerHello (type 2).
func serverHelloRandom(s2c []byte) ([]byte, error) {
	body, err := firstHandshake(s2c, 2)
	if err != nil {
		return nil, err
	}
	if len(body) < 2+32 {
		return nil, fmt.Errorf("tlsreplay: ServerHello too short for random")
	}
	return body[2 : 2+32], nil
}

// serverHelloParams parses a ServerHello for the negotiated cipher suite and
// whether the supported_versions extension selects TLS 1.3.
func serverHelloParams(s2c []byte) (suite uint16, isTLS13 bool, err error) {
	b, err := firstHandshake(s2c, 2)
	if err != nil {
		return 0, false, err
	}
	// legacy_version(2) + random(32) + session_id
	p := 2 + 32
	if p >= len(b) {
		return 0, false, fmt.Errorf("tlsreplay: ServerHello truncated at session id")
	}
	sidLen := int(b[p])
	p += 1 + sidLen
	if p+2 > len(b) {
		return 0, false, fmt.Errorf("tlsreplay: ServerHello truncated at cipher suite")
	}
	suite = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	// compression_method(1)
	if p >= len(b) {
		return 0, false, fmt.Errorf("tlsreplay: ServerHello truncated at compression method")
	}
	p++
	// A 0x13xx suite already implies TLS 1.3; also honour supported_versions.
	if suite>>8 == 0x13 {
		isTLS13 = true
	}
	if p+2 <= len(b) {
		extLen := int(binary.BigEndian.Uint16(b[p : p+2]))
		p += 2
		end := p + extLen
		if end > len(b) {
			return 0, false, fmt.Errorf("tlsreplay: ServerHello extension block declares %d byte(s), have %d", extLen, len(b)-p)
		}
		for p < end {
			if p+4 > end {
				return 0, false, fmt.Errorf("tlsreplay: ServerHello has a truncated extension header")
			}
			et := binary.BigEndian.Uint16(b[p : p+2])
			el := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
			p += 4
			if p+el > end {
				return 0, false, fmt.Errorf("tlsreplay: ServerHello extension 0x%04x declares %d byte(s), have %d", et, el, end-p)
			}
			if et == 0x002b && el >= 2 { // supported_versions
				if binary.BigEndian.Uint16(b[p:p+2]) == 0x0304 {
					isTLS13 = true
				}
			}
			p += el
		}
		if end != len(b) {
			return 0, false, fmt.Errorf("tlsreplay: ServerHello has %d trailing byte(s) after extensions", len(b)-end)
		}
	} else if p != len(b) {
		return 0, false, fmt.Errorf("tlsreplay: ServerHello has a truncated extension length")
	}
	return suite, isTLS13, nil
}
