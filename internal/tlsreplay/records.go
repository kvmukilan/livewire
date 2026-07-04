package tlsreplay

import (
	"encoding/binary"
	"fmt"
)

// record is one complete TLS record split from a reassembled stream.
type record struct {
	typ  uint8
	ver  uint16
	body []byte
}

// splitRecords walks a reassembled TLS byte stream into complete records. A
// trailing partial record is dropped (the decryptor works on full captures).
func splitRecords(stream []byte) []record {
	var recs []record
	for off := 0; off+5 <= len(stream); {
		typ := stream[off]
		ver := binary.BigEndian.Uint16(stream[off+1 : off+3])
		n := int(binary.BigEndian.Uint16(stream[off+3 : off+5]))
		if off+5+n > len(stream) {
			break
		}
		recs = append(recs, record{typ: typ, ver: ver, body: stream[off+5 : off+5+n]})
		off += 5 + n
	}
	return recs
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

// firstHandshake returns the body of the first handshake message of wantType
// from a stream's opening (plaintext) record.
func firstHandshake(stream []byte, wantType uint8) ([]byte, error) {
	recs := splitRecords(stream)
	if len(recs) == 0 || recs[0].typ != 22 {
		return nil, fmt.Errorf("tlsreplay: stream does not begin with a TLS handshake record")
	}
	hs := recs[0].body
	if len(hs) < 4 || hs[0] != wantType {
		return nil, fmt.Errorf("tlsreplay: expected handshake type %d, got %d", wantType, safeByte(hs))
	}
	length := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if 4+length > len(hs) {
		length = len(hs) - 4
	}
	return hs[4 : 4+length], nil
}

func safeByte(b []byte) int {
	if len(b) == 0 {
		return -1
	}
	return int(b[0])
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
			end = len(b)
		}
		for p+4 <= end {
			et := binary.BigEndian.Uint16(b[p : p+2])
			el := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
			p += 4
			if p+el > end {
				break
			}
			if et == 0x002b && el >= 2 { // supported_versions
				if binary.BigEndian.Uint16(b[p:p+2]) == 0x0304 {
					isTLS13 = true
				}
			}
			p += el
		}
	}
	return suite, isTLS13, nil
}
