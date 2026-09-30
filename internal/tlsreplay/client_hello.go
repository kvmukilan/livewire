package tlsreplay

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// ClientHelloMetadata contains public negotiation inputs, never session keys,
// tickets, PSKs, or captured encrypted application data.
type ClientHelloMetadata struct {
	ServerName      string   `json:"serverName,omitempty"`
	ALPN            []string `json:"alpn,omitempty"`
	LegacyVersion   uint16   `json:"legacyVersion"`
	OfferedVersions []uint16 `json:"offeredVersions"`
	UsedVersions    []uint16 `json:"usedVersions"`
	SHA256          string   `json:"sha256"`
	RandomSHA256    string   `json:"randomSha256"`
}

const maxClientHelloBytes = 256 << 10

// ParseClientHello strictly decodes a complete opening handshake after TCP
// reassembly. Execution must not use the dissector's best-effort partial view.
func ParseClientHello(stream []byte) (*ClientHelloMetadata, error) {
	b, err := openingClientHello(stream)
	if err != nil {
		return nil, err
	}
	if len(b) > maxClientHelloBytes || len(b) < 38 {
		return nil, fmt.Errorf("TLS ClientHello size is invalid")
	}
	m := &ClientHelloMetadata{LegacyVersion: binary.BigEndian.Uint16(b[:2]), SHA256: publicHash(b), RandomSHA256: publicHash(b[2:34])}
	if m.LegacyVersion < 0x0301 || m.LegacyVersion > 0x0303 {
		return nil, fmt.Errorf("TLS ClientHello legacy version is invalid")
	}
	p := 34
	sid := int(b[p])
	p++
	if sid > 32 || p+sid+2 > len(b) {
		return nil, fmt.Errorf("TLS ClientHello session ID is malformed")
	}
	p += sid
	n := int(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2
	if n == 0 || n%2 != 0 || p+n+1 > len(b) {
		return nil, fmt.Errorf("TLS ClientHello cipher list is malformed")
	}
	p += n
	n = int(b[p])
	p++
	if n == 0 || p+n > len(b) {
		return nil, fmt.Errorf("TLS ClientHello compression list is malformed")
	}
	compression := append([]byte(nil), b[p:p+n]...)
	p += n
	seen := map[uint16]bool{}
	if p < len(b) {
		if p+2 > len(b) {
			return nil, fmt.Errorf("TLS ClientHello extension length is truncated")
		}
		n = int(binary.BigEndian.Uint16(b[p : p+2]))
		p += 2
		if p+n != len(b) {
			return nil, fmt.Errorf("TLS ClientHello extension length is invalid")
		}
		for p < len(b) {
			if p+4 > len(b) {
				return nil, fmt.Errorf("TLS ClientHello extension header is truncated")
			}
			kind := binary.BigEndian.Uint16(b[p : p+2])
			n = int(binary.BigEndian.Uint16(b[p+2 : p+4]))
			p += 4
			if p+n > len(b) || seen[kind] {
				return nil, fmt.Errorf("TLS ClientHello extension 0x%04x is truncated or duplicated", kind)
			}
			seen[kind] = true
			ext := b[p : p+n]
			p += n
			switch kind {
			case 0:
				if len(ext) < 5 || int(binary.BigEndian.Uint16(ext[:2])) != len(ext)-2 || ext[2] != 0 || int(binary.BigEndian.Uint16(ext[3:5])) != len(ext)-5 {
					return nil, fmt.Errorf("TLS ClientHello SNI is malformed")
				}
				m.ServerName = string(ext[5:])
				if !validSNI(m.ServerName) {
					return nil, fmt.Errorf("TLS ClientHello SNI is not a valid DNS name")
				}
			case 16:
				if len(ext) < 3 || len(ext) > 4096 || int(binary.BigEndian.Uint16(ext[:2])) != len(ext)-2 {
					return nil, fmt.Errorf("TLS ClientHello ALPN list is malformed or exceeds 4096 bytes")
				}
				for q := 2; q < len(ext); {
					length := int(ext[q])
					q++
					if length == 0 || q+length > len(ext) {
						return nil, fmt.Errorf("TLS ClientHello ALPN protocol is malformed")
					}
					m.ALPN = append(m.ALPN, string(ext[q:q+length]))
					q += length
				}
			case 43:
				if len(ext) < 3 || int(ext[0]) != len(ext)-1 || ext[0]%2 != 0 {
					return nil, fmt.Errorf("TLS ClientHello supported versions are malformed")
				}
				versions := map[uint16]bool{}
				for q := 1; q < len(ext); q += 2 {
					v := binary.BigEndian.Uint16(ext[q : q+2])
					if versions[v] {
						return nil, fmt.Errorf("TLS ClientHello repeats a supported version")
					}
					versions[v] = true
					m.OfferedVersions = append(m.OfferedVersions, v)
				}
			case 0xfe0d:
				return nil, fmt.Errorf("captured ECH ClientHello cannot establish the hidden server identity; a keylog-free handshake is unsupported")
			}
		}
	}
	if !seen[43] {
		m.OfferedVersions = []uint16{m.LegacyVersion}
	}
	nullCompression := false
	for _, value := range compression {
		nullCompression = nullCompression || value == 0
	}
	if !nullCompression {
		return nil, fmt.Errorf("TLS ClientHello does not offer null compression")
	}
	for _, version := range m.OfferedVersions {
		if version == tls.VersionTLS13 && (m.LegacyVersion != tls.VersionTLS12 || len(compression) != 1 || compression[0] != 0) {
			return nil, fmt.Errorf("TLS 1.3 ClientHello legacy version or compression is invalid")
		}
	}
	for _, v := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		for _, offered := range m.OfferedVersions {
			if v == offered || !seen[43] && v <= offered && v <= tls.VersionTLS12 {
				m.UsedVersions = append(m.UsedVersions, v)
				break
			}
		}
	}
	if len(m.UsedVersions) == 0 {
		return nil, fmt.Errorf("captured ClientHello offers no supported TLS 1.2 or TLS 1.3 version")
	}
	return m, nil
}

// Stop at the opening message: allocating a record index for unrelated later
// ciphertext would let a capture's tiny empty records amplify memory use.
func openingClientHello(stream []byte) ([]byte, error) {
	var hs []byte
	for offset := 0; offset < len(stream) && offset < maxClientHelloBytes; {
		if len(stream)-offset < 5 {
			return nil, fmt.Errorf("TLS ClientHello record header is truncated")
		}
		header := stream[offset : offset+5]
		n := int(binary.BigEndian.Uint16(header[3:5]))
		offset += 5
		if header[0] != 22 || header[1] != 3 || n > 16384 {
			return nil, fmt.Errorf("capture does not begin with valid TLS ClientHello records")
		}
		if n > len(stream)-offset {
			return nil, fmt.Errorf("TLS ClientHello record body is truncated")
		}
		if offset+n > maxClientHelloBytes || len(hs)+n > maxClientHelloBytes {
			return nil, fmt.Errorf("TLS ClientHello exceeds 256 KiB")
		}
		hs = append(hs, stream[offset:offset+n]...)
		offset += n
		if len(hs) < 4 {
			continue
		}
		length := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		if hs[0] != 1 || length > maxClientHelloBytes-4 {
			return nil, fmt.Errorf("capture opening handshake is not a bounded ClientHello")
		}
		if len(hs) >= 4+length {
			return hs[4 : 4+length], nil
		}
	}
	return nil, fmt.Errorf("capture has no complete opening TLS ClientHello")
}

func validSNI(s string) bool {
	if len(s) == 0 || len(s) > 253 || net.ParseIP(s) != nil || strings.HasSuffix(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func publicHash(b []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }
