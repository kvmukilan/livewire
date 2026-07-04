package dissect

import "encoding/binary"

// TLS record content types (RFC 8446 §5.1).
const (
	tlsChangeCipherSpec = 20
	tlsAlert            = 21
	tlsHandshake        = 22
	tlsApplicationData  = 23
)

// TLSRecord is the header view of one TLS record.
type TLSRecord struct {
	ContentType uint8
	Version     uint16 // legacy_record_version
	Length      int
	Fragment    []byte
}

// TLSInfo summarises what a flow's opening bytes reveal about TLS. livewire
// uses IsTLS to route encrypted flows toward re-termination instead of the raw
// stateful engine.
type TLSInfo struct {
	IsTLS      bool
	Version    uint16 // record-layer version of the first record
	IsClientHi bool
	SNI        string
	ALPN       []string
}

// ParseTLSRecord reads one record header from the front of buf.
func ParseTLSRecord(buf []byte) (TLSRecord, bool) {
	if len(buf) < 5 {
		return TLSRecord{}, false
	}
	ct := buf[0]
	if ct < tlsChangeCipherSpec || ct > tlsApplicationData {
		return TLSRecord{}, false
	}
	ver := binary.BigEndian.Uint16(buf[1:3])
	// TLS 1.0–1.3 all carry a legacy record version of 0x03xx.
	if ver>>8 != 0x03 {
		return TLSRecord{}, false
	}
	n := int(binary.BigEndian.Uint16(buf[3:5]))
	rec := TLSRecord{ContentType: ct, Version: ver, Length: n}
	if 5+n <= len(buf) {
		rec.Fragment = buf[5 : 5+n]
	} else {
		rec.Fragment = buf[5:]
	}
	return rec, true
}

// DetectTLS inspects a flow's first client payload and reports whether it is
// TLS, extracting the SNI and ALPN from a ClientHello when present.
func DetectTLS(clientPayload []byte) TLSInfo {
	rec, ok := ParseTLSRecord(clientPayload)
	if !ok {
		return TLSInfo{}
	}
	info := TLSInfo{IsTLS: true, Version: rec.Version}
	if rec.ContentType == tlsHandshake {
		parseClientHello(rec.Fragment, &info)
	}
	return info
}

// parseClientHello pulls the SNI (extension 0) and ALPN (extension 16) from a
// ClientHello. Detection is best-effort: truncation just stops parsing.
func parseClientHello(hs []byte, info *TLSInfo) {
	if len(hs) < 4 || hs[0] != 1 { // handshake type 1 = ClientHello
		return
	}
	info.IsClientHi = true
	body := hs[4:]
	// client_version(2) + random(32)
	if len(body) < 34 {
		return
	}
	p := 34
	// session_id
	if p >= len(body) {
		return
	}
	sidLen := int(body[p])
	p += 1 + sidLen
	// cipher_suites
	if p+2 > len(body) {
		return
	}
	csLen := int(binary.BigEndian.Uint16(body[p : p+2]))
	p += 2 + csLen
	// compression_methods
	if p >= len(body) {
		return
	}
	cmLen := int(body[p])
	p += 1 + cmLen
	// extensions
	if p+2 > len(body) {
		return
	}
	extTotal := int(binary.BigEndian.Uint16(body[p : p+2]))
	p += 2
	end := p + extTotal
	if end > len(body) {
		end = len(body)
	}
	for p+4 <= end {
		etype := binary.BigEndian.Uint16(body[p : p+2])
		elen := int(binary.BigEndian.Uint16(body[p+2 : p+4]))
		p += 4
		if p+elen > end {
			return
		}
		switch etype {
		case 0x0000: // server_name
			info.SNI = parseSNI(body[p : p+elen])
		case 0x0010: // application_layer_protocol_negotiation
			info.ALPN = parseALPN(body[p : p+elen])
		}
		p += elen
	}
}

func parseSNI(ext []byte) string {
	if len(ext) < 5 {
		return ""
	}
	// server_name_list length(2), then name_type(1)+name_len(2)+name.
	nameLen := int(binary.BigEndian.Uint16(ext[3:5]))
	if 5+nameLen > len(ext) {
		return ""
	}
	return string(ext[5 : 5+nameLen])
}

func parseALPN(ext []byte) []string {
	if len(ext) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(ext[0:2]))
	p := 2
	end := p + listLen
	if end > len(ext) {
		end = len(ext)
	}
	var out []string
	for p < end {
		n := int(ext[p])
		p++
		if p+n > end {
			break
		}
		out = append(out, string(ext[p:p+n]))
		p += n
	}
	return out
}
