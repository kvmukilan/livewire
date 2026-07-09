package dissect

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// DNP3 (IEEE 1815) framing, three stacked layers:
//
//	Data-link: 0x05 0x64 | LEN | CTRL | DEST(2) | SRC(2) | CRC(2)
//	           LEN counts CTRL+DEST+SRC+user-data (excluding CRCs); min is 5.
//	User data: blocks of up to 16 octets, each followed by a 2-octet CRC.
//	Transport: one octet — FIN(1) FIR(1) SEQ(6).
//	Application: control octet — FIR FIN CON UNS SEQ(4) — then a function code.
//
// Transport SEQ and application SEQ are counters a device may validate even when
// TCP is perfect; this dissector exposes them and rebuilds CRCs/length after an edit.

const (
	dnp3Start0     = 0x05
	dnp3Start1     = 0x64
	dnp3HeaderLen  = 10 // start(2)+len(1)+ctrl(1)+dest(2)+src(2)+crc(2)
	dnp3BlockData  = 16 // max user-data octets per CRC block
	dnp3MinLenByte = 5  // LEN counts ctrl+dest+src at minimum
)

// Errors returned by the DNP3 dissector.
var (
	ErrDNP3Start     = errors.New("dissect: not a DNP3 frame (missing 0x0564 start)")
	ErrDNP3Short     = errors.New("dissect: DNP3 frame shorter than link header")
	ErrDNP3LenField  = errors.New("dissect: DNP3 LEN field out of range")
	ErrDNP3HdrCRC    = errors.New("dissect: DNP3 link header CRC mismatch")
	ErrDNP3BlockCRC  = errors.New("dissect: DNP3 data block CRC mismatch")
	ErrDNP3Truncated = errors.New("dissect: DNP3 frame truncated")
)

// DNP3 is one parsed data-link frame with its de-blocked user data and the
// recovered transport/application fields.
type DNP3 struct {
	Control uint8
	Dest    uint16
	Source  uint16

	UserData []byte // application bytes with per-block CRCs removed

	// Transport layer (present when UserData is non-empty).
	HasTransport bool
	TransportFIN bool
	TransportFIR bool
	TransportSeq uint8 // 6-bit

	// Application layer (present when there is a byte after the transport octet).
	HasApp     bool
	AppControl uint8
	AppFIR     bool
	AppFIN     bool
	AppCON     bool
	AppUNS     bool
	AppSeq     uint8 // 4-bit
	AppFunc    uint8
}

// crcDNP computes the DNP3 CRC-16 (IEEE 1815 Annex E): poly 0x3D65, reflected,
// init 0x0000, final XOR 0xFFFF.
func crcDNP(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xA6BC // reflected 0x3D65
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc & 0xFFFF
}

// deblock verifies and strips the per-16-octet CRCs from a frame's user-data
// region, returning the concatenated application bytes.
func deblock(body []byte) ([]byte, error) {
	out := make([]byte, 0, len(body))
	for off := 0; off < len(body); {
		// Full block is 16 data octets + 2-octet CRC = 18; the last may be shorter.
		chunk := len(body) - off
		if chunk > dnp3BlockData+2 {
			chunk = dnp3BlockData + 2
		}
		if chunk < 3 { // need a data octet plus its CRC
			return nil, ErrDNP3Truncated
		}
		dataN := chunk - 2
		block := body[off : off+dataN]
		want := binary.LittleEndian.Uint16(body[off+dataN : off+chunk])
		if crcDNP(block) != want {
			return nil, ErrDNP3BlockCRC
		}
		out = append(out, block...)
		off += chunk
	}
	return out, nil
}

// enblock inverts deblock: split application bytes into 16-octet blocks, each
// followed by a fresh CRC.
func enblock(app []byte) []byte {
	out := make([]byte, 0, len(app)+2*((len(app)+15)/16))
	for off := 0; off < len(app); off += dnp3BlockData {
		n := len(app) - off
		if n > dnp3BlockData {
			n = dnp3BlockData
		}
		block := app[off : off+n]
		out = append(out, block...)
		out = binary.LittleEndian.AppendUint16(out, crcDNP(block))
	}
	return out
}

// ParseDNP3 parses one data-link frame from the front of buf, verifying the link
// header CRC and every data-block CRC and decoding the transport/application
// layers. It returns the number of bytes consumed.
func ParseDNP3(buf []byte) (d DNP3, consumed int, err error) {
	if len(buf) < dnp3HeaderLen {
		return DNP3{}, 0, ErrDNP3Short
	}
	if buf[0] != dnp3Start0 || buf[1] != dnp3Start1 {
		return DNP3{}, 0, ErrDNP3Start
	}
	length := int(buf[2])
	if length < dnp3MinLenByte {
		return DNP3{}, 0, ErrDNP3LenField
	}
	if crcDNP(buf[0:8]) != binary.LittleEndian.Uint16(buf[8:10]) {
		return DNP3{}, 0, ErrDNP3HdrCRC
	}
	d.Control = buf[3]
	d.Dest = binary.LittleEndian.Uint16(buf[4:6])
	d.Source = binary.LittleEndian.Uint16(buf[6:8])

	// User-data octet count = LEN - (ctrl + dest + src) = LEN - 5.
	userLen := length - dnp3MinLenByte
	nBlocks := (userLen + dnp3BlockData - 1) / dnp3BlockData
	bodyLen := userLen + 2*nBlocks // one CRC per block
	total := dnp3HeaderLen + bodyLen
	if total > len(buf) {
		return DNP3{}, 0, ErrDNP3Truncated
	}
	app, err := deblock(buf[dnp3HeaderLen:total])
	if err != nil {
		return DNP3{}, 0, err
	}
	d.UserData = app

	if len(app) >= 1 {
		t := app[0]
		d.HasTransport = true
		d.TransportFIN = t&0x80 != 0
		d.TransportFIR = t&0x40 != 0
		d.TransportSeq = t & 0x3F
	}
	if len(app) >= 3 {
		c := app[1]
		d.HasApp = true
		d.AppControl = c
		d.AppFIR = c&0x80 != 0
		d.AppFIN = c&0x40 != 0
		d.AppCON = c&0x20 != 0
		d.AppUNS = c&0x10 != 0
		d.AppSeq = c & 0x0F
		d.AppFunc = app[2]
	}
	return d, total, nil
}

// DNP3FunctionName maps an application function code to a short label (the
// common request/response codes; responses are 0x81/0x82).
func DNP3FunctionName(code uint8) string {
	switch code {
	case 0x00:
		return "confirm"
	case 0x01:
		return "read"
	case 0x02:
		return "write"
	case 0x03:
		return "select"
	case 0x04:
		return "operate"
	case 0x05:
		return "direct-operate"
	case 0x0d:
		return "cold-restart"
	case 0x0e:
		return "warm-restart"
	case 0x14:
		return "enable-unsolicited"
	case 0x15:
		return "disable-unsolicited"
	case 0x17:
		return "delay-measure"
	case 0x81:
		return "response"
	case 0x82:
		return "unsolicited-response"
	}
	return "unknown"
}

// ParseDNP3Stream parses every complete DNP3 link frame in buf. A trailing
// partial frame is reported via leftover (like ParseModbusStream).
func ParseDNP3Stream(buf []byte) (frames []DNP3, leftover int, err error) {
	off := 0
	for off < len(buf) {
		d, n, e := ParseDNP3(buf[off:])
		if e != nil {
			if errors.Is(e, ErrDNP3Short) || errors.Is(e, ErrDNP3Truncated) {
				return frames, len(buf) - off, nil // incomplete tail
			}
			return frames, 0, e
		}
		frames = append(frames, d)
		off += n
	}
	return frames, 0, nil
}

// CompareDNP3 checks a live DNP3 response frame against the captured one it
// should reproduce, mirroring CompareADU. A differing application function or
// application sequence is structural; user-data drift is a tolerated value
// change.
func CompareDNP3(want, got DNP3) []ADUDiff {
	var diffs []ADUDiff
	if want.HasApp || got.HasApp {
		if want.AppFunc != got.AppFunc {
			diffs = append(diffs, ADUDiff{true, fmt.Sprintf(
				"expected app function 0x%02x (%s), got 0x%02x (%s)",
				want.AppFunc, DNP3FunctionName(want.AppFunc), got.AppFunc, DNP3FunctionName(got.AppFunc))})
		}
		if want.AppSeq != got.AppSeq {
			diffs = append(diffs, ADUDiff{true, fmt.Sprintf(
				"application sequence mismatch: capture %d, live %d", want.AppSeq, got.AppSeq)})
		}
	}
	if want.AppFunc == got.AppFunc && !bytesEqual(want.UserData, got.UserData) {
		diffs = append(diffs, ADUDiff{false, fmt.Sprintf(
			"response data differs: capture [% x], live [% x]", want.UserData, got.UserData)})
	}
	return diffs
}

// transportOctet rebuilds the transport control byte from FIN/FIR/SEQ.
func (d DNP3) transportOctet() uint8 {
	var t uint8
	if d.TransportFIN {
		t |= 0x80
	}
	if d.TransportFIR {
		t |= 0x40
	}
	return t | (d.TransportSeq & 0x3F)
}

// Encode rebuilds the on-wire frame, recomputing the LEN byte, link header CRC,
// and every data-block CRC. Valid after mutating UserData or bumping
// TransportSeq/AppSeq.
func (d DNP3) Encode() []byte {
	app := append([]byte(nil), d.UserData...)
	if d.HasTransport && len(app) >= 1 {
		app[0] = d.transportOctet()
	}
	if d.HasApp && len(app) >= 2 {
		app[1] = (d.AppControl &^ 0x0F) | (d.AppSeq & 0x0F)
	}

	length := dnp3MinLenByte + len(app)
	out := make([]byte, dnp3HeaderLen)
	out[0], out[1] = dnp3Start0, dnp3Start1
	out[2] = uint8(length)
	out[3] = d.Control
	binary.LittleEndian.PutUint16(out[4:6], d.Dest)
	binary.LittleEndian.PutUint16(out[6:8], d.Source)
	binary.LittleEndian.PutUint16(out[8:10], crcDNP(out[0:8]))
	return append(out, enblock(app)...)
}
