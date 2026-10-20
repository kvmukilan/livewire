package dissect

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// IEC 60870-5-104 (IEC 104) carries IEC 60870-5-101 ASDUs over TCP behind a
// six-byte APCI: start byte 0x68, an APDU length, and a four-byte control
// field. The control field distinguishes information (I), supervisory (S) and
// unnumbered (U) frames and carries the send/receive sequence numbers that a
// controlled station validates on every live connection. Those numbers belong
// to the connection, not the capture, so a replay must rewrite them.

// Errors returned by the IEC 104 dissector.
var (
	ErrIEC104Short     = errors.New("dissect: iec104 APDU shorter than the APCI header")
	ErrIEC104Start     = errors.New("dissect: iec104 APDU does not begin with 0x68")
	ErrIEC104Length    = errors.New("dissect: iec104 APDU length field below the control field size")
	ErrIEC104Truncated = errors.New("dissect: iec104 APDU truncated")
)

// IEC104Format is the APCI frame format.
type IEC104Format uint8

const (
	// IEC104I carries an ASDU and both sequence numbers.
	IEC104I IEC104Format = iota
	// IEC104S acknowledges received I frames.
	IEC104S
	// IEC104U carries connection control (STARTDT, STOPDT, TESTFR).
	IEC104U
)

func (f IEC104Format) String() string {
	switch f {
	case IEC104I:
		return "I"
	case IEC104S:
		return "S"
	default:
		return "U"
	}
}

// U-frame function codes (control octet 1).
const (
	IEC104StartDTAct uint8 = 0x07
	IEC104StartDTCon uint8 = 0x0b
	IEC104StopDTAct  uint8 = 0x13
	IEC104StopDTCon  uint8 = 0x23
	IEC104TestFRAct  uint8 = 0x43
	IEC104TestFRCon  uint8 = 0x83
)

const (
	iec104APCILen    = 6
	iec104MaxAPDULen = 253
	// iec104ASDUHeaderLen is the IEC 104 ASDU header: type, VSQ, two-byte
	// cause of transmission and two-byte common address.
	iec104ASDUHeaderLen = 6
	iec104IOALen        = 3
)

// IEC104 is one parsed APDU.
type IEC104 struct {
	Raw     []byte
	Format  IEC104Format
	SendSeq uint16 // N(S), I frames
	RecvSeq uint16 // N(R), I and S frames
	UFunc   uint8  // U-frame function code
	ASDU    []byte // bytes after the control field (I frames)

	// ASDU header, valid when HasASDU is set.
	HasASDU  bool
	TypeID   uint8
	VSQ      uint8
	COT      uint8 // cause of transmission (low six bits)
	Negative bool  // P/N bit
	Test     bool  // T bit
	OA       uint8 // originator address
	CA       uint16
}

// ParseIEC104 parses one APDU from the front of buf and reports how many bytes
// it consumed. A truncated APDU returns ErrIEC104Short or ErrIEC104Truncated so
// stream callers can wait for more bytes.
func ParseIEC104(buf []byte) (f IEC104, consumed int, err error) {
	if len(buf) < 2 {
		return IEC104{}, 0, ErrIEC104Short
	}
	if buf[0] != 0x68 {
		return IEC104{}, 0, ErrIEC104Start
	}
	length := int(buf[1])
	if length < 4 {
		return IEC104{}, 0, ErrIEC104Length
	}
	total := 2 + length
	if len(buf) < iec104APCILen {
		return IEC104{}, 0, ErrIEC104Short
	}
	if total > len(buf) {
		return IEC104{}, 0, ErrIEC104Truncated
	}
	f.Raw = buf[:total]
	control := buf[2:6]
	switch {
	case control[0]&0x01 == 0:
		f.Format = IEC104I
		f.SendSeq = uint16(control[0]>>1) | uint16(control[1])<<7
		f.RecvSeq = uint16(control[2]>>1) | uint16(control[3])<<7
		f.ASDU = buf[iec104APCILen:total]
		if len(f.ASDU) >= iec104ASDUHeaderLen {
			f.HasASDU = true
			f.TypeID = f.ASDU[0]
			f.VSQ = f.ASDU[1]
			f.COT = f.ASDU[2] & 0x3f
			f.Negative = f.ASDU[2]&0x40 != 0
			f.Test = f.ASDU[2]&0x80 != 0
			f.OA = f.ASDU[3]
			f.CA = binary.LittleEndian.Uint16(f.ASDU[4:6])
		}
	case control[0]&0x03 == 0x01:
		f.Format = IEC104S
		f.RecvSeq = uint16(control[2]>>1) | uint16(control[3])<<7
	default:
		f.Format = IEC104U
		f.UFunc = control[0]
	}
	return f, total, nil
}

// ParseIEC104Stream parses every complete APDU in buf. A trailing partial APDU
// is reported through leftover rather than as an error.
func ParseIEC104Stream(buf []byte) (frames []IEC104, leftover int, err error) {
	off := 0
	for off < len(buf) {
		f, n, e := ParseIEC104(buf[off:])
		if e != nil {
			if errors.Is(e, ErrIEC104Short) || errors.Is(e, ErrIEC104Truncated) {
				return frames, len(buf) - off, nil
			}
			return frames, 0, e
		}
		frames = append(frames, f)
		off += n
	}
	return frames, 0, nil
}

// Encode returns the APDU bytes with the control field rebuilt from the
// current Format, SendSeq, RecvSeq and UFunc. The ASDU bytes are unchanged.
func (f IEC104) Encode() []byte {
	out := append([]byte(nil), f.Raw...)
	if len(out) < iec104APCILen {
		return out
	}
	switch f.Format {
	case IEC104I:
		ns, nr := f.SendSeq&0x7fff, f.RecvSeq&0x7fff
		out[2] = byte(ns<<1) & 0xfe
		out[3] = byte(ns >> 7)
		out[4] = byte(nr<<1) & 0xfe
		out[5] = byte(nr >> 7)
	case IEC104S:
		nr := f.RecvSeq & 0x7fff
		out[2] = 0x01
		out[3] = 0
		out[4] = byte(nr<<1) & 0xfe
		out[5] = byte(nr >> 7)
	default:
		out[2] = f.UFunc
		out[3], out[4], out[5] = 0, 0, 0
	}
	return out
}

// IEC104UFrame builds a four-byte U frame for the given function code.
func IEC104UFrame(function uint8) []byte {
	return []byte{0x68, 0x04, function, 0, 0, 0}
}

// IEC104SFrame builds a supervisory frame acknowledging recvSeq.
func IEC104SFrame(recvSeq uint16) []byte {
	return IEC104{Raw: []byte{0x68, 0x04, 0x01, 0, 0, 0}, Format: IEC104S, RecvSeq: recvSeq}.Encode()
}

// Unsolicited reports whether an I frame carries data the controlled station
// sends on its own schedule: periodic, background scan, or spontaneous causes.
// A live device does not reproduce these in the captured number or order.
func (f IEC104) Unsolicited() bool {
	if f.Format != IEC104I || !f.HasASDU {
		return false
	}
	switch f.COT {
	case 1, 2, 3:
		return true
	}
	return false
}

// SQ reports whether the variable structure qualifier declares a sequence of
// elements under one information object address.
func (f IEC104) SQ() bool { return f.VSQ&0x80 != 0 }

// ObjectCount is the number of information objects or elements in the ASDU.
func (f IEC104) ObjectCount() int { return int(f.VSQ & 0x7f) }

// IEC104Object is one information object split into its address, the element
// bytes, and any trailing time tag.
type IEC104Object struct {
	IOA     uint32
	Element []byte
	Time    []byte
}

// iec104Layout gives the element and time-tag sizes for the ASDU types whose
// information objects are fixed-size. Types outside this table are compared as
// opaque ASDU bytes.
type iec104Layout struct{ element, timeTag int }

var iec104Layouts = map[uint8]iec104Layout{
	1: {1, 0}, 2: {1, 3}, 3: {1, 0}, 4: {1, 3}, 5: {2, 0}, 6: {2, 3}, 7: {5, 0}, 8: {5, 3},
	9: {3, 0}, 10: {3, 3}, 11: {3, 0}, 12: {3, 3}, 13: {5, 0}, 14: {5, 3}, 15: {5, 0}, 16: {5, 3},
	17: {3, 3}, 18: {7, 3}, 19: {7, 3}, 20: {5, 0}, 21: {2, 0},
	30: {1, 7}, 31: {1, 7}, 32: {2, 7}, 33: {5, 7}, 34: {3, 7}, 35: {3, 7}, 36: {5, 7}, 37: {5, 7},
	38: {3, 7}, 39: {7, 7}, 40: {7, 7},
	45: {1, 0}, 46: {1, 0}, 47: {1, 0}, 48: {3, 0}, 49: {3, 0}, 50: {5, 0}, 51: {4, 0},
	58: {1, 7}, 59: {1, 7}, 60: {1, 7}, 61: {3, 7}, 62: {3, 7}, 63: {5, 7}, 64: {4, 7},
	70: {1, 0}, 100: {1, 0}, 101: {1, 0}, 102: {0, 0}, 103: {0, 7}, 104: {2, 0}, 105: {1, 0},
	106: {2, 0}, 107: {2, 7}, 110: {3, 0}, 111: {3, 0}, 112: {5, 0}, 113: {0, 0},
}

// Objects splits the ASDU into information objects. It reports an error for
// type identifications outside the fixed-size table and for layouts that do not
// fit the ASDU; callers then fall back to opaque comparison.
func (f IEC104) Objects() ([]IEC104Object, error) {
	if !f.HasASDU {
		return nil, fmt.Errorf("dissect: iec104 ASDU header incomplete")
	}
	layout, ok := iec104Layouts[f.TypeID]
	if !ok {
		return nil, fmt.Errorf("dissect: iec104 type %d has no fixed object layout", f.TypeID)
	}
	body := f.ASDU[iec104ASDUHeaderLen:]
	count := f.ObjectCount()
	size := layout.element + layout.timeTag
	var out []IEC104Object
	if f.SQ() {
		if len(body) < iec104IOALen {
			return nil, fmt.Errorf("dissect: iec104 sequence lacks an information object address")
		}
		base := uint32(body[0]) | uint32(body[1])<<8 | uint32(body[2])<<16
		body = body[iec104IOALen:]
		if len(body) != count*size {
			return nil, fmt.Errorf("dissect: iec104 type %d sequence of %d needs %d byte(s), have %d", f.TypeID, count, count*size, len(body))
		}
		for i := 0; i < count; i++ {
			chunk := body[i*size : (i+1)*size]
			out = append(out, IEC104Object{IOA: base + uint32(i), Element: chunk[:layout.element], Time: chunk[layout.element:]})
		}
		return out, nil
	}
	if len(body) != count*(iec104IOALen+size) {
		return nil, fmt.Errorf("dissect: iec104 type %d with %d object(s) needs %d byte(s), have %d", f.TypeID, count, count*(iec104IOALen+size), len(body))
	}
	for i := 0; i < count; i++ {
		chunk := body[i*(iec104IOALen+size) : (i+1)*(iec104IOALen+size)]
		ioa := uint32(chunk[0]) | uint32(chunk[1])<<8 | uint32(chunk[2])<<16
		out = append(out, IEC104Object{IOA: ioa, Element: chunk[iec104IOALen : iec104IOALen+layout.element], Time: chunk[iec104IOALen+layout.element:]})
	}
	return out, nil
}

// IEC104Diff is one difference between a captured and a live APDU.
type IEC104Diff struct {
	Field      string
	Expected   string
	Actual     string
	Structural bool
}

// CompareIEC104 checks a live APDU against the captured one. Sequence numbers
// are never compared: they belong to the live connection. In lenient mode the
// originator address and time tags may drift; strict mode compares every ASDU
// byte.
func CompareIEC104(want, got IEC104, strict bool) []IEC104Diff {
	if want.Format != got.Format {
		return []IEC104Diff{{Field: "format", Expected: want.Format.String(), Actual: got.Format.String(), Structural: true}}
	}
	switch want.Format {
	case IEC104S:
		return nil
	case IEC104U:
		if want.UFunc != got.UFunc {
			return []IEC104Diff{{Field: "function", Expected: IEC104UFunctionName(want.UFunc), Actual: IEC104UFunctionName(got.UFunc), Structural: true}}
		}
		return nil
	}
	if !want.HasASDU || !got.HasASDU {
		if string(want.ASDU) != string(got.ASDU) {
			return []IEC104Diff{{Field: "asdu", Expected: fmt.Sprintf("%d bytes", len(want.ASDU)), Actual: fmt.Sprintf("%d bytes", len(got.ASDU)), Structural: true}}
		}
		return nil
	}
	var diffs []IEC104Diff
	if want.TypeID != got.TypeID {
		diffs = append(diffs, IEC104Diff{Field: "typeId", Expected: IEC104TypeName(want.TypeID), Actual: IEC104TypeName(got.TypeID), Structural: true})
	}
	if want.VSQ != got.VSQ {
		diffs = append(diffs, IEC104Diff{Field: "objects", Expected: fmt.Sprintf("%d (SQ=%t)", want.ObjectCount(), want.SQ()), Actual: fmt.Sprintf("%d (SQ=%t)", got.ObjectCount(), got.SQ()), Structural: true})
	}
	if want.COT != got.COT || want.Negative != got.Negative || want.Test != got.Test {
		diffs = append(diffs, IEC104Diff{Field: "cot", Expected: iec104COTText(want), Actual: iec104COTText(got), Structural: true})
	}
	if want.OA != got.OA && strict {
		diffs = append(diffs, IEC104Diff{Field: "originator", Expected: fmt.Sprint(want.OA), Actual: fmt.Sprint(got.OA), Structural: true})
	}
	if want.CA != got.CA {
		diffs = append(diffs, IEC104Diff{Field: "commonAddress", Expected: fmt.Sprint(want.CA), Actual: fmt.Sprint(got.CA), Structural: true})
	}
	if len(diffs) > 0 {
		return diffs
	}
	wantObjects, werr := want.Objects()
	gotObjects, gerr := got.Objects()
	if werr != nil || gerr != nil {
		if string(want.ASDU[iec104ASDUHeaderLen:]) != string(got.ASDU[iec104ASDUHeaderLen:]) {
			diffs = append(diffs, IEC104Diff{Field: "information", Expected: fmt.Sprintf("%d bytes", len(want.ASDU)-iec104ASDUHeaderLen), Actual: fmt.Sprintf("%d bytes", len(got.ASDU)-iec104ASDUHeaderLen), Structural: strict})
		}
		return diffs
	}
	for i := range wantObjects {
		w, g := wantObjects[i], gotObjects[i]
		if w.IOA != g.IOA {
			diffs = append(diffs, IEC104Diff{Field: fmt.Sprintf("object[%d].ioa", i), Expected: fmt.Sprint(w.IOA), Actual: fmt.Sprint(g.IOA), Structural: true})
			continue
		}
		if string(w.Element) != string(g.Element) {
			diffs = append(diffs, IEC104Diff{Field: fmt.Sprintf("object[%d].value", i), Expected: fmt.Sprintf("ioa %d %x", w.IOA, w.Element), Actual: fmt.Sprintf("ioa %d %x", g.IOA, g.Element), Structural: strict})
		}
		if strict && string(w.Time) != string(g.Time) {
			diffs = append(diffs, IEC104Diff{Field: fmt.Sprintf("object[%d].time", i), Expected: fmt.Sprintf("%x", w.Time), Actual: fmt.Sprintf("%x", g.Time), Structural: true})
		}
	}
	return diffs
}

func iec104COTText(f IEC104) string {
	text := fmt.Sprintf("%d", f.COT)
	if f.Negative {
		text += " negative"
	}
	if f.Test {
		text += " test"
	}
	return text
}

// IEC104UFunctionName labels a U-frame function code.
func IEC104UFunctionName(function uint8) string {
	switch function {
	case IEC104StartDTAct:
		return "STARTDT act"
	case IEC104StartDTCon:
		return "STARTDT con"
	case IEC104StopDTAct:
		return "STOPDT act"
	case IEC104StopDTCon:
		return "STOPDT con"
	case IEC104TestFRAct:
		return "TESTFR act"
	case IEC104TestFRCon:
		return "TESTFR con"
	}
	return fmt.Sprintf("U 0x%02x", function)
}

// IEC104TypeName labels a type identification with its IEC 60870-5-101 name.
func IEC104TypeName(typeID uint8) string {
	names := map[uint8]string{
		1: "M_SP_NA_1", 2: "M_SP_TA_1", 3: "M_DP_NA_1", 4: "M_DP_TA_1", 5: "M_ST_NA_1", 6: "M_ST_TA_1",
		7: "M_BO_NA_1", 8: "M_BO_TA_1", 9: "M_ME_NA_1", 10: "M_ME_TA_1", 11: "M_ME_NB_1", 12: "M_ME_TB_1",
		13: "M_ME_NC_1", 14: "M_ME_TC_1", 15: "M_IT_NA_1", 16: "M_IT_TA_1", 17: "M_EP_TA_1", 18: "M_EP_TB_1",
		19: "M_EP_TC_1", 20: "M_PS_NA_1", 21: "M_ME_ND_1", 30: "M_SP_TB_1", 31: "M_DP_TB_1", 32: "M_ST_TB_1",
		33: "M_BO_TB_1", 34: "M_ME_TD_1", 35: "M_ME_TE_1", 36: "M_ME_TF_1", 37: "M_IT_TB_1", 38: "M_EP_TD_1",
		39: "M_EP_TE_1", 40: "M_EP_TF_1", 45: "C_SC_NA_1", 46: "C_DC_NA_1", 47: "C_RC_NA_1", 48: "C_SE_NA_1",
		49: "C_SE_NB_1", 50: "C_SE_NC_1", 51: "C_BO_NA_1", 58: "C_SC_TA_1", 59: "C_DC_TA_1", 60: "C_RC_TA_1",
		61: "C_SE_TA_1", 62: "C_SE_TB_1", 63: "C_SE_TC_1", 64: "C_BO_TA_1", 70: "M_EI_NA_1", 100: "C_IC_NA_1",
		101: "C_CI_NA_1", 102: "C_RD_NA_1", 103: "C_CS_NA_1", 104: "C_TS_NA_1", 105: "C_RP_NA_1", 106: "C_CD_NA_1",
		107: "C_TS_TA_1", 110: "P_ME_NA_1", 111: "P_ME_NB_1", 112: "P_ME_NC_1", 113: "P_AC_NA_1",
		120: "F_FR_NA_1", 121: "F_SR_NA_1", 122: "F_SC_NA_1", 123: "F_LS_NA_1", 124: "F_AF_NA_1", 125: "F_SG_NA_1",
		126: "F_DR_TA_1", 127: "F_SC_NB_1",
	}
	if name, ok := names[typeID]; ok {
		return fmt.Sprintf("%s (%d)", name, typeID)
	}
	return fmt.Sprintf("type %d", typeID)
}

// IEC104ReadOnly reports whether an APDU only reads or maintains the connection:
// U and S frames, and interrogation, read, and test commands. Control, set
// point, parameter, clock, reset and file commands are not read-only.
func (f IEC104) ReadOnly() bool {
	if f.Format != IEC104I {
		return true
	}
	if !f.HasASDU {
		return false
	}
	switch f.TypeID {
	case 100, 101, 102, 104:
		return true
	}
	return false
}
