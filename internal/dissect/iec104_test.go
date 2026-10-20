package dissect

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// iec104SpontaneousFrame builds an M_SP_TB_1 (type 30) burst as a controlled
// station sends after STARTDT: count single points with CP56Time2a tags.
func iec104SpontaneousFrame(sendSeq, recvSeq uint16, count int, cot uint8, stamp byte) []byte {
	asdu := []byte{30, byte(count), cot, 0, 1, 0}
	for i := 0; i < count; i++ {
		asdu = append(asdu, byte(0x26+i), 0x1e, 0x00, byte(i&1))
		asdu = append(asdu, stamp, 0x55, 0x25, 0x0c, 0x14, 0x0a, 0x1a)
	}
	f := IEC104{Raw: append([]byte{0x68, byte(4 + len(asdu)), 0, 0, 0, 0}, asdu...), Format: IEC104I, SendSeq: sendSeq, RecvSeq: recvSeq}
	return f.Encode()
}

func TestParseIEC104Formats(t *testing.T) {
	u, n, err := ParseIEC104([]byte{0x68, 0x04, 0x07, 0, 0, 0})
	if err != nil || n != 6 || u.Format != IEC104U || u.UFunc != IEC104StartDTAct {
		t.Fatalf("STARTDT act: %+v n=%d err=%v", u, n, err)
	}
	s, _, err := ParseIEC104([]byte{0x68, 0x04, 0x01, 0x00, 0x04, 0x00})
	if err != nil || s.Format != IEC104S || s.RecvSeq != 2 {
		t.Fatalf("S frame: %+v err=%v", s, err)
	}
	// Reset-process command as captured from a controlling station: N(S)=0, N(R)=2.
	raw := []byte{0x68, 0x0e, 0x00, 0x00, 0x04, 0x00, 0x69, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01}
	i, n, err := ParseIEC104(raw)
	if err != nil || n != len(raw) || i.Format != IEC104I || i.SendSeq != 0 || i.RecvSeq != 2 {
		t.Fatalf("I frame: %+v n=%d err=%v", i, n, err)
	}
	if !i.HasASDU || i.TypeID != 105 || i.VSQ != 1 || i.COT != 1 || i.Negative || i.OA != 1 || i.CA != 1 {
		t.Fatalf("ASDU header: %+v", i)
	}
	negative, _, err := ParseIEC104([]byte{0x68, 0x0e, 0x08, 0x00, 0x02, 0x00, 0x69, 0x00, 0x47, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01})
	if err != nil || negative.SendSeq != 4 || negative.RecvSeq != 1 || negative.COT != 7 || !negative.Negative {
		t.Fatalf("negative confirmation: %+v err=%v", negative, err)
	}
	if ParseOrPanic(IEC104SFrame(0)).Unsolicited() || !ParseOrPanic(iec104SpontaneousFrame(2, 1, 21, 3, 0x08)).Unsolicited() {
		t.Fatal("spontaneous classification")
	}
}

func ParseOrPanic(raw []byte) IEC104 {
	f, _, err := ParseIEC104(raw)
	if err != nil {
		panic(err)
	}
	return f
}

func TestParseIEC104Errors(t *testing.T) {
	cases := []struct {
		raw []byte
		err error
	}{
		{[]byte{0x68}, ErrIEC104Short},
		{[]byte{0x68, 0x04, 0x07}, ErrIEC104Short},
		{[]byte{0x68, 0x0e, 0x00, 0x00, 0x04, 0x00, 0x69}, ErrIEC104Truncated},
		{[]byte{0x69, 0x04, 0x07, 0, 0, 0}, ErrIEC104Start},
		{[]byte{0x68, 0x03, 0x07, 0, 0, 0}, ErrIEC104Length},
	}
	for _, tc := range cases {
		if _, _, err := ParseIEC104(tc.raw); !errors.Is(err, tc.err) {
			t.Errorf("%x: got %v want %v", tc.raw, err, tc.err)
		}
	}
	frames, left, err := ParseIEC104Stream(append(IEC104UFrame(IEC104StartDTAct), 0x68, 0x0e, 0x00))
	if err != nil || len(frames) != 1 || left != 3 {
		t.Fatalf("stream with partial tail: frames=%d left=%d err=%v", len(frames), left, err)
	}
	if _, _, err := ParseIEC104Stream([]byte{0x68, 0x04, 0x07, 0, 0, 0, 0x00, 0x04}); err == nil {
		t.Fatal("expected a start-byte error for garbage after a frame")
	}
}

func TestIEC104EncodeRewritesControlFieldOnly(t *testing.T) {
	raw := []byte{0x68, 0x0e, 0x00, 0x00, 0x04, 0x00, 0x69, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01}
	f := ParseOrPanic(raw)
	f.SendSeq, f.RecvSeq = 300, 32767
	out := f.Encode()
	if !bytes.Equal(out[6:], raw[6:]) || bytes.Equal(out, raw) {
		t.Fatalf("encode changed the ASDU or nothing: %x", out)
	}
	again := ParseOrPanic(out)
	if again.SendSeq != 300 || again.RecvSeq != 32767 {
		t.Fatalf("round trip: %+v", again)
	}
	if got := IEC104SFrame(9); !bytes.Equal(got, []byte{0x68, 0x04, 0x01, 0x00, 0x12, 0x00}) {
		t.Fatalf("S frame: %x", got)
	}
	u := ParseOrPanic(IEC104UFrame(IEC104TestFRAct))
	if !bytes.Equal(u.Encode(), IEC104UFrame(IEC104TestFRAct)) {
		t.Fatal("U frame encode")
	}
}

func TestIEC104ObjectsAndCompare(t *testing.T) {
	want := ParseOrPanic(iec104SpontaneousFrame(0, 0, 21, 20, 0x08))
	objects, err := want.Objects()
	if err != nil || len(objects) != 21 || objects[1].IOA != 0x1e27 || len(objects[1].Element) != 1 || len(objects[1].Time) != 7 {
		t.Fatalf("objects: %d err=%v %+v", len(objects), err, objects)
	}
	// Same points, different timestamps: lenient accepts, strict does not.
	later := ParseOrPanic(iec104SpontaneousFrame(5, 3, 21, 20, 0x09))
	if diffs := CompareIEC104(want, later, false); len(diffs) != 0 {
		t.Fatalf("lenient time drift: %+v", diffs)
	}
	if diffs := CompareIEC104(want, later, true); len(diffs) != 21 || diffs[0].Field != "object[0].time" {
		t.Fatalf("strict time drift: %+v", diffs)
	}
	// A changed point value is reported in both modes, structurally only in strict.
	changed := iec104SpontaneousFrame(0, 0, 21, 20, 0x08)
	changed[6+6+3] ^= 0x01
	diffs := CompareIEC104(want, ParseOrPanic(changed), false)
	if len(diffs) != 1 || diffs[0].Field != "object[0].value" || diffs[0].Structural {
		t.Fatalf("value drift: %+v", diffs)
	}
	if diffs := CompareIEC104(want, ParseOrPanic(changed), true); len(diffs) != 1 || !diffs[0].Structural {
		t.Fatalf("strict value drift: %+v", diffs)
	}
	// Structural header differences stop before object comparison.
	other := iec104SpontaneousFrame(0, 0, 21, 3, 0x08)
	if diffs := CompareIEC104(want, ParseOrPanic(other), false); len(diffs) != 1 || diffs[0].Field != "cot" || !diffs[0].Structural {
		t.Fatalf("cot difference: %+v", diffs)
	}
	if diffs := CompareIEC104(ParseOrPanic(IEC104UFrame(IEC104StartDTCon)), ParseOrPanic(IEC104UFrame(IEC104StopDTCon)), false); len(diffs) != 1 || diffs[0].Field != "function" {
		t.Fatalf("U difference: %+v", diffs)
	}
	if diffs := CompareIEC104(ParseOrPanic(IEC104SFrame(1)), ParseOrPanic(IEC104SFrame(7)), true); len(diffs) != 0 {
		t.Fatalf("S frames never differ: %+v", diffs)
	}
	// Sequence of elements under one address.
	seq := []byte{0x68, 0x00, 0, 0, 0, 0, 1, 0x83, 20, 0, 1, 0, 0x10, 0x00, 0x00, 1, 0, 1}
	seq[1] = byte(len(seq) - 2)
	objects, err = ParseOrPanic(seq).Objects()
	if err != nil || len(objects) != 3 || objects[2].IOA != 0x12 {
		t.Fatalf("SQ objects: %+v err=%v", objects, err)
	}
	// Unknown layouts compare as opaque information bytes.
	unknown := []byte{0x68, 0x0a, 0, 0, 0, 0, 0xe9, 0x01, 0x03, 0x00, 0x01, 0x00}
	if _, err := ParseOrPanic(unknown).Objects(); err == nil {
		t.Fatal("expected unknown layout error")
	}
	if diffs := CompareIEC104(ParseOrPanic(unknown), ParseOrPanic(unknown), true); len(diffs) != 0 {
		t.Fatalf("identical unknown ASDU: %+v", diffs)
	}
	short := []byte{0x68, 0x06, 0, 0, 0, 0, 0xe9, 0x01}
	if f := ParseOrPanic(short); f.HasASDU || !bytes.Equal(f.ASDU, []byte{0xe9, 0x01}) {
		t.Fatalf("short ASDU: %+v", f)
	}
	if diffs := CompareIEC104(ParseOrPanic(short), ParseOrPanic(unknown), false); len(diffs) != 1 || diffs[0].Field != "asdu" {
		t.Fatalf("short versus full ASDU: %+v", diffs)
	}
}

func TestIEC104ReadOnlyAndNames(t *testing.T) {
	interrogation := []byte{0x68, 0x0e, 0, 0, 0, 0, 100, 1, 6, 0, 1, 0, 0, 0, 0, 20}
	if !ParseOrPanic(interrogation).ReadOnly() {
		t.Fatal("general interrogation is read-only")
	}
	if ParseOrPanic([]byte{0x68, 0x0e, 0x00, 0x00, 0x04, 0x00, 0x69, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01}).ReadOnly() {
		t.Fatal("reset process is not read-only")
	}
	if !ParseOrPanic(IEC104SFrame(0)).ReadOnly() || !ParseOrPanic(IEC104UFrame(IEC104StopDTAct)).ReadOnly() {
		t.Fatal("control frames are read-only")
	}
	if IEC104TypeName(100) != "C_IC_NA_1 (100)" || IEC104TypeName(200) != "type 200" || IEC104UFunctionName(0x83) != "TESTFR con" {
		t.Fatal("names")
	}
	var seq [2]byte
	binary.LittleEndian.PutUint16(seq[:], 1)
	if ParseOrPanic(append([]byte{0x68, 0x0a, 0, 0, 0, 0, 70, 1, 4, 0}, seq[:]...)).Unsolicited() {
		t.Fatal("end of initialisation is solicited")
	}
}
