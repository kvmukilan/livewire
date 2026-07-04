package dissect

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestDNP3CRCCheckValue anchors the CRC to the published CRC-16/DNP check value:
// CRC("123456789") == 0xEA82.
func TestDNP3CRCCheckValue(t *testing.T) {
	if got := crcDNP([]byte("123456789")); got != 0xEA82 {
		t.Fatalf("CRC-16/DNP check value = %#04x, want 0xEA82", got)
	}
}

// buildDNP3 assembles a valid frame with the given transport/app fields and data.
func buildDNP3(ctrl uint8, dst, src uint16, tSeq uint8, aSeq, aFunc uint8, objData []byte) []byte {
	app := []byte{
		0xC0 | (tSeq & 0x3F), // transport: FIN|FIR|seq
		0xC0 | (aSeq & 0x0F), // app control: FIR|FIN|seq
		aFunc,                // app function
	}
	app = append(app, objData...)

	length := dnp3MinLenByte + len(app)
	hdr := make([]byte, dnp3HeaderLen)
	hdr[0], hdr[1] = dnp3Start0, dnp3Start1
	hdr[2] = uint8(length)
	hdr[3] = ctrl
	binary.LittleEndian.PutUint16(hdr[4:6], dst)
	binary.LittleEndian.PutUint16(hdr[6:8], src)
	binary.LittleEndian.PutUint16(hdr[8:10], crcDNP(hdr[0:8]))
	return append(hdr, enblock(app)...)
}

func TestDNP3ParseRoundTrip(t *testing.T) {
	obj := []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x01} // arbitrary object block
	frame := buildDNP3(0x44, 0x0004, 0x0001, 9, 5, 0x01 /*READ*/, obj)

	d, n, err := ParseDNP3(frame)
	if err != nil {
		t.Fatalf("ParseDNP3: %v", err)
	}
	if n != len(frame) {
		t.Fatalf("consumed %d, frame is %d", n, len(frame))
	}
	if d.Dest != 0x0004 || d.Source != 0x0001 {
		t.Fatalf("addr wrong: dest=%#x src=%#x", d.Dest, d.Source)
	}
	if !d.HasTransport || d.TransportSeq != 9 || !d.TransportFIN || !d.TransportFIR {
		t.Fatalf("transport wrong: %+v", d)
	}
	if !d.HasApp || d.AppSeq != 5 || d.AppFunc != 0x01 {
		t.Fatalf("app wrong: seq=%d func=%#x", d.AppSeq, d.AppFunc)
	}

	// Re-encoding an unmodified frame must reproduce it exactly.
	if out := d.Encode(); !bytes.Equal(out, frame) {
		t.Fatalf("Encode round-trip mismatch:\n got %x\nwant %x", out, frame)
	}
}

// TestDNP3MaintainAppSeq bumps the app sequence number and checks the frame
// comes back with corrected CRCs.
func TestDNP3MaintainAppSeq(t *testing.T) {
	frame := buildDNP3(0x44, 0x0004, 0x0001, 1, 3, 0x01, []byte{0xAA})
	d, _, err := ParseDNP3(frame)
	if err != nil {
		t.Fatalf("ParseDNP3: %v", err)
	}
	d.AppSeq = (d.AppSeq + 1) & 0x0F
	d.TransportSeq = (d.TransportSeq + 1) & 0x3F
	out := d.Encode()

	re, _, err := ParseDNP3(out)
	if err != nil {
		t.Fatalf("re-parse after seq bump: %v", err) // fails if CRCs weren't fixed
	}
	if re.AppSeq != 4 || re.TransportSeq != 2 {
		t.Fatalf("seq not maintained: app=%d transport=%d", re.AppSeq, re.TransportSeq)
	}
}

func TestDNP3RejectsCorruptCRC(t *testing.T) {
	frame := buildDNP3(0x44, 0x0004, 0x0001, 0, 0, 0x01, []byte{0x01, 0x02})
	frame[len(frame)-1] ^= 0xFF // clobber the last block CRC
	if _, _, err := ParseDNP3(frame); err == nil {
		t.Fatal("expected block CRC mismatch to be rejected")
	}
}

func TestDNP3MultiBlockCRC(t *testing.T) {
	// >16 object bytes forces multiple CRC blocks, exercising de/re-blocking.
	obj := make([]byte, 40)
	for i := range obj {
		obj[i] = byte(i)
	}
	frame := buildDNP3(0x44, 0x000A, 0x0003, 12, 7, 0x81 /*RESPONSE*/, obj)
	d, n, err := ParseDNP3(frame)
	if err != nil || n != len(frame) {
		t.Fatalf("multi-block parse: err=%v n=%d/%d", err, n, len(frame))
	}
	if !bytes.Equal(d.Encode(), frame) {
		t.Fatal("multi-block Encode round-trip mismatch")
	}
}

func TestModbusParseAndLengthFixup(t *testing.T) {
	// Read Holding Registers request: txn=0x1234, unit=1, func=0x03, addr+qty.
	adu := []byte{
		0x12, 0x34, // transaction id
		0x00, 0x00, // protocol id (Modbus)
		0x00, 0x06, // length = unit + PDU (6)
		0x01,       // unit id
		0x03,       // function: read holding registers
		0x00, 0x6B, // starting address
		0x00, 0x03, // quantity
	}
	m, n, err := ParseMBAP(adu)
	if err != nil {
		t.Fatalf("ParseMBAP: %v", err)
	}
	if n != len(adu) {
		t.Fatalf("consumed %d, want %d", n, len(adu))
	}
	if m.TransactionID != 0x1234 || m.UnitID != 1 || m.Function != 0x03 {
		t.Fatalf("fields wrong: %+v", m)
	}

	// Mutate the PDU (append a byte) and confirm EncodeMBAP fixes Length.
	m.Data = append(m.Data, 0xFF)
	out := EncodeMBAP(m)
	got := binary.BigEndian.Uint16(out[4:6])
	if want := uint16(len(m.Data) + 2); got != want { // +func +unit
		t.Fatalf("length not fixed: got %d want %d", got, want)
	}
	if _, _, err := ParseMBAP(out); err != nil {
		t.Fatalf("re-parse after fixup: %v", err)
	}
}

func TestModbusPipelinedStream(t *testing.T) {
	one := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x01, 0x03, 0x00, 0x0A}
	two := []byte{0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x01, 0x01, 0x05}
	stream := append(append([]byte(nil), one...), two...)
	adus, leftover, err := ParseModbusStream(stream)
	if err != nil {
		t.Fatalf("ParseModbusStream: %v", err)
	}
	if leftover != 0 || len(adus) != 2 {
		t.Fatalf("expected 2 ADUs no leftover, got %d adus leftover=%d", len(adus), leftover)
	}
	if adus[0].TransactionID != 1 || adus[1].TransactionID != 2 {
		t.Fatalf("txn ids wrong: %d, %d", adus[0].TransactionID, adus[1].TransactionID)
	}
}

func TestModbusPartialTail(t *testing.T) {
	full := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x01, 0x03, 0x00, 0x0A}
	stream := append(append([]byte(nil), full...), 0x00, 0x02, 0x00) // partial 2nd ADU
	adus, leftover, err := ParseModbusStream(stream)
	if err != nil {
		t.Fatalf("unexpected error on partial tail: %v", err)
	}
	if len(adus) != 1 || leftover != 3 {
		t.Fatalf("expected 1 ADU + 3 leftover, got %d adus leftover=%d", len(adus), leftover)
	}
}
