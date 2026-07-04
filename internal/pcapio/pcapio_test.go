package pcapio

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/wire"
)

func TestClassicRoundTripNanos(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, wire.LinkEthernet, true)
	if err != nil {
		t.Fatal(err)
	}
	recs := []*Record{
		{Time: time.Unix(1600000000, 123456789).UTC(), Data: []byte("frame-one")},
		{Time: time.Unix(1600000001, 987654321).UTC(), Data: []byte("frame-two-longer")},
	}
	for _, r := range recs {
		if err := w.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	rd, err := NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !rd.Nanosecond() {
		t.Fatal("reader should report nanosecond resolution")
	}
	if rd.LinkType() != wire.LinkEthernet {
		t.Fatalf("link type = %d", rd.LinkType())
	}
	for i, want := range recs {
		got, err := rd.Read()
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if !got.Time.Equal(want.Time) {
			t.Fatalf("rec %d time = %v (ns=%d), want %v (ns=%d)",
				i, got.Time, got.Time.Nanosecond(), want.Time, want.Time.Nanosecond())
		}
		if !bytes.Equal(got.Data, want.Data) {
			t.Fatalf("rec %d data = %q, want %q", i, got.Data, want.Data)
		}
	}
	if _, err := rd.Read(); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestMicrosTruncation(t *testing.T) {
	// A microsecond file truncates the sub-microsecond part on write.
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, wire.LinkEthernet, false)
	w.Write(&Record{Time: time.Unix(10, 123456789).UTC(), Data: []byte("x")})
	w.Flush()
	rd, _ := NewReader(&buf)
	got, _ := rd.Read()
	if got.Time.Nanosecond() != 123456000 {
		t.Fatalf("micros nsec = %d, want 123456000", got.Time.Nanosecond())
	}
}

// buildMinimalPcapng assembles SHB + IDB(ns resolution) + one EPB in LE.
func buildMinimalPcapng(sec int64, nsec uint32, data []byte) []byte {
	le := binary.LittleEndian
	var out bytes.Buffer

	// SHB
	shb := make([]byte, 28)
	le.PutUint32(shb[0:4], ngBlockSHB)
	le.PutUint32(shb[4:8], 28)
	le.PutUint32(shb[8:12], ngByteMagic)
	le.PutUint16(shb[12:14], 1) // major
	le.PutUint16(shb[14:16], 0) // minor
	le.PutUint64(shb[16:24], 0xFFFFFFFFFFFFFFFF)
	le.PutUint32(shb[24:28], 28)
	out.Write(shb)

	// IDB with if_tsresol = 9 (10^-9)
	idb := make([]byte, 32)
	le.PutUint32(idb[0:4], ngBlockIDB)
	le.PutUint32(idb[4:8], 32)
	le.PutUint16(idb[8:10], uint16(wire.LinkEthernet))
	le.PutUint16(idb[10:12], 0)
	le.PutUint32(idb[12:16], 262144)
	le.PutUint16(idb[16:18], ngOptTSResol)
	le.PutUint16(idb[18:20], 1)
	idb[20] = 9 // decimal nanoseconds
	// idb[21:24] padding
	le.PutUint16(idb[24:26], 0) // opt_endofopt code
	le.PutUint16(idb[26:28], 0) // opt_endofopt len
	le.PutUint32(idb[28:32], 32)
	out.Write(idb)

	// EPB
	ticks := uint64(sec)*1_000_000_000 + uint64(nsec)
	dpad := (len(data) + 3) &^ 3
	total := 8 + 20 + dpad + 4
	epb := make([]byte, total)
	le.PutUint32(epb[0:4], ngBlockEPB)
	le.PutUint32(epb[4:8], uint32(total))
	le.PutUint32(epb[8:12], 0) // interface id
	le.PutUint32(epb[12:16], uint32(ticks>>32))
	le.PutUint32(epb[16:20], uint32(ticks&0xFFFFFFFF))
	le.PutUint32(epb[20:24], uint32(len(data)))
	le.PutUint32(epb[24:28], uint32(len(data)))
	copy(epb[28:28+len(data)], data)
	le.PutUint32(epb[total-4:total], uint32(total))
	out.Write(epb)

	return out.Bytes()
}

func TestPcapngRead(t *testing.T) {
	data := []byte{0xde, 0xad, 0xbe, 0xef}
	raw := buildMinimalPcapng(1600000000, 123456789, data)
	nr, err := NewNgReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := nr.Read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if rec.LinkType != wire.LinkEthernet {
		t.Fatalf("link = %d", rec.LinkType)
	}
	if rec.Time.Unix() != 1600000000 || rec.Time.Nanosecond() != 123456789 {
		t.Fatalf("time = %d.%09d", rec.Time.Unix(), rec.Time.Nanosecond())
	}
	if !bytes.Equal(rec.Data, data) {
		t.Fatalf("data = %x", rec.Data)
	}
	if nr.Mixed() {
		t.Fatal("single-interface file reported as mixed")
	}
	if _, err := nr.Read(); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}
