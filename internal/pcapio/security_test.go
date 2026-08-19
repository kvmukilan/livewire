package pcapio

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/wire"
)

func classicHeader(snaplen uint32) []byte {
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h[0:4], magicMicros)
	binary.LittleEndian.PutUint16(h[4:6], 2)
	binary.LittleEndian.PutUint16(h[6:8], 4)
	binary.LittleEndian.PutUint32(h[16:20], snaplen)
	binary.LittleEndian.PutUint32(h[20:24], uint32(wire.LinkEthernet))
	return h
}

func TestClassicVariantsAndStrictTruncation(t *testing.T) {
	be := make([]byte, 24)
	binary.BigEndian.PutUint32(be[0:4], magicMicros)
	binary.BigEndian.PutUint16(be[4:6], 2)
	binary.BigEndian.PutUint16(be[6:8], 4)
	binary.BigEndian.PutUint32(be[16:20], 64)
	binary.BigEndian.PutUint32(be[20:24], uint32(wire.LinkRaw))
	r, err := NewReader(bytes.NewReader(be))
	if err != nil || r.LinkType() != wire.LinkRaw || r.Nanosecond() {
		t.Fatalf("big-endian reader=%v err=%v", r, err)
	}
	if _, err := NewReader(bytes.NewReader(make([]byte, 24))); !errors.Is(err, ErrBadMagic) {
		t.Fatalf("bad magic error=%v", err)
	}
	truncated := append(classicHeader(64), make([]byte, 7)...)
	r, err = NewReader(bytes.NewReader(truncated))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read(); !errors.Is(err, ErrTruncated) {
		t.Fatalf("truncated record error=%v", err)
	}
}

func TestClassicReaderRejectsLengthsBeforeAllocation(t *testing.T) {
	t.Run("oversized snaplen", func(t *testing.T) {
		_, err := NewReaderWithLimits(bytes.NewReader(classicHeader(4096)), Limits{MaxRecordBytes: 1024})
		if !errors.Is(err, ErrLimit) {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("caplen exceeds snaplen", func(t *testing.T) {
		raw := classicHeader(128)
		record := make([]byte, 16)
		binary.LittleEndian.PutUint32(record[8:12], ^uint32(0))
		binary.LittleEndian.PutUint32(record[12:16], ^uint32(0))
		raw = append(raw, record...)
		r, err := NewReader(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Read(); !errors.Is(err, ErrLimit) {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("invalid timestamp fraction", func(t *testing.T) {
		raw := classicHeader(128)
		record := make([]byte, 16)
		binary.LittleEndian.PutUint32(record[4:8], 1_000_000)
		raw = append(raw, record...)
		r, _ := NewReader(bytes.NewReader(raw))
		if _, err := r.Read(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestPCAPNGRejectsOversizedAndMismatchedBlocks(t *testing.T) {
	head := make([]byte, 12)
	binary.LittleEndian.PutUint32(head[0:4], ngBlockSHB)
	binary.LittleEndian.PutUint32(head[4:8], 1<<30)
	binary.LittleEndian.PutUint32(head[8:12], ngByteMagic)
	if _, err := NewNgReader(bytes.NewReader(head)); !errors.Is(err, ErrLimit) {
		t.Fatalf("oversized error=%v", err)
	}

	shb := make([]byte, 28)
	binary.LittleEndian.PutUint32(shb[0:4], ngBlockSHB)
	binary.LittleEndian.PutUint32(shb[4:8], 28)
	binary.LittleEndian.PutUint32(shb[8:12], ngByteMagic)
	binary.LittleEndian.PutUint32(shb[24:28], 24)
	if _, err := NewNgReader(bytes.NewReader(shb)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("footer error=%v", err)
	}
}

func TestLoadEnforcesCountAndTotalData(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, wire.LinkEthernet, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := w.Write(&Record{Time: time.Unix(1, 0), Data: []byte{1, 2, 3}, CapLen: 3, OrigLen: 3}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bytes.NewReader(buf.Bytes()), Limits{MaxRecords: 1}); !errors.Is(err, ErrLimit) {
		t.Fatalf("count error=%v", err)
	}
	if _, err := Load(bytes.NewReader(buf.Bytes()), Limits{MaxCaptureData: 5}); !errors.Is(err, ErrLimit) {
		t.Fatalf("data error=%v", err)
	}
}

func TestWriterRejectsLengthMismatch(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, wire.LinkEthernet, true)
	err := w.Write(&Record{Time: time.Unix(1, 0), Data: []byte{1, 2, 3}, CapLen: 2, OrigLen: 3})
	if err == nil {
		t.Fatal("writer accepted a mismatched captured length")
	}
}

type shortOutput struct{ remaining int }

func (w *shortOutput) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, io.ErrShortWrite
	}
	if len(p) > w.remaining {
		n := w.remaining
		w.remaining = 0
		return n, io.ErrShortWrite
	}
	w.remaining -= len(p)
	return len(p), nil
}

func TestWritersPropagateShortWriteOnFlush(t *testing.T) {
	classicOut := &shortOutput{remaining: 10}
	classic, err := NewWriter(classicOut, wire.LinkEthernet, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := classic.Write(&Record{Time: time.Unix(1, 0), Data: []byte("packet"), CapLen: 6, OrigLen: 6}); err != nil {
		t.Fatal(err)
	}
	if err := classic.Flush(); err == nil {
		t.Fatal("classic writer hid short output")
	}

	ngOut := &shortOutput{remaining: 10}
	ng, err := NewNgWriter(ngOut, []NgInterface{{LinkType: wire.LinkEthernet}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ng.Write(&Record{Time: time.Unix(1, 0), Data: []byte("packet"), CapLen: 6, OrigLen: 6}); err != nil {
		t.Fatal(err)
	}
	if err := ng.Flush(); err == nil {
		t.Fatal("pcapng writer hid short output")
	}
}

func TestPcapngSimplePacketAndWriterValidation(t *testing.T) {
	prefix := buildMinimalPcapng(1, 0, []byte{1})[:60]
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body[:4], 3)
	copy(body[4:], []byte{1, 2, 3})
	raw := append(prefix, ngTestBlock(ngBlockSPB, body)...)
	r, err := NewNgReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := r.Read()
	if err != nil || !bytes.Equal(rec.Data, []byte{1, 2, 3}) || rec.OrigLen != 3 {
		t.Fatalf("simple record=%+v err=%v", rec, err)
	}

	if _, err := NewNgWriter(io.Discard, nil); err == nil {
		t.Fatal("pcapng writer accepted no interfaces")
	}
	w, err := NewNgWriter(io.Discard, []NgInterface{{LinkType: wire.LinkEthernet}})
	if err != nil {
		t.Fatal(err)
	}
	bad := []*Record{
		nil,
		{InterfaceID: 2},
		{Data: []byte{1, 2}, CapLen: 1},
		{Data: []byte{1}, OrigLen: -1},
		{Time: time.Unix(-1, 0), Data: []byte{1}},
	}
	for i, record := range bad {
		if err := w.Write(record); err == nil {
			t.Fatalf("invalid record %d accepted", i)
		}
	}
}

func TestLoadFileAndPcapngMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.pcapng")
	if err := os.WriteFile(path, buildMinimalPcapng(2, 3, []byte("packet")), 0o600); err != nil {
		t.Fatal(err)
	}
	capture, err := LoadFile(path, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !capture.PCAPNG || !capture.Nanosecond || capture.MixedLinks || capture.PrimaryLink != wire.LinkEthernet || len(capture.Records) != 1 {
		t.Fatalf("capture=%+v", capture)
	}
}

func TestPcapngRejectsMalformedPacketMetadata(t *testing.T) {
	prefix := buildMinimalPcapng(1, 0, []byte{1})[:60]
	cases := [][]byte{
		ngTestBlock(ngBlockEPB, make([]byte, 8)),
		ngTestBlock(ngBlockSPB, nil),
	}
	badIface := make([]byte, 20)
	binary.LittleEndian.PutUint32(badIface[0:4], 4)
	cases = append(cases, ngTestBlock(ngBlockEPB, badIface))
	for i, block := range cases {
		r, err := NewNgReader(bytes.NewReader(append(append([]byte(nil), prefix...), block...)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Read(); err == nil {
			t.Fatalf("malformed packet %d accepted", i)
		}
	}
}

func TestPcapngRejectsMalformedSectionsAndOptionAlignment(t *testing.T) {
	prefix := buildMinimalPcapng(1, 0, []byte{1})[:60]
	shortSection := ngTestBlock(ngBlockSHB, []byte{0x4d, 0x3c, 0x2b, 0x1a})
	r, err := NewNgReader(bytes.NewReader(append(append([]byte(nil), prefix...), shortSection...)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short section error=%v", err)
	}

	shb := buildMinimalPcapng(1, 0, []byte{1})[:28]
	idbBody := make([]byte, 12)
	binary.LittleEndian.PutUint16(idbBody[0:2], uint16(wire.LinkEthernet))
	binary.LittleEndian.PutUint32(idbBody[4:8], 65535)
	binary.LittleEndian.PutUint16(idbBody[8:10], ngOptTSResol)
	binary.LittleEndian.PutUint16(idbBody[10:12], 5) // value and padding are absent
	malformed := append(shb, ngTestBlock(ngBlockIDB, idbBody)...)
	r, err = NewNgReader(bytes.NewReader(malformed))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("misaligned option error=%v", err)
	}
}

func ngTestBlock(kind uint32, body []byte) []byte {
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	total := 12 + len(body)
	out := make([]byte, total)
	binary.LittleEndian.PutUint32(out[0:4], kind)
	binary.LittleEndian.PutUint32(out[4:8], uint32(total))
	copy(out[8:], body)
	binary.LittleEndian.PutUint32(out[total-4:], uint32(total))
	return out
}
