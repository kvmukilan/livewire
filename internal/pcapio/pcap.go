package pcapio

import (
	"bufio"
	"encoding/binary"
	"io"
	"time"

	"github.com/kvmukilan/livewire/internal/wire"
)

// Classic pcap magic numbers; the nanos variant only changes how the fractional
// timestamp is read.
const (
	magicMicros = 0xa1b2c3d4
	magicNanos  = 0xa1b23c4d
)

// Reader streams records from a classic pcap file.
type Reader struct {
	r        *bufio.Reader
	bo       binary.ByteOrder
	nanos    bool
	linkType wire.LinkType
	snaplen  uint32
}

// NewReader reads the 24-byte global header and returns a streaming Reader.
func NewReader(r io.Reader) (*Reader, error) {
	br := bufio.NewReaderSize(r, 1<<16)
	hdr := make([]byte, 24)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, err
	}
	rd := &Reader{r: br}
	switch m := binary.LittleEndian.Uint32(hdr[0:4]); m {
	case magicMicros:
		rd.bo, rd.nanos = binary.LittleEndian, false
	case magicNanos:
		rd.bo, rd.nanos = binary.LittleEndian, true
	default:
		switch binary.BigEndian.Uint32(hdr[0:4]) {
		case magicMicros:
			rd.bo, rd.nanos = binary.BigEndian, false
		case magicNanos:
			rd.bo, rd.nanos = binary.BigEndian, true
		default:
			return nil, ErrBadMagic
		}
	}
	rd.snaplen = rd.bo.Uint32(hdr[16:20])
	rd.linkType = wire.LinkType(rd.bo.Uint32(hdr[20:24]))
	return rd, nil
}

// LinkType returns the capture's link-layer type.
func (r *Reader) LinkType() wire.LinkType { return r.linkType }

// Nanosecond reports whether the source carried nanosecond-resolution stamps.
func (r *Reader) Nanosecond() bool { return r.nanos }

// Read returns the next record, or io.EOF when the file is exhausted.
func (r *Reader) Read() (*Record, error) {
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(r.r, hdr); err != nil {
		return nil, err // io.EOF at a clean record boundary
	}
	tsSec := r.bo.Uint32(hdr[0:4])
	tsFrac := r.bo.Uint32(hdr[4:8])
	capLen := r.bo.Uint32(hdr[8:12])
	origLen := r.bo.Uint32(hdr[12:16])

	nsec := int64(tsFrac)
	if !r.nanos {
		nsec *= 1000
	}
	data := make([]byte, capLen)
	if _, err := io.ReadFull(r.r, data); err != nil {
		return nil, ErrTruncated
	}
	return &Record{
		Time:     time.Unix(int64(tsSec), nsec).UTC(),
		CapLen:   int(capLen),
		OrigLen:  int(origLen),
		Data:     data,
		LinkType: r.linkType,
	}, nil
}

// Writer streams records to a classic pcap file.
type Writer struct {
	w     *bufio.Writer
	bo    binary.ByteOrder
	nanos bool
}

// NewWriter writes a global header and returns a streaming Writer. Set nanos to
// emit nanosecond-resolution timestamps (magic 0xa1b23c4d).
func NewWriter(w io.Writer, link wire.LinkType, nanos bool) (*Writer, error) {
	bw := bufio.NewWriterSize(w, 1<<16)
	hdr := make([]byte, 24)
	bo := binary.LittleEndian
	if nanos {
		bo.PutUint32(hdr[0:4], magicNanos)
	} else {
		bo.PutUint32(hdr[0:4], magicMicros)
	}
	bo.PutUint16(hdr[4:6], 2)        // version major
	bo.PutUint16(hdr[6:8], 4)        // version minor
	bo.PutUint32(hdr[16:20], 262144) // snaplen
	bo.PutUint32(hdr[20:24], uint32(link))
	if _, err := bw.Write(hdr); err != nil {
		return nil, err
	}
	return &Writer{w: bw, bo: bo, nanos: nanos}, nil
}

// Write appends one record.
func (w *Writer) Write(rec *Record) error {
	hdr := make([]byte, 16)
	w.bo.PutUint32(hdr[0:4], uint32(rec.Time.Unix()))
	frac := uint32(rec.Time.Nanosecond())
	if !w.nanos {
		frac /= 1000
	}
	w.bo.PutUint32(hdr[4:8], frac)
	capLen := rec.CapLen
	if capLen == 0 {
		capLen = len(rec.Data)
	}
	origLen := rec.OrigLen
	if origLen == 0 {
		origLen = capLen
	}
	w.bo.PutUint32(hdr[8:12], uint32(capLen))
	w.bo.PutUint32(hdr[12:16], uint32(origLen))
	if _, err := w.w.Write(hdr); err != nil {
		return err
	}
	_, err := w.w.Write(rec.Data)
	return err
}

// Flush flushes buffered output; call before closing the underlying file.
func (w *Writer) Flush() error { return w.w.Flush() }
