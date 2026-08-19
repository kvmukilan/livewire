package pcapio

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/kvmukilan/livewire/internal/wire"
)

const (
	defaultMaxRecordBytes = 16 << 20
	defaultMaxCaptureData = 512 << 20
	defaultMaxRecords     = 1_000_000
)

// Limits bounds work performed while parsing an untrusted capture. Zero values
// select the conservative defaults used by the CLI and dashboard.
type Limits struct {
	MaxRecordBytes int
	MaxCaptureData int64
	MaxRecords     int
}

// DefaultLimits returns the production limits for untrusted capture input.
func DefaultLimits() Limits {
	return Limits{
		MaxRecordBytes: defaultMaxRecordBytes,
		MaxCaptureData: defaultMaxCaptureData,
		MaxRecords:     defaultMaxRecords,
	}
}

func (l Limits) normalized() Limits {
	d := DefaultLimits()
	if l.MaxRecordBytes > 0 {
		d.MaxRecordBytes = l.MaxRecordBytes
	}
	if l.MaxCaptureData > 0 {
		d.MaxCaptureData = l.MaxCaptureData
	}
	if l.MaxRecords > 0 {
		d.MaxRecords = l.MaxRecords
	}
	return d
}

// Capture contains a strictly loaded capture and its source metadata.
type Capture struct {
	Records     []*Record
	Nanosecond  bool
	PCAPNG      bool
	MixedLinks  bool
	PrimaryLink wire.LinkType
}

type recordReader interface {
	Read() (*Record, error)
	LinkType() wire.LinkType
}

// LoadFile strictly loads a classic pcap or pcapng file. It never treats a
// malformed trailing record as EOF and bounds both record count and data held.
func LoadFile(path string, limits Limits) (capture Capture, retErr error) {
	f, err := os.Open(path)
	if err != nil {
		return Capture{}, err
	}
	defer func() { retErr = errors.Join(retErr, f.Close()) }()
	return Load(f, limits)
}

// Load strictly loads a capture from r.
func Load(r io.Reader, limits Limits) (Capture, error) {
	limits = limits.normalized()
	br := bufio.NewReaderSize(r, 1<<16)
	magic, err := br.Peek(4)
	if err != nil {
		return Capture{}, err
	}
	var rd recordReader
	out := Capture{}
	if binary.LittleEndian.Uint32(magic) == ngBlockSHB {
		nr, err := NewNgReaderWithLimits(br, limits)
		if err != nil {
			return Capture{}, err
		}
		rd, out.Nanosecond, out.PCAPNG = nr, true, true
	} else {
		pr, err := NewReaderWithLimits(br, limits)
		if err != nil {
			return Capture{}, err
		}
		rd, out.Nanosecond = pr, pr.Nanosecond()
	}
	var total int64
	for {
		rec, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Capture{}, err
		}
		if len(out.Records) >= limits.MaxRecords {
			return Capture{}, fmt.Errorf("%w: record count exceeds %d", ErrLimit, limits.MaxRecords)
		}
		if int64(len(rec.Data)) > limits.MaxCaptureData-total {
			return Capture{}, fmt.Errorf("%w: decoded packet data exceeds %d bytes", ErrLimit, limits.MaxCaptureData)
		}
		total += int64(len(rec.Data))
		out.Records = append(out.Records, rec)
	}
	out.PrimaryLink = rd.LinkType()
	if nr, ok := rd.(*NgReader); ok {
		out.MixedLinks = nr.Mixed()
	}
	return out, nil
}
