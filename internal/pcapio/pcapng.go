package pcapio

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/bits"
	"time"

	"github.com/kvmukilan/livewire/internal/wire"
)

// pcapng block types (PCAP Next Generation spec).
const (
	ngBlockSHB   = 0x0A0D0D0A // Section Header Block
	ngBlockIDB   = 0x00000001 // Interface Description Block
	ngBlockSPB   = 0x00000003 // Simple Packet Block
	ngBlockEPB   = 0x00000006 // Enhanced Packet Block
	ngByteMagic  = 0x1A2B3C4D
	ngOptTSResol = 9 // if_tsresol option code in an IDB
)

type ngIface struct {
	link        wire.LinkType
	ticksPerSec uint64
	snaplen     uint32
}

// NgReader streams records from a pcapng file, tracking per-interface link type
// and timestamp resolution.
type NgReader struct {
	r      *bufio.Reader
	bo     binary.ByteOrder
	ifaces []ngIface
	links  map[wire.LinkType]struct{}
	limits Limits
}

// NewNgReader parses the leading Section Header Block and returns a reader.
func NewNgReader(r io.Reader) (*NgReader, error) {
	return NewNgReaderWithLimits(r, DefaultLimits())
}

// NewNgReaderWithLimits parses the leading section with explicit safety bounds.
func NewNgReaderWithLimits(r io.Reader, limits Limits) (*NgReader, error) {
	limits = limits.normalized()
	br := bufio.NewReaderSize(r, 1<<16)
	nr := &NgReader{r: br, links: map[wire.LinkType]struct{}{}, limits: limits}
	// The first block must be an SHB. Read type(4)+len(4)+bom(4) to fix byte order.
	head := make([]byte, 12)
	if _, err := io.ReadFull(br, head); err != nil {
		return nil, err
	}
	if binary.LittleEndian.Uint32(head[0:4]) != ngBlockSHB {
		return nil, ErrBadMagic
	}
	switch {
	case binary.LittleEndian.Uint32(head[8:12]) == ngByteMagic:
		nr.bo = binary.LittleEndian
	case binary.BigEndian.Uint32(head[8:12]) == ngByteMagic:
		nr.bo = binary.BigEndian
	default:
		return nil, ErrBadMagic
	}
	total := nr.bo.Uint32(head[4:8])
	if total < 28 || total%4 != 0 {
		return nil, fmt.Errorf("%w: invalid section block length %d", ErrInvalid, total)
	}
	if uint64(total) > uint64(limits.MaxRecordBytes) {
		return nil, fmt.Errorf("%w: section block length %d", ErrLimit, total)
	}
	rest := make([]byte, int(total)-12)
	if _, err := io.ReadFull(br, rest); err != nil { // skip rest of SHB
		return nil, ErrTruncated
	}
	if nr.bo.Uint32(rest[len(rest)-4:]) != total {
		return nil, fmt.Errorf("%w: section block length footer mismatch", ErrInvalid)
	}
	return nr, nil
}

// LinkType returns the link type of the first interface (the flatten target).
func (nr *NgReader) LinkType() wire.LinkType {
	if len(nr.ifaces) == 0 {
		return wire.LinkEthernet
	}
	return nr.ifaces[0].link
}

// Mixed reports whether the file declares interfaces of differing link types,
// which cannot be flattened into a single classic pcap.
func (nr *NgReader) Mixed() bool { return len(nr.links) > 1 }

// Read returns the next packet record, skipping non-packet blocks, or io.EOF.
func (nr *NgReader) Read() (*Record, error) {
	for {
		head := make([]byte, 8)
		if _, err := io.ReadFull(nr.r, head); err != nil {
			if err == io.EOF {
				return nil, io.EOF
			}
			return nil, ErrTruncated
		}
		btype := nr.bo.Uint32(head[0:4])
		total := nr.bo.Uint32(head[4:8])
		if total < 12 || total%4 != 0 {
			return nil, fmt.Errorf("%w: invalid block length %d", ErrInvalid, total)
		}
		if uint64(total) > uint64(nr.limits.MaxRecordBytes) {
			return nil, fmt.Errorf("%w: block length %d", ErrLimit, total)
		}
		body := make([]byte, int(total)-8) // body + trailing length word
		if _, err := io.ReadFull(nr.r, body); err != nil {
			return nil, ErrTruncated
		}
		if nr.bo.Uint32(body[len(body)-4:]) != total {
			return nil, fmt.Errorf("%w: block length footer mismatch", ErrInvalid)
		}
		body = body[:len(body)-4]

		switch btype {
		case ngBlockSHB:
			if total < 28 || len(body) < 16 || nr.bo.Uint32(body[:4]) != ngByteMagic {
				return nil, fmt.Errorf("%w: invalid additional section header", ErrInvalid)
			}
			// A new same-endian section resets interface numbering. Cross-endian
			// sections are rejected rather than being interpreted with stale order.
			nr.ifaces = nil
			nr.links = map[wire.LinkType]struct{}{}
		case ngBlockIDB:
			if err := nr.addIface(body); err != nil {
				return nil, err
			}
		case ngBlockEPB:
			return nr.readEPB(body)
		case ngBlockSPB:
			return nr.readSPB(body)
		default:
			// Name-resolution, statistics, etc.: skip.
		}
	}
}

func (nr *NgReader) addIface(body []byte) error {
	if len(body) < 8 {
		return fmt.Errorf("%w: truncated interface block", ErrInvalid)
	}
	iface := ngIface{
		link:        wire.LinkType(nr.bo.Uint16(body[0:2])),
		snaplen:     nr.bo.Uint32(body[4:8]),
		ticksPerSec: 1_000_000, // default resolution 10^-6 s
	}
	if iface.snaplen == 0 || uint64(iface.snaplen) > uint64(nr.limits.MaxRecordBytes) {
		return fmt.Errorf("%w: interface snaplen %d", ErrLimit, iface.snaplen)
	}
	// Parse options for if_tsresol.
	opt := body[8:]
	for len(opt) >= 4 {
		code := nr.bo.Uint16(opt[0:2])
		olen := int(nr.bo.Uint16(opt[2:4]))
		if code == 0 { // opt_endofopt
			if olen != 0 {
				return fmt.Errorf("%w: invalid end-of-options length", ErrInvalid)
			}
			for _, padding := range opt[4:] {
				if padding != 0 {
					return fmt.Errorf("%w: nonzero bytes after end-of-options", ErrInvalid)
				}
			}
			opt = nil
			break
		}
		if 4+olen > len(opt) {
			return fmt.Errorf("%w: truncated interface option", ErrInvalid)
		}
		if code == ngOptTSResol && olen >= 1 {
			ticks, ok := tsresolToTicks(opt[4])
			if !ok {
				return fmt.Errorf("%w: unsupported timestamp resolution", ErrInvalid)
			}
			iface.ticksPerSec = ticks
		}
		pad := (olen + 3) &^ 3
		if 4+pad > len(opt) {
			return fmt.Errorf("%w: misaligned interface option", ErrInvalid)
		}
		opt = opt[4+pad:]
	}
	if len(opt) != 0 {
		return fmt.Errorf("%w: truncated interface option header", ErrInvalid)
	}
	nr.ifaces = append(nr.ifaces, iface)
	nr.links[iface.link] = struct{}{}
	return nil
}

// tsresolToTicks converts an if_tsresol byte to ticks-per-second.
func tsresolToTicks(b byte) (uint64, bool) {
	if b&0x80 != 0 { // binary: resolution 2^-(b&0x7f)
		n := b & 0x7f
		if n >= 64 {
			return 0, false
		}
		return uint64(1) << n, true
	}
	// decimal: resolution 10^-b
	t := uint64(1)
	for i := byte(0); i < b; i++ {
		if t > math.MaxUint64/10 {
			return 0, false
		}
		t *= 10
	}
	return t, true
}

func (nr *NgReader) readEPB(body []byte) (*Record, error) {
	if len(body) < 20 {
		return nil, fmt.Errorf("%w: truncated enhanced packet block", ErrInvalid)
	}
	ifaceID := nr.bo.Uint32(body[0:4])
	tsHigh := uint64(nr.bo.Uint32(body[4:8]))
	tsLow := uint64(nr.bo.Uint32(body[8:12]))
	capRaw := nr.bo.Uint32(body[12:16])
	origRaw := nr.bo.Uint32(body[16:20])
	if uint64(capRaw) > uint64(nr.limits.MaxRecordBytes) {
		return nil, fmt.Errorf("%w: captured length %d", ErrLimit, capRaw)
	}
	capLen, origLen := int(capRaw), int(origRaw)
	if origLen < capLen || 20+capLen > len(body) {
		return nil, fmt.Errorf("%w: invalid enhanced packet lengths", ErrInvalid)
	}
	iface := nr.iface(ifaceID)
	if ifaceID >= uint32(len(nr.ifaces)) || capRaw > iface.snaplen {
		return nil, fmt.Errorf("%w: invalid interface %d or snaplen", ErrInvalid, ifaceID)
	}
	data := make([]byte, capLen)
	copy(data, body[20:20+capLen])
	tm, err := ticksToTime(tsHigh<<32|tsLow, iface.ticksPerSec)
	if err != nil {
		return nil, err
	}
	return &Record{
		Time:        tm,
		CapLen:      capLen,
		OrigLen:     origLen,
		Data:        data,
		LinkType:    iface.link,
		InterfaceID: ifaceID,
	}, nil
}

func (nr *NgReader) readSPB(body []byte) (*Record, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("%w: truncated simple packet block", ErrInvalid)
	}
	origLen := int(nr.bo.Uint32(body[0:4]))
	iface := nr.iface(0)
	capLen := origLen
	if capLen > int(iface.snaplen) {
		capLen = int(iface.snaplen)
	}
	if capLen > nr.limits.MaxRecordBytes || capLen < 0 || capLen > len(body)-4 {
		return nil, fmt.Errorf("%w: invalid simple packet length", ErrInvalid)
	}
	data := make([]byte, capLen)
	copy(data, body[4:4+capLen])
	return &Record{
		CapLen:   capLen,
		OrigLen:  origLen,
		Data:     data,
		LinkType: iface.link,
	}, nil
}

func (nr *NgReader) iface(id uint32) ngIface {
	if int(id) < len(nr.ifaces) {
		return nr.ifaces[id]
	}
	return ngIface{link: wire.LinkEthernet, ticksPerSec: 1_000_000}
}

// ticksToTime converts a tick count at the given resolution to UTC, using 128-bit
// integer math to keep nanoseconds exact.
func ticksToTime(ticks, ticksPerSec uint64) (time.Time, error) {
	if ticksPerSec == 0 {
		ticksPerSec = 1_000_000
	}
	secs := ticks / ticksPerSec
	if secs > math.MaxInt64 {
		return time.Time{}, fmt.Errorf("%w: timestamp overflows time.Time", ErrInvalid)
	}
	rem := ticks % ticksPerSec
	hi, lo := bits.Mul64(rem, 1_000_000_000)
	nsec, _ := bits.Div64(hi, lo, ticksPerSec)
	return time.Unix(int64(secs), int64(nsec)).UTC(), nil
}
