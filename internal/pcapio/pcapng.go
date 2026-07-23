package pcapio

import (
	"bufio"
	"encoding/binary"
	"io"
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
}

// NewNgReader parses the leading Section Header Block and returns a reader.
func NewNgReader(r io.Reader) (*NgReader, error) {
	br := bufio.NewReaderSize(r, 1<<16)
	nr := &NgReader{r: br, links: map[wire.LinkType]struct{}{}}
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
	if total < 12 {
		return nil, ErrTruncated
	}
	if _, err := io.ReadFull(br, make([]byte, total-12)); err != nil { // skip rest of SHB
		return nil, ErrTruncated
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
			return nil, err // io.EOF at a clean boundary
		}
		btype := nr.bo.Uint32(head[0:4])
		total := nr.bo.Uint32(head[4:8])
		if total < 12 {
			return nil, ErrTruncated
		}
		body := make([]byte, total-8) // body + trailing length word
		if _, err := io.ReadFull(nr.r, body); err != nil {
			return nil, ErrTruncated
		}
		body = body[:len(body)-4] // drop trailing block-total-length

		switch btype {
		case ngBlockSHB:
			// A new section resets interface numbering.
			nr.ifaces = nil
		case ngBlockIDB:
			nr.addIface(body)
		case ngBlockEPB:
			if rec := nr.readEPB(body); rec != nil {
				return rec, nil
			}
		case ngBlockSPB:
			if rec := nr.readSPB(body); rec != nil {
				return rec, nil
			}
		default:
			// Name-resolution, statistics, etc.: skip.
		}
	}
}

func (nr *NgReader) addIface(body []byte) {
	if len(body) < 8 {
		return
	}
	iface := ngIface{
		link:        wire.LinkType(nr.bo.Uint16(body[0:2])),
		snaplen:     nr.bo.Uint32(body[4:8]),
		ticksPerSec: 1_000_000, // default resolution 10^-6 s
	}
	// Parse options for if_tsresol.
	opt := body[8:]
	for len(opt) >= 4 {
		code := nr.bo.Uint16(opt[0:2])
		olen := int(nr.bo.Uint16(opt[2:4]))
		if code == 0 { // opt_endofopt
			break
		}
		if 4+olen > len(opt) {
			break
		}
		if code == ngOptTSResol && olen >= 1 {
			iface.ticksPerSec = tsresolToTicks(opt[4])
		}
		pad := (olen + 3) &^ 3
		opt = opt[4+pad:]
	}
	nr.ifaces = append(nr.ifaces, iface)
	nr.links[iface.link] = struct{}{}
}

// tsresolToTicks converts an if_tsresol byte to ticks-per-second.
func tsresolToTicks(b byte) uint64 {
	if b&0x80 != 0 { // binary: resolution 2^-(b&0x7f)
		return uint64(1) << (b & 0x7f)
	}
	// decimal: resolution 10^-b
	t := uint64(1)
	for i := byte(0); i < b; i++ {
		t *= 10
	}
	return t
}

func (nr *NgReader) readEPB(body []byte) *Record {
	if len(body) < 20 {
		return nil
	}
	ifaceID := nr.bo.Uint32(body[0:4])
	tsHigh := uint64(nr.bo.Uint32(body[4:8]))
	tsLow := uint64(nr.bo.Uint32(body[8:12]))
	capLen := int(nr.bo.Uint32(body[12:16]))
	origLen := int(nr.bo.Uint32(body[16:20]))
	if 20+capLen > len(body) {
		return nil
	}
	iface := nr.iface(ifaceID)
	data := make([]byte, capLen)
	copy(data, body[20:20+capLen])
	return &Record{
		Time:        ticksToTime(tsHigh<<32|tsLow, iface.ticksPerSec),
		CapLen:      capLen,
		OrigLen:     origLen,
		Data:        data,
		LinkType:    iface.link,
		InterfaceID: ifaceID,
	}
}

func (nr *NgReader) readSPB(body []byte) *Record {
	if len(body) < 4 {
		return nil
	}
	origLen := int(nr.bo.Uint32(body[0:4]))
	iface := nr.iface(0)
	capLen := origLen
	if avail := len(body) - 4; capLen > avail {
		capLen = avail
	}
	data := make([]byte, capLen)
	copy(data, body[4:4+capLen])
	return &Record{
		CapLen:   capLen,
		OrigLen:  origLen,
		Data:     data,
		LinkType: iface.link,
	}
}

func (nr *NgReader) iface(id uint32) ngIface {
	if int(id) < len(nr.ifaces) {
		return nr.ifaces[id]
	}
	return ngIface{link: wire.LinkEthernet, ticksPerSec: 1_000_000}
}

// ticksToTime converts a tick count at the given resolution to UTC, using 128-bit
// integer math to keep nanoseconds exact.
func ticksToTime(ticks, ticksPerSec uint64) time.Time {
	if ticksPerSec == 0 {
		ticksPerSec = 1_000_000
	}
	secs := ticks / ticksPerSec
	rem := ticks % ticksPerSec
	hi, lo := bits.Mul64(rem, 1_000_000_000)
	nsec, _ := bits.Div64(hi, lo, ticksPerSec)
	return time.Unix(int64(secs), int64(nsec)).UTC()
}
