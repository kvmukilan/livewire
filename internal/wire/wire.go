// Package wire parses and edits Ethernet/IPv4/IPv6/TCP/UDP frames over a byte
// buffer, with no external deps. Parsing records offsets; edits write through
// the buffer. Length-changing edits (VLAN push/pop, DLT conversion) return a
// new buffer.
package wire

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/kvmukilan/livewire/internal/units"
)

// LinkType mirrors the libpcap DLT values the tool understands.
type LinkType uint16

const (
	LinkNull     LinkType = 0   // DLT_NULL: 4-byte host-order address family, then IP
	LinkEthernet LinkType = 1   // DLT_EN10MB
	LinkRaw      LinkType = 101 // DLT_RAW: bare IP, version from first nibble
	LinkLinuxSLL LinkType = 113 // DLT_LINUX_SLL: 16-byte cooked header
	LinkLoop     LinkType = 108 // DLT_LOOP: like NULL but network-order family
)

// EtherType values.
const (
	etherIPv4 uint16 = 0x0800
	etherIPv6 uint16 = 0x86DD
	etherVLAN uint16 = 0x8100
	etherQinQ uint16 = 0x88A8
	etherARP  uint16 = 0x0806
)

// IP protocol numbers.
const (
	ProtoICMPv4 uint8 = 1
	ProtoTCP    uint8 = 6
	ProtoUDP    uint8 = 17
	ProtoICMPv6 uint8 = 58
)

// IPv6 extension-header next-header values, skipped when locating L4.
const (
	ext6HopByHop  uint8 = 0
	ext6Routing   uint8 = 43
	ext6Fragment  uint8 = 44
	ext6DestOpts  uint8 = 60
	ext6AH        uint8 = 51
	ext6NoNextHdr uint8 = 59
)

// TCP flag bits (byte 13 of the TCP header).
const (
	FlagFIN uint8 = 1 << 0
	FlagSYN uint8 = 1 << 1
	FlagRST uint8 = 1 << 2
	FlagPSH uint8 = 1 << 3
	FlagACK uint8 = 1 << 4
	FlagURG uint8 = 1 << 5
	FlagECE uint8 = 1 << 6
	FlagCWR uint8 = 1 << 7
)

// Parse errors.
var (
	ErrShort       = errors.New("wire: buffer too short")
	ErrUnsupported = errors.New("wire: unsupported link or protocol")
	ErrNotIP       = errors.New("wire: not an IP packet")
)

// Packet is a parsed, editable view over a frame buffer.
type Packet struct {
	Buf  []byte
	Link LinkType

	// Layer 2 (Ethernet-family only).
	hasEth    bool
	etherType uint16 // innermost ethertype
	vlanTCI   []int  // buffer offsets of each 802.1Q/QinQ TCI field

	// Layer 3.
	l3Off            int
	l3HdrLn          int
	isV4             bool
	isV6             bool
	proto            uint8
	frag6            bool
	frag6Off         int
	frag6PrevNextOff int
	frag6Offset      int
	frag6More        bool
	frag6ID          uint32
	frag6Next        uint8

	// Layer 4.
	l4Off      int
	l4HdrLn    int
	l4TotalLen int // L4 header+payload per IP length fields, clamped to buffer
	payloadOff int
	payloadLen int
	isTCP      bool
	isUDP      bool
	isICMP     bool
}

// Parse decodes buf per link. The returned Packet aliases buf.
func Parse(buf []byte, link LinkType) (*Packet, error) {
	p := &Packet{Buf: buf, Link: link}
	l3Off, etherType, err := p.parseL2(link)
	if err != nil {
		return nil, err
	}
	p.etherType = etherType
	p.l3Off = l3Off
	if err := p.parseL3(); err != nil {
		return nil, err
	}
	if err := p.parseL4(); err != nil {
		return nil, err
	}
	return p, nil
}

// parseL2 returns the L3 offset and ethertype for the frame.
func (p *Packet) parseL2(link LinkType) (int, uint16, error) {
	switch link {
	case LinkEthernet:
		p.hasEth = true
		if len(p.Buf) < 14 {
			return 0, 0, ErrShort
		}
		et := binary.BigEndian.Uint16(p.Buf[12:14])
		off := 14
		for et == etherVLAN || et == etherQinQ {
			if len(p.Buf) < off+4 {
				return 0, 0, ErrShort
			}
			p.vlanTCI = append(p.vlanTCI, off) // TCI is the 2 bytes at off
			et = binary.BigEndian.Uint16(p.Buf[off+2 : off+4])
			off += 4
		}
		return off, et, nil
	case LinkRaw:
		if len(p.Buf) < 1 {
			return 0, 0, ErrShort
		}
		return 0, ipVersionEtherType(p.Buf[0] >> 4), nil
	case LinkNull, LinkLoop:
		if len(p.Buf) < 4 {
			return 0, 0, ErrShort
		}
		var fam uint32
		if link == LinkNull {
			fam = binary.LittleEndian.Uint32(p.Buf[0:4])
		} else {
			fam = binary.BigEndian.Uint32(p.Buf[0:4])
		}
		et := etherIPv4
		if fam != 2 { // AF_INET==2 everywhere; anything else here is IPv6 family
			et = etherIPv6
		}
		return 4, et, nil
	case LinkLinuxSLL:
		if len(p.Buf) < 16 {
			return 0, 0, ErrShort
		}
		return 16, binary.BigEndian.Uint16(p.Buf[14:16]), nil
	default:
		return 0, 0, ErrUnsupported
	}
}

func ipVersionEtherType(ver byte) uint16 {
	if ver == 6 {
		return etherIPv6
	}
	return etherIPv4
}

func (p *Packet) parseL3() error {
	switch p.etherType {
	case etherIPv4:
		return p.parseIPv4()
	case etherIPv6:
		return p.parseIPv6()
	default:
		return ErrNotIP
	}
}

func (p *Packet) parseIPv4() error {
	b := p.Buf
	o := p.l3Off
	if len(b) < o+20 {
		return ErrShort
	}
	if b[o]>>4 != 4 {
		return ErrNotIP
	}
	ihl := int(b[o]&0x0f) * 4
	if ihl < 20 || len(b) < o+ihl {
		return ErrShort
	}
	p.isV4 = true
	p.l3HdrLn = ihl
	p.proto = b[o+9]
	return nil
}

func (p *Packet) parseIPv6() error {
	b := p.Buf
	o := p.l3Off
	if len(b) < o+40 {
		return ErrShort
	}
	if b[o]>>4 != 6 {
		return ErrNotIP
	}
	p.isV6 = true
	p.l3HdrLn = 40
	next := b[o+6]
	nextOff := o + 6
	pos := o + 40
	// Walk extension headers to the transport header.
	for {
		switch next {
		case ProtoTCP, ProtoUDP, ProtoICMPv6, ext6NoNextHdr:
			p.proto = next
			p.l3HdrLn = pos - o
			return nil
		case ext6Fragment:
			if len(b) < pos+8 {
				return ErrShort
			}
			word := binary.BigEndian.Uint16(b[pos+2 : pos+4])
			p.frag6 = true
			p.frag6Off = pos
			p.frag6PrevNextOff = nextOff
			p.frag6Offset = int((word>>3)&0x1fff) * 8
			p.frag6More = word&1 != 0
			p.frag6ID = binary.BigEndian.Uint32(b[pos+4 : pos+8])
			p.frag6Next = b[pos]
			nextOff = pos
			next = b[pos]
			pos += 8
		case ext6HopByHop, ext6Routing, ext6DestOpts, ext6AH:
			if len(b) < pos+2 {
				return ErrShort
			}
			hdrExtLen := int(b[pos+1])
			adv := (hdrExtLen + 1) * 8
			if next == ext6AH {
				adv = (hdrExtLen + 2) * 4 // AH length is in 4-byte units, minus 2
			}
			nextOff = pos
			next = b[pos]
			pos += adv
			if pos > len(b) {
				return ErrShort
			}
		default:
			// Unknown/other L4 (ICMPv6, etc.): record it, no L4 parse.
			p.proto = next
			p.l3HdrLn = pos - o
			return nil
		}
	}
}

func (p *Packet) parseL4() error {
	if !p.isV4 && !p.isV6 {
		return nil
	}
	// Non-first IPv4 fragment (offset > 0): no transport header to parse.
	// internal/ipreasm stitches these before the transport is read.
	if (p.isV4 && p.fragWord()&0x1fff != 0) || (p.isV6 && p.frag6 && p.frag6Offset != 0) {
		p.l4Off = p.l3Off + p.l3HdrLn
		return nil
	}
	o := p.l3Off + p.l3HdrLn
	p.l4Off = o
	p.l4TotalLen = p.ipIndicatedL4Len()
	b := p.Buf
	switch p.proto {
	case ProtoTCP:
		if len(b) < o+20 {
			return ErrShort
		}
		dataOff := int(b[o+12]>>4) * 4
		if dataOff < 20 || len(b) < o+dataOff {
			return ErrShort
		}
		p.isTCP = true
		p.l4HdrLn = dataOff
	case ProtoUDP:
		if len(b) < o+8 {
			return ErrShort
		}
		p.isUDP = true
		p.l4HdrLn = 8
	case ProtoICMPv4, ProtoICMPv6:
		if len(b) < o+8 {
			return ErrShort
		}
		p.isICMP = true
		p.l4HdrLn = 8
	default:
		return nil // unknown L4: L3 is parsed and the frame remains wire-replayable
	}
	p.payloadOff = o + p.l4HdrLn
	if p.payloadOff > len(b) {
		p.payloadOff = len(b)
	}
	payLen := p.l4TotalLen - p.l4HdrLn
	if payLen < 0 {
		payLen = 0
	}
	if p.payloadOff+payLen > len(b) {
		payLen = len(b) - p.payloadOff
	}
	p.payloadLen = payLen
	return nil
}

// ipIndicatedL4Len returns the transport length (header+payload) from the IP
// length fields, clamped to the buffer. Using the IP length avoids counting
// Ethernet min-frame padding, which would corrupt transport checksums.
func (p *Packet) ipIndicatedL4Len() int {
	b := p.Buf
	var n int
	switch {
	case p.isV4:
		total := int(binary.BigEndian.Uint16(b[p.l3Off+2 : p.l3Off+4]))
		n = total - p.l3HdrLn
	case p.isV6:
		payload := int(binary.BigEndian.Uint16(b[p.l3Off+4 : p.l3Off+6]))
		n = payload - (p.l3HdrLn - 40) // subtract extension-header bytes
	default:
		return len(b) - p.l4Off
	}
	if n < 0 {
		n = 0
	}
	if avail := len(b) - p.l4Off; n > avail {
		n = avail
	}
	return n
}

// IsIPv4 reports whether the packet carries an IPv4 datagram.
func (p *Packet) IsIPv4() bool { return p.isV4 }

// IsIPv6 reports whether the packet carries an IPv6 datagram.
func (p *Packet) IsIPv6() bool { return p.isV6 }

// IsTCP reports whether the transport layer is TCP.
func (p *Packet) IsTCP() bool { return p.isTCP }

// IsUDP reports whether the transport layer is UDP.
func (p *Packet) IsUDP() bool { return p.isUDP }

// IsICMP reports whether the transport is ICMPv4 or ICMPv6.
func (p *Packet) IsICMP() bool { return p.isICMP }

// ICMPEcho reports whether this is an echo request/reply and returns the
// request flag, identifier, and sequence number.
func (p *Packet) ICMPEcho() (request bool, id, seq uint16, ok bool) {
	if !p.isICMP || p.l4Off+8 > len(p.Buf) {
		return false, 0, 0, false
	}
	typ := p.Buf[p.l4Off]
	switch {
	case p.proto == ProtoICMPv4 && typ == 8:
		request, ok = true, true
	case p.proto == ProtoICMPv4 && typ == 0:
		ok = true
	case p.proto == ProtoICMPv6 && typ == 128:
		request, ok = true, true
	case p.proto == ProtoICMPv6 && typ == 129:
		ok = true
	default:
		return false, 0, 0, false
	}
	return request, binary.BigEndian.Uint16(p.Buf[p.l4Off+4 : p.l4Off+6]),
		binary.BigEndian.Uint16(p.Buf[p.l4Off+6 : p.l4Off+8]), true
}

// Proto returns the IP protocol number (6 TCP, 17 UDP, ...).
func (p *Packet) Proto() uint8 { return p.proto }

// PayloadLen returns the number of transport payload bytes.
func (p *Packet) PayloadLen() int { return p.payloadLen }

// Payload returns the transport payload slice (aliases the buffer).
func (p *Packet) Payload() []byte {
	if p.payloadOff >= len(p.Buf) {
		return nil
	}
	end := p.payloadOff + p.payloadLen
	if end > len(p.Buf) {
		end = len(p.Buf)
	}
	return p.Buf[p.payloadOff:end]
}

// SrcIP returns the source IP address.
func (p *Packet) SrcIP() netip.Addr { return p.ipAt(p.srcIPOff()) }

// DstIP returns the destination IP address.
func (p *Packet) DstIP() netip.Addr { return p.ipAt(p.dstIPOff()) }

func (p *Packet) srcIPOff() int {
	if p.isV4 {
		return p.l3Off + 12
	}
	return p.l3Off + 8
}

func (p *Packet) dstIPOff() int {
	if p.isV4 {
		return p.l3Off + 16
	}
	return p.l3Off + 24
}

func (p *Packet) ipAt(off int) netip.Addr {
	if p.isV4 {
		return netip.AddrFrom4([4]byte(p.Buf[off : off+4]))
	}
	if p.isV6 {
		return netip.AddrFrom16([16]byte(p.Buf[off : off+16]))
	}
	return netip.Addr{}
}

// SrcPort returns the transport source port (0 if not TCP/UDP).
func (p *Packet) SrcPort() uint16 {
	if !p.isTCP && !p.isUDP {
		return 0
	}
	return binary.BigEndian.Uint16(p.Buf[p.l4Off : p.l4Off+2])
}

// DstPort returns the transport destination port (0 if not TCP/UDP).
func (p *Packet) DstPort() uint16 {
	if !p.isTCP && !p.isUDP {
		return 0
	}
	return binary.BigEndian.Uint16(p.Buf[p.l4Off+2 : p.l4Off+4])
}

// Seq returns the TCP sequence number.
func (p *Packet) Seq() units.Seq {
	return units.Seq(binary.BigEndian.Uint32(p.Buf[p.l4Off+4 : p.l4Off+8]))
}

// AckNum returns the TCP acknowledgement number.
func (p *Packet) AckNum() units.Ack {
	return units.Ack(binary.BigEndian.Uint32(p.Buf[p.l4Off+8 : p.l4Off+12]))
}

// Flags returns the TCP flags byte.
func (p *Packet) Flags() uint8 {
	if !p.isTCP {
		return 0
	}
	return p.Buf[p.l4Off+13]
}

// HasFlags reports whether all bits in mask are set in the TCP flags.
func (p *Packet) HasFlags(mask uint8) bool { return p.Flags()&mask == mask }

// Window returns the raw (unscaled) TCP window field.
func (p *Packet) Window() uint16 {
	return binary.BigEndian.Uint16(p.Buf[p.l4Off+14 : p.l4Off+16])
}

// tcpOptions returns the TCP option bytes (between the fixed header and payload).
func (p *Packet) tcpOptions() []byte {
	if !p.isTCP || p.l4HdrLn <= 20 {
		return nil
	}
	return p.Buf[p.l4Off+20 : p.l4Off+p.l4HdrLn]
}

// SegmentLen returns the segment's sequence-space length: payload bytes plus
// one each for SYN and FIN.
func (p *Packet) SegmentLen() uint32 {
	if !p.isTCP {
		return 0
	}
	n := uint32(p.payloadLen)
	if p.HasFlags(FlagSYN) {
		n++
	}
	if p.HasFlags(FlagFIN) {
		n++
	}
	return n
}
