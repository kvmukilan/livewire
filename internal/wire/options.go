package wire

import "encoding/binary"

// TCP option kinds we understand (RFC 793, 7323, 2018).
const (
	optEOL       uint8 = 0
	optNOP       uint8 = 1
	optMSS       uint8 = 2
	optWScale    uint8 = 3
	optSACKPerm  uint8 = 4
	optSACK      uint8 = 5
	optTimestamp uint8 = 8
)

// tcpOption is a located option within the TCP header.
type tcpOption struct {
	Kind uint8
	Off  int // buffer offset of the option's first byte (its kind)
	Len  int // total option length in bytes (1 for EOL/NOP)
}

// eachTCPOption calls fn for every TCP option until fn returns false or the
// options end. Truncated/garbage option areas stop the walk cleanly.
func (p *Packet) eachTCPOption(fn func(o tcpOption) bool) {
	if !p.isTCP || p.l4HdrLn <= 20 {
		return
	}
	opts := p.Buf[p.l4Off+20 : p.l4Off+p.l4HdrLn]
	base := p.l4Off + 20
	i := 0
	for i < len(opts) {
		kind := opts[i]
		switch kind {
		case optEOL:
			return
		case optNOP:
			if !fn(tcpOption{Kind: optNOP, Off: base + i, Len: 1}) {
				return
			}
			i++
		default:
			if i+1 >= len(opts) {
				return
			}
			l := int(opts[i+1])
			if l < 2 || i+l > len(opts) {
				return
			}
			if !fn(tcpOption{Kind: kind, Off: base + i, Len: l}) {
				return
			}
			i += l
		}
	}
}

// MSS returns the advertised maximum segment size option, if present.
func (p *Packet) MSS() (mss uint16, ok bool) {
	p.eachTCPOption(func(o tcpOption) bool {
		if o.Kind == optMSS && o.Len == 4 {
			mss = binary.BigEndian.Uint16(p.Buf[o.Off+2 : o.Off+4])
			ok = true
			return false
		}
		return true
	})
	return
}

// WindowScale returns the window-scale shift count, if present. Only meaningful
// on SYN / SYN-ACK segments.
func (p *Packet) WindowScale() (shift uint8, ok bool) {
	p.eachTCPOption(func(o tcpOption) bool {
		if o.Kind == optWScale && o.Len == 3 {
			shift = p.Buf[o.Off+2]
			ok = true
			return false
		}
		return true
	})
	return
}

// SACKPermitted reports whether the SACK-permitted option is present.
func (p *Packet) SACKPermitted() bool {
	found := false
	p.eachTCPOption(func(o tcpOption) bool {
		if o.Kind == optSACKPerm {
			found = true
			return false
		}
		return true
	})
	return found
}

// Timestamps returns the TSval/TSecr timestamp option values, if present.
func (p *Packet) Timestamps() (tsval, tsecr uint32, ok bool) {
	p.eachTCPOption(func(o tcpOption) bool {
		if o.Kind == optTimestamp && o.Len == 10 {
			tsval = binary.BigEndian.Uint32(p.Buf[o.Off+2 : o.Off+6])
			tsecr = binary.BigEndian.Uint32(p.Buf[o.Off+6 : o.Off+10])
			ok = true
			return false
		}
		return true
	})
	return
}

// SetTimestamps rewrites the TSval/TSecr option in place, reporting whether one
// was present. Recompute the TCP checksum afterwards. Skipping this trips the
// peer's PAWS check (RFC 7323).
func (p *Packet) SetTimestamps(tsval, tsecr uint32) bool {
	done := false
	p.eachTCPOption(func(o tcpOption) bool {
		if o.Kind == optTimestamp && o.Len == 10 {
			binary.BigEndian.PutUint32(p.Buf[o.Off+2:o.Off+6], tsval)
			binary.BigEndian.PutUint32(p.Buf[o.Off+6:o.Off+10], tsecr)
			done = true
			return false
		}
		return true
	})
	return done
}

// HasTimestamps reports whether the segment carries a TCP timestamp option.
func (p *Packet) HasTimestamps() bool {
	_, _, ok := p.Timestamps()
	return ok
}

// SACKBlocks returns the SACK blocks as [left, right] sequence pairs (RFC 2018).
func (p *Packet) SACKBlocks() [][2]uint32 {
	var blocks [][2]uint32
	p.eachTCPOption(func(o tcpOption) bool {
		if o.Kind == optSACK && o.Len >= 10 && (o.Len-2)%8 == 0 {
			n := (o.Len - 2) / 8
			for k := 0; k < n; k++ {
				lo := o.Off + 2 + k*8
				blocks = append(blocks, [2]uint32{
					binary.BigEndian.Uint32(p.Buf[lo : lo+4]),
					binary.BigEndian.Uint32(p.Buf[lo+4 : lo+8]),
				})
			}
		}
		return true
	})
	return blocks
}

// RewriteSACKEdges applies fn to every 32-bit SACK edge in place. Edges carry
// absolute sequence numbers, so shift them by the same delta as the peer's
// sequence space. Recompute the TCP checksum afterwards.
func (p *Packet) RewriteSACKEdges(fn func(edge uint32) uint32) {
	p.eachTCPOption(func(o tcpOption) bool {
		if o.Kind == optSACK && o.Len >= 10 && (o.Len-2)%8 == 0 {
			n := (o.Len - 2) / 8
			for k := 0; k < 2*n; k++ {
				e := o.Off + 2 + k*4
				v := binary.BigEndian.Uint32(p.Buf[e : e+4])
				binary.BigEndian.PutUint32(p.Buf[e:e+4], fn(v))
			}
		}
		return true
	})
}
