package wire

import "encoding/binary"

// SynMSS, SynSACKPerm, and synTimestamp build the option bytes commonly carried
// on a SYN. They are used to give a synthesized handshake realistic options.
func SynMSS(mss uint16) []byte {
	return []byte{optMSS, 4, byte(mss >> 8), byte(mss)}
}

// SynSACKPerm is the SACK-permitted option.
func SynSACKPerm() []byte { return []byte{optSACKPerm, 2} }

// SynTimestamp is a timestamp option with the given TSval and a zero TSecr.
func SynTimestamp(tsval uint32) []byte {
	o := []byte{optTimestamp, 10, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(o[2:6], tsval)
	return o
}

// PadOptions pads an option blob with NOPs to a 4-byte boundary (TCP header
// length is measured in 32-bit words).
func PadOptions(opts []byte) []byte {
	for len(opts)%4 != 0 {
		opts = append(opts, optNOP)
	}
	return opts
}

// RebuildWithOptions returns a copy of p with its TCP options replaced by opts
// (padded to a 4-byte boundary) and the given payload, fixing the TCP data
// offset, the IP length field, and all checksums. Returns ok=false for a
// non-TCP packet or an option area that would exceed the 60-byte TCP header.
// The receiver is left unmodified.
func (p *Packet) RebuildWithOptions(opts, payload []byte) ([]byte, bool) {
	if !p.isTCP {
		return nil, false
	}
	opts = PadOptions(append([]byte(nil), opts...))
	dataOff := 20 + len(opts)
	if dataOff > 60 {
		return nil, false
	}

	l2l3 := p.Buf[:p.l4Off]
	tcpFixed := append([]byte(nil), p.Buf[p.l4Off:p.l4Off+20]...) // 20-byte fixed TCP header

	out := make([]byte, 0, len(l2l3)+dataOff+len(payload))
	out = append(out, l2l3...)
	out = append(out, tcpFixed...)
	out = append(out, opts...)
	out = append(out, payload...)

	// Data offset lives in the high nibble of TCP header byte 12; the low nibble
	// (reserved + NS) is normally zero.
	out[p.l4Off+12] = byte((dataOff / 4) << 4)

	// Fix the IP length field for the new total.
	l4Total := dataOff + len(payload)
	switch {
	case p.isV4:
		total := p.l3HdrLn + l4Total
		binary.BigEndian.PutUint16(out[p.l3Off+2:p.l3Off+4], uint16(total))
	case p.isV6:
		plen := (p.l3HdrLn - 40) + l4Total
		binary.BigEndian.PutUint16(out[p.l3Off+4:p.l3Off+6], uint16(plen))
	}

	if np, err := Parse(out, p.Link); err == nil {
		np.RecalcChecksums()
		return np.Buf, true
	}
	return out, true
}
