package wire

import "encoding/binary"

// RebuildWithPayload returns a copy of p with payload swapped in, fixing the
// IPv4 total-length or IPv6 payload-length field and all checksums. p is left
// unmodified. Works for any link and IP version since it reuses parsed offsets.
// Used for re-segmentation and RST synthesis.
func (p *Packet) RebuildWithPayload(payload []byte) []byte {
	out := make([]byte, p.payloadOff+len(payload))
	copy(out, p.Buf[:p.payloadOff])
	copy(out[p.payloadOff:], payload)

	l4HdrLn := p.payloadOff - p.l4Off
	switch {
	case p.isV4:
		total := p.l3HdrLn + l4HdrLn + len(payload)
		binary.BigEndian.PutUint16(out[p.l3Off+2:p.l3Off+4], uint16(total))
	case p.isV6:
		// Payload length counts extension headers + transport + data.
		plen := (p.l3HdrLn - 40) + l4HdrLn + len(payload)
		binary.BigEndian.PutUint16(out[p.l3Off+4:p.l3Off+6], uint16(plen))
	}

	if np, err := Parse(out, p.Link); err == nil {
		np.RecalcChecksums()
		return np.Buf
	}
	return out
}
