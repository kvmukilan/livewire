package wire

import "encoding/binary"

// StripVLANs removes all 802.1Q/QinQ tags and returns a new buffer. Untagged or
// non-Ethernet frames are returned unchanged. Re-parse the result before editing.
func StripVLANs(buf []byte) []byte {
	if len(buf) < 14 {
		return buf
	}
	k := 0
	for {
		off := 12 + 4*k
		if len(buf) < off+2 {
			break
		}
		et := binary.BigEndian.Uint16(buf[off : off+2])
		if et != etherVLAN && et != etherQinQ {
			break
		}
		k++
	}
	if k == 0 {
		return buf
	}
	out := make([]byte, 0, len(buf)-4*k)
	out = append(out, buf[0:12]...)
	out = append(out, buf[12+4*k:]...)
	return out
}

// PushVLAN inserts a single 802.1Q tag (VID 0..4095, PCP 0..7) after the MAC
// addresses, returning a new buffer. No-op on non-Ethernet frames.
func PushVLAN(buf []byte, vid uint16, pcp uint8) []byte {
	if len(buf) < 14 {
		return buf
	}
	tci := (uint16(pcp&0x7) << 13) | (vid & 0x0fff)
	out := make([]byte, 0, len(buf)+4)
	out = append(out, buf[0:12]...)
	tag := []byte{0x81, 0x00, byte(tci >> 8), byte(tci)}
	out = append(out, tag...)
	out = append(out, buf[12:]...)
	return out
}
