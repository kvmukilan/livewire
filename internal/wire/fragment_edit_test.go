package wire

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestRewriteFragmentTuplePreservesWholeTransportChecksum(t *testing.T) {
	for _, tc := range []struct {
		name           string
		oldSrc, oldDst netip.Addr
		newSrc, newDst netip.Addr
	}{
		{"IPv4", netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2"), netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.20")},
		{"IPv6", netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2001:db8:1::10"), netip.MustParseAddr("2001:db8:1::20")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			full := buildTCP(t, tcpSpec{src: tc.oldSrc, dst: tc.oldDst, sport: 1200, dport: 80, seq: 10, flags: FlagACK, window: 4096, payload: bytes.Repeat([]byte("fragment"), 8)})
			mustParse(t, full).RecalcChecksums()
			fragments := splitTCPTestFragments(t, full)
			for _, fragment := range fragments {
				packet := mustParse(t, fragment)
				if !packet.RewriteFragmentTuple(tc.newSrc, tc.newDst, 45000, 8080) {
					t.Fatal("fragment tuple rewrite was rejected")
				}
			}
			reassembled := joinTCPTestFragments(t, fragments)
			packet := mustParse(t, reassembled)
			if packet.SrcIP() != tc.newSrc || packet.DstIP() != tc.newDst || packet.SrcPort() != 45000 || packet.DstPort() != 8080 {
				t.Fatalf("rewritten tuple=%s:%d -> %s:%d", packet.SrcIP(), packet.SrcPort(), packet.DstIP(), packet.DstPort())
			}
			if ipOK, transportOK := packet.VerifyChecksums(); !ipOK || !transportOK {
				t.Fatalf("reassembled checksums ip=%v transport=%v", ipOK, transportOK)
			}
		})
	}
}

func splitTCPTestFragments(t *testing.T, full []byte) [][]byte {
	t.Helper()
	packet := mustParse(t, full)
	l3 := packet.L3Offset()
	l4 := l3 + packet.L3HeaderLen()
	transport := full[l4:]
	split := 24 // TCP header plus four bytes; non-final fragment is 8-byte aligned.
	if packet.IsIPv4() {
		first := append(append([]byte(nil), full[:l4]...), transport[:split]...)
		second := append(append([]byte(nil), full[:l4]...), transport[split:]...)
		binary.BigEndian.PutUint16(first[l3+2:l3+4], uint16(len(first)-l3))
		binary.BigEndian.PutUint16(first[l3+6:l3+8], 0x2000)
		binary.BigEndian.PutUint16(second[l3+2:l3+4], uint16(len(second)-l3))
		binary.BigEndian.PutUint16(second[l3+6:l3+8], uint16(split/8))
		mustParse(t, first).recalcIPv4Header()
		mustParse(t, second).recalcIPv4Header()
		return [][]byte{first, second}
	}

	prefix := append([]byte(nil), full[:l4]...)
	prefix[l3+6] = ext6Fragment
	makeFragment := func(offset int, more bool, data []byte) []byte {
		frame := append([]byte(nil), prefix...)
		header := make([]byte, 8)
		header[0] = ProtoTCP
		word := uint16(offset/8) << 3
		if more {
			word |= 1
		}
		binary.BigEndian.PutUint16(header[2:4], word)
		binary.BigEndian.PutUint32(header[4:8], 77)
		frame = append(frame, header...)
		frame = append(frame, data...)
		binary.BigEndian.PutUint16(frame[l3+4:l3+6], uint16(8+len(data)))
		return frame
	}
	return [][]byte{makeFragment(0, true, transport[:split]), makeFragment(split, false, transport[split:])}
}

func joinTCPTestFragments(t *testing.T, fragments [][]byte) []byte {
	t.Helper()
	first := mustParse(t, fragments[0])
	second := mustParse(t, fragments[1])
	if first.IsIPv4() {
		l3, headerLen := first.L3Offset(), first.L3HeaderLen()
		frame := append([]byte(nil), fragments[0][:l3+headerLen]...)
		frame = append(frame, fragments[0][first.L3PayloadOffset():]...)
		frame = append(frame, fragments[1][second.L3PayloadOffset():]...)
		binary.BigEndian.PutUint16(frame[l3+2:l3+4], uint16(len(frame)-l3))
		binary.BigEndian.PutUint16(frame[l3+6:l3+8], 0)
		mustParse(t, frame).recalcIPv4Header()
		return frame
	}
	l3 := first.L3Offset()
	fragmentHeader, _, _, next, _, _, ok := first.IPv6Fragment()
	_ = fragmentHeader
	if !ok {
		t.Fatal("missing IPv6 fragment metadata")
	}
	firstHeaderOff := first.L3PayloadOffset() - 8
	secondHeaderOff := second.L3PayloadOffset() - 8
	frame := append([]byte(nil), fragments[0][:firstHeaderOff]...)
	frame[l3+6] = next
	frame = append(frame, fragments[0][first.L3PayloadOffset():]...)
	frame = append(frame, fragments[1][secondHeaderOff+8:]...)
	binary.BigEndian.PutUint16(frame[l3+4:l3+6], uint16(len(frame)-(l3+40)))
	return frame
}
