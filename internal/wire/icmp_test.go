package wire

import (
	"encoding/binary"
	"testing"
)

func TestICMPEchoParseAndChecksum(t *testing.T) {
	f := make([]byte, 14+20+8+4)
	binary.BigEndian.PutUint16(f[12:14], 0x0800)
	ip := f[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, ProtoICMPv4
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(f)-14))
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})
	icmp := f[34:]
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[4:6], 9)
	binary.BigEndian.PutUint16(icmp[6:8], 3)
	copy(icmp[8:], []byte("ping"))
	p, err := Parse(f, LinkEthernet)
	if err != nil {
		t.Fatal(err)
	}
	p.RecalcChecksums()
	req, id, seq, ok := p.ICMPEcho()
	if !ok || !req || id != 9 || seq != 3 {
		t.Fatalf("req=%v id=%d seq=%d ok=%v", req, id, seq, ok)
	}
	if ipOK, l4OK := p.VerifyChecksums(); !ipOK || !l4OK {
		t.Fatalf("checksums ip=%v l4=%v", ipOK, l4OK)
	}
}
