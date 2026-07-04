package edit

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/kvmukilan/livewire/internal/wire"
)

func buildTCP4(t *testing.T, src, dst string, sport, dport uint16, seq uint32, payload []byte) []byte {
	t.Helper()
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = 5 << 4
	tcp[13] = wire.FlagACK
	binary.BigEndian.PutUint16(tcp[14:16], 4096)
	copy(tcp[20:], payload)

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(tcp)))
	ip[8] = 64
	ip[9] = 6
	sa := netip.MustParseAddr(src).As4()
	da := netip.MustParseAddr(dst).As4()
	copy(ip[12:16], sa[:])
	copy(ip[16:20], da[:])

	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	return append(append(eth, ip...), tcp...)
}

func TestPNATPreservesHostBits(t *testing.T) {
	buf := buildTCP4(t, "10.5.6.7", "10.9.9.9", 1000, 2000, 42, []byte("hi"))
	r := &Rules{
		SrcIPMap: []IPMap{{
			Match:   netip.MustParsePrefix("10.0.0.0/8"),
			Rewrite: netip.MustParsePrefix("192.168.0.0/16"),
		}},
	}
	p, _ := wire.Parse(buf, wire.LinkEthernet)
	if !r.Apply(p) {
		t.Fatal("expected change")
	}
	q, _ := wire.Parse(buf, wire.LinkEthernet)
	// /16 rewrite: top 16 bits become 192.168, low 16 bits (6.7) preserved.
	if got := q.SrcIP(); got != netip.MustParseAddr("192.168.6.7") {
		t.Fatalf("pnat src = %v, want 192.168.6.7", got)
	}
	if ipOK, l4OK := q.VerifyChecksums(); !ipOK || !l4OK {
		t.Fatalf("checksums bad after pnat: ip=%v l4=%v", ipOK, l4OK)
	}
}

func TestPortMapAndSeqShift(t *testing.T) {
	buf := buildTCP4(t, "10.0.0.1", "10.0.0.2", 80, 12345, 1000, []byte("payload"))
	shift := uint32(0xFFFFFF00) // large shift to exercise wrapping
	r := &Rules{
		PortMap:  map[uint16]uint16{80: 8080},
		SeqShift: shift,
	}
	p, _ := wire.Parse(buf, wire.LinkEthernet)
	r.Apply(p)
	q, _ := wire.Parse(buf, wire.LinkEthernet)
	if q.SrcPort() != 8080 {
		t.Fatalf("port not remapped: %d", q.SrcPort())
	}
	if q.Seq().Uint32() != uint32(1000)+shift {
		t.Fatalf("seq shift wrong: %d", q.Seq().Uint32())
	}
	if _, l4OK := q.VerifyChecksums(); !l4OK {
		t.Fatal("tcp checksum bad after edit")
	}
}

func TestMACRewrite(t *testing.T) {
	buf := buildTCP4(t, "10.0.0.1", "10.0.0.2", 1, 2, 1, nil)
	smac := [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	dmac := [6]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	r := &Rules{SrcMAC: &smac, DstMAC: &dmac}
	p, _ := wire.Parse(buf, wire.LinkEthernet)
	r.Apply(p)
	q, _ := wire.Parse(buf, wire.LinkEthernet)
	if q.SrcMAC() != smac || q.DstMAC() != dmac {
		t.Fatalf("mac rewrite failed: %x %x", q.SrcMAC(), q.DstMAC())
	}
}

func TestVLANPushStrip(t *testing.T) {
	buf := buildTCP4(t, "10.0.0.1", "10.0.0.2", 1, 2, 1, []byte("x"))
	r := &Rules{PushVLAN: &VLANTag{VID: 100, PCP: 3}}
	tagged := r.PreTransform(buf)
	if len(tagged) != len(buf)+4 {
		t.Fatalf("push vlan len = %d, want %d", len(tagged), len(buf)+4)
	}
	p, err := wire.Parse(tagged, wire.LinkEthernet)
	if err != nil || !p.IsTCP() {
		t.Fatalf("tagged parse: %v", err)
	}
	// Strip returns to original length and remains parseable.
	strip := &Rules{StripVLAN: true}
	back := strip.PreTransform(tagged)
	if len(back) != len(buf) {
		t.Fatalf("strip vlan len = %d, want %d", len(back), len(buf))
	}
}
