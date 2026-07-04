package wire

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/kvmukilan/livewire/internal/units"
)

// Checks the primitive against the canonical worked example (header sums to
// 0xb1e6), anchoring sumBytes/fold to an external reference.
func TestIPv4HeaderChecksumKnownAnswer(t *testing.T) {
	hdr := []byte{
		0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63,
		0xac, 0x10, 0x0a, 0x0c,
	}
	if got := ipv4HeaderChecksum(hdr); got != 0xb1e6 {
		t.Fatalf("checksum = 0x%04x, want 0xb1e6", got)
	}
	// With the checksum written back, the header must sum to zero.
	binary.BigEndian.PutUint16(hdr[10:12], 0xb1e6)
	if fold(sumBytes(hdr, 0)) != 0 {
		t.Fatal("header with checksum should verify to zero")
	}
}

type tcpSpec struct {
	src, dst netip.Addr
	sport    uint16
	dport    uint16
	seq, ack uint32
	flags    uint8
	window   uint16
	options  []byte
	payload  []byte
}

func buildTCP(t *testing.T, s tcpSpec) []byte {
	t.Helper()
	v4 := s.src.Is4()
	if len(s.options)%4 != 0 {
		t.Fatalf("options must be 4-byte aligned, got %d", len(s.options))
	}
	tcpHdrLen := 20 + len(s.options)
	tcp := make([]byte, tcpHdrLen+len(s.payload))
	binary.BigEndian.PutUint16(tcp[0:2], s.sport)
	binary.BigEndian.PutUint16(tcp[2:4], s.dport)
	binary.BigEndian.PutUint32(tcp[4:8], s.seq)
	binary.BigEndian.PutUint32(tcp[8:12], s.ack)
	tcp[12] = byte((tcpHdrLen / 4) << 4)
	tcp[13] = s.flags
	binary.BigEndian.PutUint16(tcp[14:16], s.window)
	copy(tcp[20:20+len(s.options)], s.options)
	copy(tcp[tcpHdrLen:], s.payload)

	eth := make([]byte, 14)
	copy(eth[0:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	copy(eth[6:12], []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb})

	if v4 {
		binary.BigEndian.PutUint16(eth[12:14], etherIPv4)
		ip := make([]byte, 20)
		ip[0] = 0x45
		total := 20 + len(tcp)
		binary.BigEndian.PutUint16(ip[2:4], uint16(total))
		binary.BigEndian.PutUint16(ip[4:6], 0x1234)
		binary.BigEndian.PutUint16(ip[6:8], 0x4000)
		ip[8] = 64
		ip[9] = ProtoTCP
		sa, da := s.src.As4(), s.dst.As4()
		copy(ip[12:16], sa[:])
		copy(ip[16:20], da[:])
		return append(append(eth, ip...), tcp...)
	}
	binary.BigEndian.PutUint16(eth[12:14], etherIPv6)
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(tcp)))
	ip[6] = ProtoTCP
	ip[7] = 64
	sa, da := s.src.As16(), s.dst.As16()
	copy(ip[8:24], sa[:])
	copy(ip[24:40], da[:])
	return append(append(eth, ip...), tcp...)
}

func mustParse(t *testing.T, buf []byte) *Packet {
	t.Helper()
	p, err := Parse(buf, LinkEthernet)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

func TestParseAndChecksumV4(t *testing.T) {
	// NOP, NOP, Timestamp(TSval=0x01020304, TSecr=0x05060708)
	opts := []byte{optNOP, optNOP, optTimestamp, 10,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	buf := buildTCP(t, tcpSpec{
		src: netip.MustParseAddr("10.0.0.1"), dst: netip.MustParseAddr("10.0.0.2"),
		sport: 12345, dport: 80, seq: 0x11223344, ack: 0x55667788,
		flags: FlagACK | FlagPSH, window: 0xffff, options: opts, payload: []byte("hello"),
	})
	p := mustParse(t, buf)

	if !p.IsIPv4() || !p.IsTCP() {
		t.Fatal("expected IPv4/TCP")
	}
	if p.SrcIP() != netip.MustParseAddr("10.0.0.1") || p.DstIP() != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("addrs: %v -> %v", p.SrcIP(), p.DstIP())
	}
	if p.SrcPort() != 12345 || p.DstPort() != 80 {
		t.Fatalf("ports: %d -> %d", p.SrcPort(), p.DstPort())
	}
	if p.Seq() != units.Seq(0x11223344) || p.AckNum() != units.Ack(0x55667788) {
		t.Fatalf("seq/ack: %x/%x", p.Seq(), p.AckNum())
	}
	if p.PayloadLen() != 5 {
		t.Fatalf("payload len = %d, want 5", p.PayloadLen())
	}
	if tsv, tse, ok := p.Timestamps(); !ok || tsv != 0x01020304 || tse != 0x05060708 {
		t.Fatalf("timestamps: %x %x %v", tsv, tse, ok)
	}

	p.RecalcChecksums()
	if ipOK, l4OK := p.VerifyChecksums(); !ipOK || !l4OK {
		t.Fatalf("checksums after recalc: ip=%v l4=%v", ipOK, l4OK)
	}
}

func TestRewriteSeqAndIPRecomputesChecksum(t *testing.T) {
	buf := buildTCP(t, tcpSpec{
		src: netip.MustParseAddr("192.168.1.10"), dst: netip.MustParseAddr("192.168.1.20"),
		sport: 5000, dport: 443, seq: 1000, ack: 2000,
		flags: FlagACK, window: 8192, payload: []byte("abcdef"),
	})
	p := mustParse(t, buf)
	p.SetSrcIP(netip.MustParseAddr("203.0.113.7"))
	p.SetSeq(p.Seq().Add(4242))
	p.SetAck(p.AckNum().Add(99))
	p.RecalcChecksums()

	q := mustParse(t, buf) // re-parse the mutated buffer
	if q.SrcIP() != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("src not rewritten: %v", q.SrcIP())
	}
	if q.Seq() != units.Seq(1000+4242) || q.AckNum() != units.Ack(2000+99) {
		t.Fatalf("seq/ack not rewritten: %d/%d", q.Seq(), q.AckNum())
	}
	if ipOK, l4OK := q.VerifyChecksums(); !ipOK || !l4OK {
		t.Fatalf("checksums invalid after rewrite: ip=%v l4=%v", ipOK, l4OK)
	}
}

func TestSynOptionsAndSACKRewrite(t *testing.T) {
	// SYN with MSS=1460, WScale=7, SACK-perm, then a SACK block on a later seg.
	// Build a segment carrying a SACK option: kind5 len10 [left=0x1000 right=0x2000].
	opts := []byte{optSACK, 10, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00, optNOP, optNOP}
	buf := buildTCP(t, tcpSpec{
		src: netip.MustParseAddr("10.1.1.1"), dst: netip.MustParseAddr("10.1.1.2"),
		sport: 1, dport: 2, seq: 5, ack: 6, flags: FlagACK, window: 100, options: opts,
	})
	p := mustParse(t, buf)
	blocks := p.SACKBlocks()
	if len(blocks) != 1 || blocks[0] != [2]uint32{0x1000, 0x2000} {
		t.Fatalf("sack blocks: %v", blocks)
	}
	p.RewriteSACKEdges(func(e uint32) uint32 { return e + 0x100 })
	blocks = p.SACKBlocks()
	if blocks[0] != [2]uint32{0x1100, 0x2100} {
		t.Fatalf("sack edges not shifted: %v", blocks)
	}

	// Timestamp rewrite on a segment that has one.
	tsOpts := []byte{optNOP, optNOP, optTimestamp, 10, 0, 0, 0, 1, 0, 0, 0, 2}
	buf2 := buildTCP(t, tcpSpec{
		src: netip.MustParseAddr("10.1.1.1"), dst: netip.MustParseAddr("10.1.1.2"),
		sport: 1, dport: 2, seq: 5, ack: 6, flags: FlagACK, window: 100, options: tsOpts,
	})
	p2 := mustParse(t, buf2)
	if !p2.SetTimestamps(0xAABBCCDD, 0x11223344) {
		t.Fatal("SetTimestamps returned false")
	}
	tsv, tse, _ := p2.Timestamps()
	if tsv != 0xAABBCCDD || tse != 0x11223344 {
		t.Fatalf("timestamps not set: %x %x", tsv, tse)
	}
}

func TestParseAndChecksumV6(t *testing.T) {
	buf := buildTCP(t, tcpSpec{
		src: netip.MustParseAddr("2001:db8::1"), dst: netip.MustParseAddr("2001:db8::2"),
		sport: 1111, dport: 2222, seq: 7, ack: 8, flags: FlagSYN, window: 65535,
		payload: []byte("v6payload"),
	})
	p := mustParse(t, buf)
	if !p.IsIPv6() || !p.IsTCP() {
		t.Fatal("expected IPv6/TCP")
	}
	if p.SrcIP() != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("v6 src: %v", p.SrcIP())
	}
	if p.PayloadLen() != 9 {
		t.Fatalf("v6 payload len = %d, want 9", p.PayloadLen())
	}
	p.SetDstIP(netip.MustParseAddr("2001:db8::dead:beef"))
	p.RecalcChecksums()
	q := mustParse(t, buf)
	if _, l4OK := q.VerifyChecksums(); !l4OK {
		t.Fatal("v6 tcp checksum invalid after recalc")
	}
}

func TestVLANParsing(t *testing.T) {
	// Ethernet with a single 802.1Q tag (vid 100) wrapping IPv4/TCP.
	inner := buildTCP(t, tcpSpec{
		src: netip.MustParseAddr("10.0.0.1"), dst: netip.MustParseAddr("10.0.0.2"),
		sport: 80, dport: 8080, seq: 1, ack: 1, flags: FlagACK, window: 1,
	})
	// Splice a VLAN tag after the 12-byte MAC addresses.
	tagged := make([]byte, 0, len(inner)+4)
	tagged = append(tagged, inner[0:12]...)         // dst+src MAC
	tagged = append(tagged, 0x81, 0x00, 0x00, 0x64) // 802.1Q, vid=100
	tagged = append(tagged, inner[12:]...)          // original ethertype + payload
	p, err := Parse(tagged, LinkEthernet)
	if err != nil {
		t.Fatalf("parse vlan: %v", err)
	}
	if !p.IsIPv4() || p.SrcPort() != 80 || p.DstPort() != 8080 {
		t.Fatalf("vlan inner parse wrong: v4=%v %d->%d", p.IsIPv4(), p.SrcPort(), p.DstPort())
	}
}

func TestSegmentLenCountsSynFin(t *testing.T) {
	buf := buildTCP(t, tcpSpec{
		src: netip.MustParseAddr("10.0.0.1"), dst: netip.MustParseAddr("10.0.0.2"),
		sport: 1, dport: 2, seq: 1, ack: 0, flags: FlagSYN, window: 1,
	})
	if n := mustParse(t, buf).SegmentLen(); n != 1 {
		t.Fatalf("SYN segment len = %d, want 1", n)
	}
	buf2 := buildTCP(t, tcpSpec{
		src: netip.MustParseAddr("10.0.0.1"), dst: netip.MustParseAddr("10.0.0.2"),
		sport: 1, dport: 2, seq: 1, ack: 1, flags: FlagFIN | FlagACK, window: 1,
		payload: []byte("data"),
	})
	if n := mustParse(t, buf2).SegmentLen(); n != 5 { // 4 payload + FIN
		t.Fatalf("FIN+data segment len = %d, want 5", n)
	}
}
