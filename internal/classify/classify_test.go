package classify

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/kvmukilan/livewire/internal/wire"
)

// buildTCP4 assembles a minimal Ethernet/IPv4/TCP frame and parses it.
func buildTCP4(t *testing.T, src, dst string, sport, dport uint16, flags uint8) *wire.Packet {
	t.Helper()
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 1024)

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
	buf := append(append(eth, ip...), tcp...)
	p, err := wire.Parse(buf, wire.LinkEthernet)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

func TestAutoClassifyHandshake(t *testing.T) {
	// Client 10.0.0.9:5000 -> Server 10.0.0.1:80
	pkts := []*wire.Packet{
		buildTCP4(t, "10.0.0.9", "10.0.0.1", 5000, 80, wire.FlagSYN),              // client SYN
		buildTCP4(t, "10.0.0.1", "10.0.0.9", 80, 5000, wire.FlagSYN|wire.FlagACK), // server SYN-ACK
		buildTCP4(t, "10.0.0.9", "10.0.0.1", 5000, 80, wire.FlagACK),              // client ACK
		buildTCP4(t, "10.0.0.1", "10.0.0.9", 80, 5000, wire.FlagACK|wire.FlagPSH), // server data
	}
	c := &Classifier{Mode: ModeAuto}
	cache := c.Classify(pkts)
	want := []Send{SendPrimary, SendSecondary, SendPrimary, SendSecondary}
	for i, w := range want {
		if cache.At(i) != w {
			t.Fatalf("packet %d: got %d want %d", i, cache.At(i), w)
		}
	}
	pri, sec, _ := cache.Counts()
	if pri != 2 || sec != 2 {
		t.Fatalf("counts pri=%d sec=%d", pri, sec)
	}
}

func TestCIDRClassify(t *testing.T) {
	pkts := []*wire.Packet{
		buildTCP4(t, "192.168.5.5", "8.8.8.8", 4444, 53, wire.FlagACK),
		buildTCP4(t, "8.8.8.8", "192.168.5.5", 53, 4444, wire.FlagACK),
	}
	c := &Classifier{Mode: ModeClientCIDR, ClientNets: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}}
	cache := c.Classify(pkts)
	if cache.At(0) != SendPrimary || cache.At(1) != SendSecondary {
		t.Fatalf("cidr classify wrong: %d %d", cache.At(0), cache.At(1))
	}
}

func TestCacheRoundTrip(t *testing.T) {
	in := NewCache()
	seq := []Send{SendPrimary, SendSecondary, SendNone, SendPrimary, SendPrimary, SendSecondary, SendNone}
	for _, s := range seq {
		in.Append(s)
	}
	var buf bytes.Buffer
	if err := WriteCache(&buf, in, "test-comment"); err != nil {
		t.Fatal(err)
	}
	out, comment, err := ReadCache(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if comment != "test-comment" {
		t.Fatalf("comment = %q", comment)
	}
	if out.Len() != len(seq) {
		t.Fatalf("len = %d want %d", out.Len(), len(seq))
	}
	for i, s := range seq {
		if out.At(i) != s {
			t.Fatalf("entry %d = %d want %d", i, out.At(i), s)
		}
	}
}
