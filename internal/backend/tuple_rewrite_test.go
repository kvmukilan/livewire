package backend

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/wire"
)

type tupleStub struct {
	sent []byte
	recv []byte
}

func (s *tupleStub) Send(b []byte) error { s.sent = append([]byte(nil), b...); return nil }
func (s *tupleStub) Recv(b []byte, _ time.Duration) (int, bool, error) {
	copy(b, s.recv)
	return len(s.recv), true, nil
}
func (s *tupleStub) Now() time.Time          { return time.Unix(0, 0) }
func (s *tupleStub) LinkType() wire.LinkType { return wire.LinkEthernet }
func (s *tupleStub) Caps() Capabilities      { return CanReceive | Layer2 }
func (s *tupleStub) Close() error            { return nil }

func tupleUDP(src, dst netip.Addr, sp, dp uint16) []byte {
	f := make([]byte, 14+20+8)
	binary.BigEndian.PutUint16(f[12:14], 0x0800)
	ip := f[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, wire.ProtoUDP
	binary.BigEndian.PutUint16(ip[2:4], 28)
	sa, da := src.As4(), dst.As4()
	copy(ip[12:16], sa[:])
	copy(ip[16:20], da[:])
	binary.BigEndian.PutUint16(f[34:36], sp)
	binary.BigEndian.PutUint16(f[36:38], dp)
	binary.BigEndian.PutUint16(f[38:40], 8)
	p, _ := wire.Parse(f, wire.LinkEthernet)
	p.RecalcChecksums()
	return f
}

func TestTupleRewriterRoundTrip(t *testing.T) {
	cc := TupleEndpoint{netip.MustParseAddr("192.0.2.10"), 5000}
	cs := TupleEndpoint{netip.MustParseAddr("192.0.2.20"), 53}
	lc := TupleEndpoint{netip.MustParseAddr("10.0.0.10"), 5000}
	ls := TupleEndpoint{netip.MustParseAddr("10.0.0.20"), 53}
	stub := &tupleStub{}
	rw := NewTupleRewriter(stub, TupleRewrite{cc, cs, lc, ls})
	if err := rw.Send(tupleUDP(cc.IP, cs.IP, cc.Port, cs.Port)); err != nil {
		t.Fatal(err)
	}
	p, _ := wire.Parse(stub.sent, wire.LinkEthernet)
	if p.SrcIP() != lc.IP || p.DstIP() != ls.IP {
		t.Fatalf("sent %s -> %s", p.SrcIP(), p.DstIP())
	}
	stub.recv = tupleUDP(ls.IP, lc.IP, ls.Port, lc.Port)
	buf := make([]byte, 128)
	n, _, _ := rw.Recv(buf, time.Second)
	p, _ = wire.Parse(buf[:n], wire.LinkEthernet)
	if p.SrcIP() != cs.IP || p.DstIP() != cc.IP {
		t.Fatalf("recv %s -> %s", p.SrcIP(), p.DstIP())
	}
}
