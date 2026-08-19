package backend

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/wire"
)

type recordingResponder struct {
	seen [][]byte
	out  [][]byte
}

func (r *recordingResponder) OnSend(frame []byte, _ time.Time) [][]byte {
	r.seen = append(r.seen, append([]byte(nil), frame...))
	return r.out
}

func TestMockBackendLifecycleAndCapabilities(t *testing.T) {
	start := time.Unix(123, 0)
	responder := &recordingResponder{out: [][]byte{[]byte("reply-one"), []byte("reply-two")}}
	b := NewMock(responder, wire.LinkRaw, start)
	if !b.Caps().Has(CanReceive|StatefulSafe|Layer2) || b.Caps().Has(BatchSend) || b.LinkType() != wire.LinkRaw || !b.Now().Equal(start) {
		t.Fatalf("caps=%v link=%v now=%v", b.Caps(), b.LinkType(), b.Now())
	}
	input := []byte("request")
	if err := b.Send(input); err != nil {
		t.Fatal(err)
	}
	input[0] = 'X'
	buf := make([]byte, 32)
	n, ok, err := b.Recv(buf, time.Second)
	if err != nil || !ok || string(buf[:n]) != "reply-one" {
		t.Fatalf("recv=%q ok=%v err=%v", buf[:n], ok, err)
	}
	n, ok, err = b.Recv(buf[:4], time.Second)
	if err != nil || !ok || string(buf[:n]) != "repl" {
		t.Fatalf("short recv=%q ok=%v err=%v", buf[:n], ok, err)
	}
	before := b.Now()
	if n, ok, err := b.Recv(buf, 250*time.Millisecond); err != nil || ok || n != 0 || !b.Now().Equal(before.Add(250*time.Millisecond)) {
		t.Fatalf("timeout n=%d ok=%v err=%v now=%v", n, ok, err, b.Now())
	}
	if b.Sent() != 1 || b.Received() != 2 {
		t.Fatalf("sent=%d received=%d", b.Sent(), b.Received())
	}
	if err := b.Close(); err != nil {
		t.Fatalf("close=%v", err)
	}
}

func TestMACRewriterAndPassThroughs(t *testing.T) {
	local := [6]byte{2, 1, 2, 3, 4, 5}
	next := [6]byte{2, 6, 7, 8, 9, 10}
	responder := &recordingResponder{}
	inner := NewMock(responder, wire.LinkEthernet, time.Unix(1, 0))
	b := NewMACRewriter(inner, local, next)
	frame := tupleUDP(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 10, 20)
	if err := b.Send(frame); err != nil {
		t.Fatal(err)
	}
	if got := responder.seen[0]; !bytes.Equal(got[0:6], next[:]) || !bytes.Equal(got[6:12], local[:]) {
		t.Fatalf("rewritten MACs=%x", got[:12])
	}
	if err := b.Send([]byte{1, 2, 3}); err != nil || len(responder.seen) != 2 {
		t.Fatalf("malformed pass-through err=%v seen=%d", err, len(responder.seen))
	}
	if b.LinkType() != wire.LinkEthernet || b.Caps() != inner.Caps() || !b.Now().Equal(inner.Now()) || b.Close() != nil {
		t.Fatal("wrapper pass-through methods differ")
	}

	rawResponder := &recordingResponder{}
	raw := NewMACRewriter(NewMock(rawResponder, wire.LinkRaw, time.Time{}), local, next)
	if err := raw.Send([]byte("raw")); err != nil || string(rawResponder.seen[0]) != "raw" {
		t.Fatalf("raw pass-through err=%v seen=%q", err, rawResponder.seen)
	}
}

func TestNeighborSolicitationAndAdvertisementParsing(t *testing.T) {
	src := netip.MustParseAddr("2001:db8::1")
	dst := netip.MustParseAddr("ff02::1:ff00:2")
	target := netip.MustParseAddr("2001:db8::2")
	srcMAC := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	dstMAC := net.HardwareAddr{0x33, 0x33, 0xff, 0, 0, 2}
	ns := buildNS(srcMAC, dstMAC, src, dst, target)
	if len(ns) != 86 || binary.BigEndian.Uint16(ns[12:14]) != ethIPv6 || ns[14+40] != 135 {
		t.Fatalf("neighbor solicitation=%x", ns)
	}

	na := append([]byte(nil), ns...)
	na[14+40] = 136
	copy(na[14+40+8:14+40+24], target.AsSlice())
	na[14+40+24] = 2
	wantMAC := net.HardwareAddr{2, 9, 8, 7, 6, 5}
	copy(na[14+40+26:], wantMAC)
	got, ok := parseNA(na, target)
	if !ok || !bytes.Equal(got, wantMAC) {
		t.Fatalf("NA MAC=%v ok=%v", got, ok)
	}
	na[14+40+24] = 1
	got, ok = parseNA(na, target)
	if !ok || !bytes.Equal(got, na[6:12]) {
		t.Fatalf("fallback MAC=%v ok=%v", got, ok)
	}
	if _, ok := parseNA(na[:20], target); ok {
		t.Fatal("truncated advertisement accepted")
	}
	if _, ok := parseNA(na, netip.MustParseAddr("2001:db8::3")); ok {
		t.Fatal("wrong-target advertisement accepted")
	}
	if checksum := icmpv6Checksum(src.AsSlice(), dst.AsSlice(), []byte{1, 2, 3}); checksum == 0 {
		t.Fatal("unexpected zero checksum")
	}
}
