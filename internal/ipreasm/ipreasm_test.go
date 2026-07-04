package ipreasm

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/kvmukilan/livewire/internal/wire"
)

// makeIPv4 builds an Ethernet/IPv4 frame. mf sets More-Fragments; fragOff is the
// byte offset (a multiple of 8).
func makeIPv4(id uint16, proto uint8, fragOff int, mf bool, payload []byte) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(ip[4:6], id)
	word := uint16(fragOff/8) & 0x1fff
	if mf {
		word |= 0x2000
	}
	binary.BigEndian.PutUint16(ip[6:8], word)
	ip[8] = 64
	ip[9] = proto
	sa := netip.MustParseAddr("10.0.0.1").As4()
	da := netip.MustParseAddr("10.0.0.2").As4()
	copy(ip[12:16], sa[:])
	copy(ip[16:20], da[:])
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	return append(append(eth, ip...), payload...)
}

// udpDatagram builds a UDP header + data.
func udpDatagram(sport, dport uint16, data []byte) []byte {
	u := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(u[0:2], sport)
	binary.BigEndian.PutUint16(u[2:4], dport)
	binary.BigEndian.PutUint16(u[4:6], uint16(8+len(data)))
	copy(u[8:], data)
	return u
}

func TestReassembleTwoFragments(t *testing.T) {
	// 24-byte UDP datagram (8 header + 16 data) split in two: frag0 = UDP header +
	// first 8 data (offset 0, MF=1), frag1 = last 8 data (offset 16, MF=0).
	full := udpDatagram(1000, 2000, []byte("0123456789ABCDEF")) // 8 + 16 = 24 bytes
	frag0 := makeIPv4(42, 17, 0, true, full[:16])               // UDP hdr(8) + 8 data
	frag1 := makeIPv4(42, 17, 16, false, full[16:])             // remaining 8 data

	out, dropped, err := ReassembleAll([][]byte{frag0, frag1}, wire.LinkEthernet)
	if err != nil {
		t.Fatal(err)
	}
	if dropped != 0 {
		t.Fatalf("expected 0 dropped, got %d", dropped)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 reassembled frame, got %d", len(out))
	}

	p, err := wire.Parse(out[0], wire.LinkEthernet)
	if err != nil {
		t.Fatalf("parse reassembled: %v", err)
	}
	if p.IsFragment() {
		t.Fatal("reassembled frame should not be a fragment")
	}
	if !p.IsUDP() {
		t.Fatal("reassembled transport should be UDP")
	}
	if p.PayloadLen() != 16 {
		t.Fatalf("reassembled UDP payload = %d, want 16", p.PayloadLen())
	}
	if got := p.Payload()[:16]; !bytes.Equal(got, []byte("0123456789ABCDEF")) {
		t.Fatalf("reassembled payload mismatch: %q", got)
	}
	if ipOK, l4OK := p.VerifyChecksums(); !ipOK || !l4OK {
		t.Fatalf("reassembled checksums invalid (ip=%v l4=%v)", ipOK, l4OK)
	}
}

func TestReassembleThreeFragmentsOutOfOrder(t *testing.T) {
	full := udpDatagram(1, 2, bytes.Repeat([]byte("X"), 40)) // 8 + 40 = 48 bytes
	f0 := makeIPv4(7, 17, 0, true, full[:24])                // offset 0
	f1 := makeIPv4(7, 17, 24, true, full[24:40])             // offset 24
	f2 := makeIPv4(7, 17, 40, false, full[40:])              // offset 40, last
	// Deliver out of order.
	out, dropped, err := ReassembleAll([][]byte{f2, f0, f1}, wire.LinkEthernet)
	if err != nil || dropped != 0 || len(out) != 1 {
		t.Fatalf("out-of-order reassembly failed: err=%v dropped=%d n=%d", err, dropped, len(out))
	}
	p, _ := wire.Parse(out[0], wire.LinkEthernet)
	if p.PayloadLen() != 40 {
		t.Fatalf("payload = %d, want 40", p.PayloadLen())
	}
}

func TestIncompleteFragmentsDropped(t *testing.T) {
	full := udpDatagram(1, 2, bytes.Repeat([]byte("Y"), 24))
	f0 := makeIPv4(9, 17, 0, true, full[:16]) // first only; last never arrives
	out, dropped, err := ReassembleAll([][]byte{f0}, wire.LinkEthernet)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 || dropped != 1 {
		t.Fatalf("incomplete set should drop: out=%d dropped=%d", len(out), dropped)
	}
}

func TestNonFragmentsPassThrough(t *testing.T) {
	whole := makeIPv4(1, 17, 0, false, udpDatagram(1, 2, []byte("hi")))
	out, _, err := ReassembleAll([][]byte{whole}, wire.LinkEthernet)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || !bytes.Equal(out[0], whole) {
		t.Fatal("non-fragment should pass through unchanged")
	}
}

func TestFragmentAccessors(t *testing.T) {
	f := makeIPv4(0x1234, 6, 1480, true, []byte("data"))
	p, err := wire.Parse(f, wire.LinkEthernet)
	if err != nil {
		t.Fatal(err)
	}
	if p.FragmentID() != 0x1234 {
		t.Fatalf("id = %#x", p.FragmentID())
	}
	if p.FragmentOffset() != 1480 {
		t.Fatalf("offset = %d, want 1480", p.FragmentOffset())
	}
	if !p.MoreFragments() || !p.IsFragment() {
		t.Fatal("MF/IsFragment should be true")
	}
}
