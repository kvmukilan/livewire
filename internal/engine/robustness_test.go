package engine

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

// tcpSeg builds a TCP segment (header with a timestamp option + payload).
func tcpSeg(sport, dport uint16, seq, ack uint32, flags uint8, tsval, tsecr uint32, payload []byte) []byte {
	opts := []byte{0x01, 0x01, 0x08, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(opts[4:8], tsval)
	binary.BigEndian.PutUint32(opts[8:12], tsecr)
	hdr := 20 + len(opts)
	tcp := make([]byte, hdr+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = byte((hdr / 4) << 4)
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 0xffff)
	copy(tcp[20:], opts)
	copy(tcp[hdr:], payload)
	return tcp
}

// frame6 builds an Ethernet/IPv6/TCP frame.
func frame6(src, dst string, sport, dport uint16, seq, ack uint32, flags uint8, tsval, tsecr uint32, payload []byte) []byte {
	tcp := tcpSeg(sport, dport, seq, ack, flags, tsval, tsecr, payload)
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(tcp)))
	ip[6] = 6 // next header = TCP
	ip[7] = 64
	sa := netip.MustParseAddr(src).As16()
	da := netip.MustParseAddr(dst).As16()
	copy(ip[8:24], sa[:])
	copy(ip[24:40], da[:])
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x86DD)
	return append(append(eth, ip...), tcp...)
}

// frameVLAN builds an 802.1Q VLAN-tagged Ethernet/IPv4/TCP frame.
func frameVLAN(vid uint16, src, dst string, sport, dport uint16, seq, ack uint32, flags uint8, tsval, tsecr uint32, payload []byte) []byte {
	tcp := tcpSeg(sport, dport, seq, ack, flags, tsval, tsecr, payload)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(tcp)))
	ip[8] = 64
	ip[9] = 6
	sa := netip.MustParseAddr(src).As4()
	da := netip.MustParseAddr(dst).As4()
	copy(ip[12:16], sa[:])
	copy(ip[16:20], da[:])
	eth := make([]byte, 18) // dst+src(12) + 802.1Q(4) + ethertype(2)
	binary.BigEndian.PutUint16(eth[12:14], 0x8100)
	binary.BigEndian.PutUint16(eth[14:16], vid&0x0fff)
	binary.BigEndian.PutUint16(eth[16:18], 0x0800)
	return append(append(eth, ip...), tcp...)
}

func recsFrom(frames [][]byte) []*pcapio.Record {
	recs := make([]*pcapio.Record, len(frames))
	base := time.Unix(1700000000, 0)
	for i, f := range frames {
		recs[i] = &pcapio.Record{Time: base.Add(time.Duration(i) * time.Millisecond), Data: f, LinkType: wire.LinkEthernet}
	}
	return recs
}

// TestReplayIPv6: the engine replays an IPv6 flow exactly as it does IPv4 (the
// seq/ack machinery is address-family agnostic).
func TestReplayIPv6(t *testing.T) {
	const c, s = 1000, 500000
	req, resp := []byte("modbus-req"), []byte("modbus-resp")
	frames := [][]byte{
		frame6("fd00::9", "fd00::1", 5000, 502, c, 0, wire.FlagSYN, 100, 0, nil),
		frame6("fd00::1", "fd00::9", 502, 5000, s, c+1, wire.FlagSYN|wire.FlagACK, 900, 100, nil),
		frame6("fd00::9", "fd00::1", 5000, 502, c+1, s+1, wire.FlagACK, 101, 900, nil),
		frame6("fd00::9", "fd00::1", 5000, 502, c+1, s+1, wire.FlagACK|wire.FlagPSH, 102, 900, req),
		frame6("fd00::1", "fd00::9", 502, 5000, s+1, c+1+uint32(len(req)), wire.FlagACK|wire.FlagPSH, 901, 102, resp),
		frame6("fd00::9", "fd00::1", 5000, 502, c+1+uint32(len(req)), s+1+uint32(len(resp)), wire.FlagACK, 103, 901, nil),
		frame6("fd00::9", "fd00::1", 5000, 502, c+1+uint32(len(req)), s+1+uint32(len(resp)), wire.FlagFIN|wire.FlagACK, 104, 901, nil),
		frame6("fd00::1", "fd00::9", 502, 5000, s+1+uint32(len(resp)), c+2+uint32(len(req)), wire.FlagFIN|wire.FlagACK, 902, 104, nil),
	}
	flows := ExtractFlows(recsFrom(frames))
	if len(flows) != 1 {
		t.Fatalf("expected 1 IPv6 flow, got %d", len(flows))
	}
	f := flows[0]
	if !f.Client.Addr.Is6() || f.Server.Port != 502 {
		t.Fatalf("IPv6 orientation wrong: client=%s server=%s", f.Client, f.Server)
	}
	out, c2, peer := driveExtracted(t, f, BehaviorCompliant)
	if !out.Succeeded() {
		t.Fatalf("IPv6 replay failed: phase=%s reason=%q", out.Phase, out.Reason)
	}
	if c2.sess.LiveServerISN.Uint32() != peer.HiddenISN() {
		t.Fatal("IPv6 ISN recovery mismatch")
	}

	// Link-agnostic peer helpers over IPv6: re-segment stays in sync, RST aborts.
	reseg, _, _ := driveExtracted(t, f, BehaviorReSegment)
	if !reseg.Succeeded() {
		t.Fatalf("IPv6 re-segment replay failed: phase=%s reason=%q", reseg.Phase, reseg.Reason)
	}
	rst, _, _ := driveExtracted(t, f, BehaviorResetOnData)
	if !rst.Aborted {
		t.Fatalf("IPv6 RST should abort, got phase=%s", rst.Phase)
	}
}

// driveExtracted runs a closed-loop replay for an already-extracted flow.
func driveExtracted(t *testing.T, f *Flow, b PeerBehavior) (Outcome, *Conversation, *MockPeer) {
	t.Helper()
	opts := Options{Seed: 7}
	peer := NewMockPeer(f, b, opts)
	mb := backend.NewMock(peer, f.Packets[0].Rec.LinkType, time.Unix(1700000000, 0))
	c, err := NewConversation(f, opts, ConvConfig{})
	if err != nil {
		t.Fatalf("NewConversation: %v", err)
	}
	out, err := Drive(c, mb, 1000)
	if err != nil {
		t.Fatalf("Drive: %v", err)
	}
	return out, c, peer
}

// TestRewriteAccuracyPreservesPayloadAndChecksums: across address families and L2
// encaps, rewrite changes only seq/ack/timestamps, keeps the payload
// byte-identical, and produces valid IP/transport checksums.
func TestRewriteAccuracyPreservesPayloadAndChecksums(t *testing.T) {
	cases := []struct {
		name   string
		frames [][]byte
	}{
		{"ipv6", [][]byte{
			frame6("fd00::9", "fd00::1", 5000, 502, 1000, 0, wire.FlagSYN, 100, 0, nil),
			frame6("fd00::1", "fd00::9", 502, 5000, 9000, 1001, wire.FlagSYN|wire.FlagACK, 900, 100, nil),
			frame6("fd00::9", "fd00::1", 5000, 502, 1001, 9001, wire.FlagACK|wire.FlagPSH, 101, 900, []byte("payload-bytes-123")),
		}},
		{"vlan-ipv4", [][]byte{
			frameVLAN(42, "10.0.0.9", "10.0.0.1", 5000, 502, 1000, 0, wire.FlagSYN, 100, 0, nil),
			frameVLAN(42, "10.0.0.1", "10.0.0.9", 502, 5000, 9000, 1001, wire.FlagSYN|wire.FlagACK, 900, 100, nil),
			frameVLAN(42, "10.0.0.9", "10.0.0.1", 5000, 502, 1001, 9001, wire.FlagACK|wire.FlagPSH, 101, 900, []byte("payload-bytes-123")),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows := ExtractFlows(recsFrom(tc.frames))
			if len(flows) != 1 {
				t.Fatalf("expected 1 flow, got %d", len(flows))
			}
			rep, err := SimulateRewrite(flows[0], Options{Seed: 3})
			if err != nil {
				t.Fatalf("SimulateRewrite: %v", err)
			}
			if !rep.Consistent() {
				t.Fatalf("rewrite produced %d ack anomalies", rep.Anomalies)
			}
			for i := range rep.Frames {
				p, err := wire.Parse(rep.Frames[i].Data, rep.Frames[i].LinkType)
				if err != nil {
					t.Fatalf("frame %d: parse rewritten: %v", i, err)
				}
				ipOK, l4OK := p.VerifyChecksums()
				if !ipOK || !l4OK {
					t.Fatalf("frame %d: bad checksum after rewrite (ip=%v l4=%v)", i, ipOK, l4OK)
				}
			}
			// The data packet's payload must survive rewrite untouched.
			last := rep.Frames[len(rep.Frames)-1]
			p, _ := wire.Parse(last.Data, last.LinkType)
			if got := string(p.Payload()[:len("payload-bytes-123")]); got != "payload-bytes-123" {
				t.Fatalf("payload corrupted by rewrite: %q", got)
			}
		})
	}
}
