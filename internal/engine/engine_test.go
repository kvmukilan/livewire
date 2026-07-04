package engine

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

// frameTS builds an Ethernet/IPv4/TCP frame carrying a timestamp option.
func frameTS(src, dst string, sport, dport uint16, seq, ack uint32, flags uint8, tsval, tsecr uint32, payload []byte) []byte {
	opts := []byte{0x01, 0x01, 0x08, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(opts[4:8], tsval)
	binary.BigEndian.PutUint32(opts[8:12], tsecr)
	tcpHdr := 20 + len(opts)
	tcp := make([]byte, tcpHdr+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = byte((tcpHdr / 4) << 4)
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 0xffff)
	copy(tcp[20:], opts)
	copy(tcp[tcpHdr:], payload)

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

// session builds a full request/response TCP flow as a slice of records.
func session(cli, srv string, sport, dport uint16, req, resp []byte) []*pcapio.Record {
	const C, S = 1000, 500000
	frames := [][]byte{
		frameTS(cli, srv, sport, dport, C, 0, wire.FlagSYN, 100, 0, nil),
		frameTS(srv, cli, dport, sport, S, C+1, wire.FlagSYN|wire.FlagACK, 900, 100, nil),
		frameTS(cli, srv, sport, dport, C+1, S+1, wire.FlagACK, 101, 900, nil),
		frameTS(cli, srv, sport, dport, C+1, S+1, wire.FlagACK|wire.FlagPSH, 102, 900, req),
		frameTS(srv, cli, dport, sport, S+1, C+1+uint32(len(req)), wire.FlagACK|wire.FlagPSH, 901, 102, resp),
		frameTS(cli, srv, sport, dport, C+1+uint32(len(req)), S+1+uint32(len(resp)), wire.FlagACK, 103, 901, nil),
		frameTS(cli, srv, sport, dport, C+1+uint32(len(req)), S+1+uint32(len(resp)), wire.FlagFIN|wire.FlagACK, 104, 901, nil),
		frameTS(srv, cli, dport, sport, S+1+uint32(len(resp)), C+2+uint32(len(req)), wire.FlagFIN|wire.FlagACK, 902, 104, nil),
	}
	recs := make([]*pcapio.Record, len(frames))
	base := time.Unix(1700000000, 0)
	for i, fr := range frames {
		recs[i] = &pcapio.Record{Time: base.Add(time.Duration(i) * time.Millisecond), Data: fr, LinkType: wire.LinkEthernet}
	}
	return recs
}

func TestExtractAndOrient(t *testing.T) {
	recs := session("10.0.0.9", "10.0.0.1", 5000, 502, []byte("req"), []byte("response"))
	flows := ExtractFlows(recs)
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	f := flows[0]
	if f.Client.Port != 5000 || f.Server.Port != 502 {
		t.Fatalf("orientation wrong: client=%s server=%s", f.Client, f.Server)
	}
	if !f.HasSyn || !f.HasSynAck || !f.TSClient || !f.TSServer {
		t.Fatalf("handshake/TS not detected: syn=%v synack=%v tsc=%v tss=%v", f.HasSyn, f.HasSynAck, f.TSClient, f.TSServer)
	}
}

func TestRewriteMaintainsSequence(t *testing.T) {
	recs := session("10.0.0.9", "10.0.0.1", 5000, 502, []byte("req"), []byte("response"))
	f := ExtractFlows(recs)[0]
	rep, err := SimulateRewrite(f, Options{Seed: 42})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Consistent() {
		t.Fatalf("rewrite not consistent: %d anomalies", rep.Anomalies)
	}
	// Rewrite must actually change the numbers (fresh ISNs).
	if rep.ClientDelta == 0 && rep.ServerDelta == 0 {
		t.Fatal("deltas are both zero; ISNs were not changed")
	}
	for _, r := range rep.Rows {
		if r.AckSet && !r.AckAligned {
			t.Fatalf("packet %d ack not aligned: %s", r.Index, r.Note)
		}
	}
}

func TestLiveDryRunLearnsHiddenISN(t *testing.T) {
	recs := session("10.0.0.9", "10.0.0.1", 5000, 502, []byte("req"), []byte("response"))
	f := ExtractFlows(recs)[0]
	rep, err := LiveDryRun(f, Options{Seed: 7})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.HandshakeOK {
		t.Fatal("handshake did not complete")
	}
	if rep.LearnedServerISN != rep.PeerServerISN {
		t.Fatalf("engine failed to recover hidden server ISN: peer=0x%08x learned=0x%08x", rep.PeerServerISN, rep.LearnedServerISN)
	}
	if !rep.Succeeded() {
		t.Fatalf("dry run failed: %d mismatches", rep.Mismatches)
	}
}

// TestProtocolAgnostic: only TCP headers are rewritten, so Modbus, DNP3, and HTTP all succeed.
func TestProtocolAgnostic(t *testing.T) {
	modbus := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0a}     // read holding regs
	dnp3 := []byte{0x05, 0x64, 0x0b, 0xc4, 0x01, 0x00, 0x0a, 0x00, 0x12, 0x34, 0xc0, 0xc1, 0x01} // link+transport+app
	http := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")

	cases := []struct {
		name         string
		serverPort   uint16
		req          []byte
		resp         []byte
		wantProtocol string
	}{
		{"modbus", 502, modbus, []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x00, 0x64}, "Modbus/TCP"},
		{"dnp3", 20000, dnp3, []byte{0x05, 0x64, 0x0a, 0x44, 0x0a, 0x00, 0x01, 0x00, 0xff, 0xff, 0xc0, 0xc1, 0x81}, "DNP3"},
		{"http", 80, http, []byte("HTTP/1.1 200 OK\r\n\r\n"), "HTTP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recs := session("10.0.0.9", "10.0.0.1", 5000, tc.serverPort, tc.req, tc.resp)
			f := ExtractFlows(recs)[0]
			if got := ProtocolGuess(f.Server.Port, f.Client.Port); got != tc.wantProtocol {
				t.Fatalf("protocol guess = %q, want %q", got, tc.wantProtocol)
			}
			rw, err := SimulateRewrite(f, Options{Seed: 1})
			if err != nil || !rw.Consistent() {
				t.Fatalf("%s: rewrite inconsistent: %v", tc.name, err)
			}
			dr, err := LiveDryRun(f, Options{Seed: 1})
			if err != nil || !dr.Succeeded() {
				t.Fatalf("%s: peer dry run failed (mismatches=%d)", tc.name, dr.Mismatches)
			}
		})
	}
}

func TestMultiFlow(t *testing.T) {
	var recs []*pcapio.Record
	recs = append(recs, session("10.0.0.9", "10.0.0.1", 5000, 502, []byte("a"), []byte("b"))...)
	recs = append(recs, session("10.0.0.8", "10.0.0.2", 6000, 20000, []byte("cc"), []byte("dd"))...)
	flows := ExtractFlows(recs)
	if len(flows) != 2 {
		t.Fatalf("expected 2 flows, got %d", len(flows))
	}
	for i, f := range flows {
		rep, err := LiveDryRun(f, Options{Seed: int64(i + 1)})
		if err != nil || !rep.Succeeded() {
			t.Fatalf("flow %d dry run failed", i)
		}
	}
}
