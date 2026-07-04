package main

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/classify"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

func ethTCP(src, dst string, sport, dport uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 0xffff)
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
	copy(eth[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(eth[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	return append(append(eth, ip...), tcp...)
}

// writeHandshakePcap writes a 5-packet client/server TCP session and returns the path.
func writeHandshakePcap(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "session.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w, err := pcapio.NewWriter(f, wire.LinkEthernet, true)
	if err != nil {
		t.Fatal(err)
	}
	cli, srv := "10.0.0.9", "10.0.0.1"
	frames := [][]byte{
		ethTCP(cli, srv, 5000, 80, 1000, 0, wire.FlagSYN, nil),
		ethTCP(srv, cli, 80, 5000, 9000, 1001, wire.FlagSYN|wire.FlagACK, nil),
		ethTCP(cli, srv, 5000, 80, 1001, 9001, wire.FlagACK, nil),
		ethTCP(cli, srv, 5000, 80, 1001, 9001, wire.FlagACK|wire.FlagPSH, []byte("GET / HTTP/1.0\r\n\r\n")),
		ethTCP(srv, cli, 80, 5000, 9001, 1019, wire.FlagACK|wire.FlagPSH, []byte("HTTP/1.0 200 OK\r\n\r\n")),
	}
	base := time.Unix(1700000000, 500000000).UTC()
	for i, fr := range frames {
		if err := w.Write(&pcapio.Record{Time: base.Add(time.Duration(i) * time.Millisecond), Data: fr}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestE2EInfoRewritePrep(t *testing.T) {
	dir := t.TempDir()
	in := writeHandshakePcap(t, dir)

	if err := cmdInfo([]string{"-v", in}); err != nil {
		t.Fatalf("info: %v", err)
	}

	// rewrite: pnat 10.0.0.0/8 -> 172.16.0.0/12, portmap 80->8080.
	out := filepath.Join(dir, "rw.pcap")
	err := cmdRewrite([]string{
		"-in", in, "-out", out,
		"-pnat", "10.0.0.0/8,172.16.0.0/12",
		"-portmap", "80:8080",
	})
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	// Verify the rewrite: addresses remapped, ports changed, checksums valid.
	verifyRewrite(t, out)

	// prep: auto classification -> cache with 3 client + 2 server packets.
	cache := filepath.Join(dir, "session.cache")
	if err := cmdPrep([]string{"-in", in, "-out", cache, "-mode", "auto"}); err != nil {
		t.Fatalf("prep: %v", err)
	}
	cf, err := os.Open(cache)
	if err != nil {
		t.Fatal(err)
	}
	defer cf.Close()
	c, _, err := classify.ReadCache(cf)
	if err != nil {
		t.Fatal(err)
	}
	pri, sec, _ := c.Counts()
	if pri != 3 || sec != 2 {
		t.Fatalf("cache counts pri=%d sec=%d, want 3/2", pri, sec)
	}
}

func verifyRewrite(t *testing.T, path string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := pcapio.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		rec, err := r.Read()
		if err != nil {
			break
		}
		n++
		p, err := wire.Parse(rec.Data, rec.LinkType)
		if err != nil {
			t.Fatalf("parse rewritten packet: %v", err)
		}
		// 10.0.0.9 -> 172.16.0.9, 10.0.0.1 -> 172.16.0.1 (host bits preserved).
		if p.SrcIP().As4()[0] != 172 || p.DstIP().As4()[0] != 172 {
			t.Fatalf("addresses not remapped: %v -> %v", p.SrcIP(), p.DstIP())
		}
		if p.SrcPort() != 8080 && p.DstPort() != 8080 {
			t.Fatalf("port 80 not remapped to 8080: %d -> %d", p.SrcPort(), p.DstPort())
		}
		if ipOK, l4OK := p.VerifyChecksums(); !ipOK || !l4OK {
			t.Fatalf("bad checksum after rewrite: ip=%v l4=%v", ipOK, l4OK)
		}
	}
	if n != 5 {
		t.Fatalf("rewrote %d packets, want 5", n)
	}
}

// minimalPcapng builds SHB + IDB(ns resolution) + one EPB (ts 1600000000.123456789).
func minimalPcapng(data []byte) []byte {
	le := binary.LittleEndian
	out := make([]byte, 0, 128)

	shb := make([]byte, 28)
	le.PutUint32(shb[0:4], 0x0A0D0D0A)
	le.PutUint32(shb[4:8], 28)
	le.PutUint32(shb[8:12], 0x1A2B3C4D)
	le.PutUint16(shb[12:14], 1)
	le.PutUint64(shb[16:24], 0xFFFFFFFFFFFFFFFF)
	le.PutUint32(shb[24:28], 28)
	out = append(out, shb...)

	idb := make([]byte, 32)
	le.PutUint32(idb[0:4], 0x00000001)
	le.PutUint32(idb[4:8], 32)
	le.PutUint16(idb[8:10], uint16(wire.LinkEthernet))
	le.PutUint32(idb[12:16], 262144)
	le.PutUint16(idb[16:18], 9) // if_tsresol
	le.PutUint16(idb[18:20], 1)
	idb[20] = 9 // decimal 10^-9
	le.PutUint32(idb[28:32], 32)
	out = append(out, idb...)

	ticks := uint64(1600000000)*1_000_000_000 + 123456789
	dpad := (len(data) + 3) &^ 3
	total := 8 + 20 + dpad + 4
	epb := make([]byte, total)
	le.PutUint32(epb[0:4], 0x00000006)
	le.PutUint32(epb[4:8], uint32(total))
	le.PutUint32(epb[12:16], uint32(ticks>>32))
	le.PutUint32(epb[16:20], uint32(ticks&0xFFFFFFFF))
	le.PutUint32(epb[20:24], uint32(len(data)))
	le.PutUint32(epb[24:28], uint32(len(data)))
	copy(epb[28:28+len(data)], data)
	le.PutUint32(epb[total-4:total], uint32(total))
	out = append(out, epb...)
	return out
}

func TestE2EConvertPcapng(t *testing.T) {
	dir := t.TempDir()
	// Handwritten minimal pcapng section.
	ngPath := filepath.Join(dir, "in.pcapng")
	if err := os.WriteFile(ngPath, minimalPcapng(ethTCP("10.0.0.1", "10.0.0.2", 1, 2, 3, 4, wire.FlagSYN, nil)), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.pcap")
	if err := cmdConvert([]string{"-in", ngPath, "-out", out}); err != nil {
		t.Fatalf("convert: %v", err)
	}
	f, _ := os.Open(out)
	defer f.Close()
	r, err := pcapio.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Nanosecond() {
		t.Fatal("converted output should be nanosecond resolution")
	}
	rec, err := r.Read()
	if err != nil {
		t.Fatalf("read converted: %v", err)
	}
	if rec.Time.Nanosecond() != 123456789 {
		t.Fatalf("timestamp nanos lost: %d", rec.Time.Nanosecond())
	}
	p, err := wire.Parse(rec.Data, rec.LinkType)
	if err != nil || !p.IsTCP() {
		t.Fatalf("converted frame parse: %v", err)
	}
}
