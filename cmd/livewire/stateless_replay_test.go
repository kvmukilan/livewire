package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

type statelessTestSender struct {
	link       wire.LinkType
	frames     [][]byte
	failAt     int
	closed     int
	closeError error
}

func (s *statelessTestSender) Send(frame []byte) error {
	if s.failAt > 0 && len(s.frames)+1 == s.failAt {
		return errors.New("injected send failure")
	}
	s.frames = append(s.frames, append([]byte(nil), frame...))
	return nil
}

func (s *statelessTestSender) Recv([]byte, time.Duration) (int, bool, error) {
	panic("stateless replay must not read responses")
}
func (s *statelessTestSender) Now() time.Time             { return time.Now() }
func (s *statelessTestSender) LinkType() wire.LinkType    { return s.link }
func (s *statelessTestSender) Caps() backend.Capabilities { return backend.Layer2 }
func (s *statelessTestSender) Close() error {
	s.closed++
	return s.closeError
}

func readStatelessReport(t *testing.T, path string) wireReplayReport {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result wireReplayReport
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestStatelessReplayReportsPartialSendsAndCloseErrors(t *testing.T) {
	input := writeHandshakePcap(t, t.TempDir())
	records, _, err := loadRecords(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		failAt     int
		closeError error
		wantSent   int
		wantPasses int
	}{
		{"first pass partial", 3, nil, 2, 0},
		{"second pass partial", len(records) + 3, nil, len(records) + 2, 1},
		{"close failure", 0, errors.New("injected close failure"), 2 * len(records), 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "report.json")
			sender := &statelessTestSender{link: wire.LinkEthernet, failAt: tc.failAt, closeError: tc.closeError}
			err := cmdReplayWithSender([]string{"-in", input, "-i", "test", "-topspeed", "-n", "2", "-report", out}, func(string) (backend.PacketBackend, error) { return sender, nil })
			if err == nil || sender.closed != 1 {
				t.Fatalf("err=%v closed=%d", err, sender.closed)
			}
			report := readStatelessReport(t, out)
			if report.Completed || report.Verified || report.Error == "" || report.Status != "incomplete" || report.FramesSent != tc.wantSent || report.Passes != tc.wantPasses {
				t.Fatalf("wrong partial result: %+v", report)
			}
		})
	}
}

func statelessInterleavedCapture(t *testing.T) (string, []*pcapio.Record, []*pcapio.Record) {
	t.Helper()
	records, _, err := loadRecords(writeHandshakePcap(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	var interleaved []*pcapio.Record
	for _, rec := range records {
		interleaved = append(interleaved, rec)
		other := *rec
		other.Data = append([]byte(nil), rec.Data...)
		packet, err := wire.Parse(other.Data, rec.LinkType)
		if err != nil {
			t.Fatal(err)
		}
		if packet.SrcIP().String() == "10.0.0.9" {
			packet.SetSrcIP(netip.MustParseAddr("192.0.2.9"))
			packet.SetDstIP(netip.MustParseAddr("192.0.2.1"))
		} else {
			packet.SetSrcIP(netip.MustParseAddr("192.0.2.1"))
			packet.SetDstIP(netip.MustParseAddr("192.0.2.9"))
		}
		packet.RecalcChecksums()
		// Equal and backwards timestamps must not change capture record order.
		other.Time = records[0].Time
		interleaved = append(interleaved, &other)
	}
	opaque := make([]byte, 60)
	opaque[12], opaque[13] = 0x88, 0xb5
	interleaved = append(interleaved, &pcapio.Record{Time: records[0].Time, Data: opaque, LinkType: wire.LinkEthernet})
	path := filepath.Join(t.TempDir(), "interleaved.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	w, err := pcapio.NewWriter(f, wire.LinkEthernet, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range interleaved {
		if err := w.Write(rec); err != nil {
			t.Fatal(err)
		}
	}
	if err := errors.Join(w.Flush(), f.Close()); err != nil {
		t.Fatal(err)
	}
	return path, interleaved, records
}

func TestStatelessReplayPreservesBothDirectionsAndRecordOrder(t *testing.T) {
	input, records, _ := statelessInterleavedCapture(t)
	out := filepath.Join(t.TempDir(), "report.json")
	sender := &statelessTestSender{link: wire.LinkEthernet}
	err := cmdReplayWithSender([]string{"-in", input, "-i", "test", "-topspeed", "-n", "3", "-report", out}, func(string) (backend.PacketBackend, error) { return sender, nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(sender.frames) != 3*len(records) || sender.closed != 1 {
		t.Fatalf("sent=%d closed=%d", len(sender.frames), sender.closed)
	}
	for i, frame := range sender.frames {
		if !bytes.Equal(frame, records[i%len(records)].Data) {
			t.Fatalf("captured frame %d changed or moved", i)
		}
	}
	report := readStatelessReport(t, out)
	if !report.Completed || report.Verified || report.Status != "wire" || report.FramesSent != len(sender.frames) || report.Passes != 3 {
		t.Fatalf("stateless replay made an incorrect claim: %+v", report)
	}
}

func TestStatelessReplaySessionSelectionKeepsCapturedOrder(t *testing.T) {
	input, _, selected := statelessInterleavedCapture(t)
	sender := &statelessTestSender{link: wire.LinkEthernet}
	err := cmdReplayWithSender([]string{"-in", input, "-i", "test", "-topspeed", "-session", "tcp-0"}, func(string) (backend.PacketBackend, error) { return sender, nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(sender.frames) != len(selected) {
		t.Fatalf("selected frames=%d, want %d", len(sender.frames), len(selected))
	}
	for i, frame := range sender.frames {
		if !bytes.Equal(frame, selected[i].Data) {
			t.Fatalf("selected frame %d changed or moved", i)
		}
	}
}

func TestStatelessReplayRejectsInvalidRatesBeforeOpeningSender(t *testing.T) {
	input := writeHandshakePcap(t, t.TempDir())
	for _, flags := range [][]string{
		{"-pps", "0"}, {"-mbps", "-1"}, {"-multiplier", "0"},
		{"-pps", "NaN"}, {"-mbps", "+Inf"}, {"-multiplier", "-Inf"},
		{"-topspeed", "-pps", "1"}, {"-pps", "2", "-mbps", "3"},
		{"-pps", "1e-300"}, {"-mbps", "1e-300"}, {"-multiplier", "1e-300"},
	} {
		t.Run(strings.Join(flags, " "), func(t *testing.T) {
			args := append([]string{"-in", input, "-i", "test"}, flags...)
			err := cmdReplayWithSender(args, func(string) (backend.PacketBackend, error) {
				t.Fatal("invalid rate opened the packet sender")
				return nil, nil
			})
			if err == nil {
				t.Fatalf("accepted %v", flags)
			}
		})
	}
}

func TestStatelessReplayRejectsInterfaceLinkMismatchBeforeSending(t *testing.T) {
	input := writeHandshakePcap(t, t.TempDir())
	out := filepath.Join(t.TempDir(), "report.json")
	sender := &statelessTestSender{link: wire.LinkNull}
	err := cmdReplayWithSender([]string{"-in", input, "-i", "test", "-report", out}, func(string) (backend.PacketBackend, error) { return sender, nil })
	if err == nil || !strings.Contains(err.Error(), "link type") || len(sender.frames) != 0 || sender.closed != 1 {
		t.Fatalf("err=%v sent=%d closed=%d", err, len(sender.frames), sender.closed)
	}
	report := readStatelessReport(t, out)
	if report.Completed || report.FramesSent != 0 || report.Passes != 0 || report.Verified {
		t.Fatalf("incorrect mismatch report: %+v", report)
	}
}

func TestStatelessReplayRejectsMixedLinksBeforeOpeningSender(t *testing.T) {
	input := filepath.Join(t.TempDir(), "mixed.pcapng")
	f, err := os.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	w, err := pcapio.NewNgWriter(f, []pcapio.NgInterface{{LinkType: wire.LinkEthernet}, {LinkType: wire.LinkRaw}})
	if err != nil {
		t.Fatal(err)
	}
	frame := ethTCP("192.0.2.1", "192.0.2.2", 1234, 80, 1, 0, wire.FlagSYN, nil)
	for i, data := range [][]byte{frame, frame[14:]} {
		if err := w.Write(&pcapio.Record{Time: time.Unix(1, int64(i)), Data: data, InterfaceID: uint32(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := errors.Join(w.Flush(), f.Close()); err != nil {
		t.Fatal(err)
	}
	err = cmdReplayWithSender([]string{"-in", input, "-i", "test"}, func(string) (backend.PacketBackend, error) {
		t.Fatal("mixed capture opened packet sender")
		return nil, fmt.Errorf("unexpected sender open")
	})
	if err == nil || !strings.Contains(err.Error(), "mixes link types") {
		t.Fatalf("mixed-link error=%v", err)
	}
}
