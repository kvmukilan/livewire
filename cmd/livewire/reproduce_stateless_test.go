package main

import (
	"bytes"
	"errors"
	"flag"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

func TestReproduceAndReplaySendExactFramesWithUnverifiedReports(t *testing.T) {
	input, records, _ := statelessInterleavedCapture(t)
	for _, command := range []string{"reproduce", "replay"} {
		for _, positional := range []bool{true, false} {
			t.Run(command+map[bool]string{true: "/positional", false: "/in"}[positional], func(t *testing.T) {
				out := filepath.Join(t.TempDir(), "result.json")
				args := []string{input, "-i", "test", "-topspeed", "-n", "2", "-report", out}
				if !positional {
					args = append([]string{"-in"}, args...)
				}
				sender := &statelessTestSender{link: wire.LinkEthernet}
				err := cmdStatelessReplayWithSender(command, args, func(string) (backend.PacketBackend, error) { return sender, nil })
				if err != nil || sender.closed != 1 || len(sender.frames) != 2*len(records) {
					t.Fatalf("err=%v closed=%d sent=%d", err, sender.closed, len(sender.frames))
				}
				for i, frame := range sender.frames {
					if !bytes.Equal(frame, records[i%len(records)].Data) {
						t.Fatalf("frame %d changed or moved", i)
					}
				}
				report := readStatelessReport(t, out)
				if report.Command != command || !report.Completed || report.Verified || report.Status != "wire" || report.Mode != "wire" || report.Passes != 2 || report.FramesSent != len(sender.frames) {
					t.Fatalf("incorrect stateless report: %+v", report)
				}
			})
		}
	}
}

func TestReproduceDoesNotOpenApplicationOrTLSConnections(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	// The captured endpoint is a real listening socket. TLS bytes are opaque:
	// no matching keys are supplied and no live ClientHello should be attempted.
	frames := [][]byte{
		ethTCP("127.0.0.2", "127.0.0.1", 41000, port, 100, 0, wire.FlagSYN, nil),
		ethTCP("127.0.0.1", "127.0.0.2", port, 41000, 900, 101, wire.FlagSYN|wire.FlagACK, nil),
		ethTCP("127.0.0.2", "127.0.0.1", 41000, port, 101, 901, wire.FlagACK|wire.FlagPSH, []byte{22, 3, 3, 0, 1, 0}),
	}
	input := filepath.Join(t.TempDir(), "encrypted.pcap")
	f, err := os.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	w, err := pcapio.NewWriter(f, wire.LinkEthernet, true)
	if err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	for i, frame := range frames {
		if err := w.Write(&pcapio.Record{Time: time.Unix(1, int64(i)), Data: frame}); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
	}
	if err := errors.Join(w.Flush(), f.Close()); err != nil {
		t.Fatal(err)
	}
	sender := &statelessTestSender{link: wire.LinkEthernet}
	if err := cmdStatelessReplayWithSender("reproduce", []string{input, "-i", "test", "-topspeed"}, func(string) (backend.PacketBackend, error) { return sender, nil }); err != nil {
		t.Fatal(err)
	}
	for i, frame := range sender.frames {
		if !bytes.Equal(frame, frames[i]) {
			t.Fatalf("captured TLS frame %d changed", i)
		}
	}
	if len(sender.frames) != len(frames) {
		t.Fatalf("sent=%d want=%d", len(sender.frames), len(frames))
	}
	preview := filepath.Join(t.TempDir(), "preview.json")
	if err := cmdReproduce([]string{input, "-dry-run", "-report", preview}); err != nil {
		t.Fatalf("actual reproduce entry point tried secure replay: %v", err)
	}
	report := readStatelessReport(t, preview)
	if report.Command != "reproduce" || report.Status != "preview" || report.Verified || report.FramesSent != 0 || report.Passes != 0 {
		t.Fatalf("preview made a send/verification claim: %+v", report)
	}
	if err := listener.SetDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.AcceptTCP()
	if err == nil {
		_ = conn.Close()
		t.Fatal("stateless reproduce opened an application/TLS connection")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("listener observation failed: %v", err)
	}
}

func TestReproduceRejectsApplicationFlagsBeforeCaptureOrNetwork(t *testing.T) {
	for _, flags := range [][]string{
		{"-t", "127.0.0.1:443"}, {"--keylog=keys.log"}, {"-ca", "ca.pem"},
		{"-server-name", "localhost"}, {"-user", "operator"}, {"-mode", "application"},
		{"-expect-fault", "reset"}, {"-scenario", "scenario.json"}, {"-resume", "state"},
		{"-insecure-skip-verify=false"}, {"-response-timeout", "1s"},
	} {
		t.Run(strings.Join(flags, " "), func(t *testing.T) {
			args := append([]string{filepath.Join(t.TempDir(), "missing.pcap"), "-i", "test"}, flags...)
			err := cmdStatelessReplayWithSender("reproduce", args, func(string) (backend.PacketBackend, error) {
				t.Fatal("application flags opened sender")
				return nil, nil
			})
			if err == nil || !strings.Contains(err.Error(), "stateless reproduce") || !strings.Contains(err.Error(), "Use live <capture>") || !strings.Contains(err.Error(), "no packets were sent") {
				t.Fatalf("missing early migration guidance: %v", err)
			}
		})
	}
}

func TestStatelessMigrationLexerDoesNotTreatFlagValuesAsOptions(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("in", "", "")
	fs.String("report", "", "")
	fs.Bool("dry-run", false, "")
	for _, args := range [][]string{
		{"-in", "-keylog", "-report", "-t", "-dry-run"},
		{"--in=-keylog", "--report=-t", "-dry-run"},
		{"-dry-run", "--", "-keylog"},
	} {
		if got := applicationOnlyReplayFlag(fs, args); got != "" {
			t.Fatalf("%v falsely selected application option %q", args, got)
		}
	}
}
