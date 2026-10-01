package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/recording"
	"github.com/kvmukilan/livewire/internal/wire"
)

func TestCaptureExportChild(t *testing.T) {
	if os.Getenv("LIVEWIRE_CAPTURE_TEST_CHILD") != "1" {
		return
	}
	data, err := os.ReadFile(os.Args[len(os.Args)-1])
	if err != nil {
		os.Exit(2)
	}
	f, err := os.OpenFile(os.Getenv("SSLKEYLOGFILE"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		os.Exit(3)
	}
	if _, err := f.Write(data); err != nil {
		os.Exit(4)
	}
	if err := f.Close(); err != nil {
		os.Exit(5)
	}
	os.Exit(0)
}

type captureTestBackend struct {
	backend.PacketBackend
	remaining []*pcapio.Record
	now       time.Time
	closed    int
	failure   error
}

func (b *captureTestBackend) Recv(buf []byte, timeout time.Duration) (int, bool, error) {
	if len(b.remaining) == 0 {
		time.Sleep(timeout)
		return 0, false, b.failure
	}
	r := b.remaining[0]
	b.remaining = b.remaining[1:]
	b.now = r.Time
	return copy(buf, r.Data), true, nil
}
func (b *captureTestBackend) Now() time.Time          { return b.now }
func (b *captureTestBackend) LinkType() wire.LinkType { return wire.LinkEthernet }
func (b *captureTestBackend) Close() error            { b.closed++; return nil }

func TestTLSRecordingToStatefulLive(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			t.Setenv("LIVEWIRE_CAPTURE_TEST_CHILD", "1")
			cert, ca := testTLSCertificate(t)
			events, keys := captureHTTPOverTLSVersion(t, cert, version)
			_, unrelated := captureHTTPOverTLSVersion(t, cert, version)
			classic, exportSeed, caPath := writeTLSFixture(t, t.TempDir(), events, append(append([]byte{}, keys...), unrelated...), ca)
			capture, err := pcapio.LoadFile(classic, pcapio.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			b := &captureTestBackend{remaining: capture.Records}
			path := filepath.Join(t.TempDir(), "recorded.pcapng")
			err = captureTLS("test", path, 0, 5*time.Second, false,
				[]string{os.Args[0], "-test.run=^TestCaptureExportChild$", "--", exportSeed},
				func(string, bool) (backend.PacketBackend, error) { return b, nil })
			if err != nil {
				t.Fatal(err)
			}
			if b.closed != 1 {
				t.Fatalf("backend close count %d", b.closed)
			}
			saved, err := pcapio.LoadFile(path, pcapio.DefaultLimits())
			if err != nil || len(saved.Records) != len(capture.Records) {
				t.Fatalf("recording round trip: %v", err)
			}
			for _, line := range strings.Split(string(unrelated), "\n") {
				if line != "" && bytes.Contains(saved.TLSKeyLog(), []byte(line)) {
					t.Fatal("unrelated TLS secret embedded")
				}
			}
			if err := os.Remove(exportSeed); err != nil {
				t.Fatal(err)
			}
			target, done := startTLSHTTPPeer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			reportPath := filepath.Join(t.TempDir(), "live.json")
			if err := cmdLive([]string{path, "-t", target, "-ca", caPath, "-strict", "-report", reportPath}); err != nil {
				t.Fatal(err)
			}
			if peer := awaitTLSHTTPPeer(t, done); peer.err != nil {
				t.Fatal(peer.err)
			}
			data, err := os.ReadFile(reportPath)
			if err != nil {
				t.Fatal(err)
			}
			var report reterminationReport
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			if !report.Outcome.ApplicationReplayCompleted || !report.Outcome.Matched || !report.Outcome.Verified || report.Outcome.TLSSecretsSource != "embedded" {
				t.Fatalf("recording did not replay: %+v", report.Outcome)
			}
		})
	}
}

func TestTLSRecordingIncompletePreservesEvidence(t *testing.T) {
	for _, mode := range []string{"no-export", "malformed", "unmatched", "backend-error"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("LIVEWIRE_CAPTURE_TEST_CHILD", "1")
			cert, ca := testTLSCertificate(t)
			events, keys := captureHTTPOverTLS(t, cert)
			classic, seed, _ := writeTLSFixture(t, t.TempDir(), events, keys, ca)
			switch mode {
			case "no-export":
				keys = nil
			case "malformed":
				keys = []byte("private-malformed-data\n")
			case "unmatched":
				_, keys = captureHTTPOverTLS(t, cert)
			}
			if err := os.WriteFile(seed, keys, 0600); err != nil {
				t.Fatal(err)
			}
			capture, err := pcapio.LoadFile(classic, pcapio.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			b := &captureTestBackend{remaining: capture.Records}
			if mode == "backend-error" {
				b.failure = errors.New("test capture failure")
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "incomplete.pcapng")
			err = captureTLS("test", path, 0, 5*time.Second, false,
				[]string{os.Args[0], "-test.run=^TestCaptureExportChild$", "--", seed},
				func(string, bool) (backend.PacketBackend, error) { return b, nil })
			if err == nil || !strings.Contains(err.Error(), "partial capture") || strings.Contains(err.Error(), "private-malformed-data") {
				t.Fatalf("incomplete recording diagnostic: %v", err)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("incomplete recording published as complete")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatalf("partial evidence missing: %v", err)
			}
			partial, err := pcapio.LoadFile(filepath.Join(dir, entries[0].Name()), pcapio.DefaultLimits())
			if err != nil || len(partial.Records) != len(capture.Records) {
				t.Fatalf("partial evidence damaged: %v", err)
			}
		})
	}
}

func TestTLSRecordingInputValidationAndNoOverwrite(t *testing.T) {
	for _, args := range [][]string{
		{"-i", "invalid", "-o", "x.pcap", "-tls", "--", "app"},
		{"-i", "invalid", "-o", "x.pcapng", "-tls"},
		{"-i", "invalid", "-o", "x.pcapng", "-tls", "app"},
		{"-i", "invalid", "-o", "x.pcap", "stray"},
	} {
		if err := cmdCapture(args); err == nil {
			t.Fatalf("accepted %q", args)
		}
	}
	path := filepath.Join(t.TempDir(), "exists.pcapng")
	if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	called := false
	err := captureTLS("test", path, 0, time.Second, false, []string{"app"}, func(string, bool) (backend.PacketBackend, error) {
		called = true
		return nil, errors.New("should not open")
	})
	if err == nil || called {
		t.Fatal("existing output did not fail before capture or application launch")
	}
	if _, _, err := recording.MatchSecrets(&pcapio.Capture{}, bytes.Repeat([]byte{'x'}, (1<<20)+1)); err == nil {
		t.Fatal("oversized key log accepted")
	}
}

func TestRecordingMatchesExplicitFTPSAndRejectsGaps(t *testing.T) {
	cert, ca := testTLSCertificate(t)
	events, keys := captureHTTPOverTLS(t, cert)
	// Only the TLS record envelope matters here; application replay/FTP parsing
	// is covered separately by the FTPS integration suite.
	events = append([]tlsWireEvent{{client: false, data: []byte("220 ready\r\n")}, {client: true, data: []byte("AUTH TLS\r\n")}, {client: false, data: []byte("234 continue\r\n")}}, events...)
	path, _, _ := writeTLSFixture(t, t.TempDir(), events, keys, ca)
	capture, err := pcapio.LoadFile(path, pcapio.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	matched, count, err := recording.MatchSecrets(&capture, keys)
	if err != nil || count != 1 || len(matched) == 0 {
		t.Fatalf("explicit FTPS key matching failed: count=%d err=%v", count, err)
	}
	// Removing a payload-bearing handshake packet makes its TCP stream
	// unrecoverable. No key may be attached to a guessed/reconstructed hello.
	for i, record := range capture.Records {
		packet, err := wire.Parse(record.Data, record.LinkType)
		if err == nil && packet.IsTCP() && len(packet.Payload()) > 20 && packet.Payload()[0] == 22 {
			capture.Records = append(capture.Records[:i], capture.Records[i+1:]...)
			break
		}
	}
	if _, _, err := recording.MatchSecrets(&capture, keys); err == nil {
		t.Fatal("incomplete handshake received embedded secrets")
	}
}
