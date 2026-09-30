package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

func embeddedTLSCapture(t *testing.T, classic string, keys []byte) string {
	t.Helper()
	capture, err := pcapio.LoadFile(classic, pcapio.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var data bytes.Buffer
	w, err := pcapio.NewNgWriter(&data, []pcapio.NgInterface{{LinkType: wire.LinkEthernet, SnapLen: 65535}})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range capture.Records {
		if err := w.Write(record); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body, 0x544c534b)
	binary.LittleEndian.PutUint32(body[4:], uint32(len(keys)))
	body = append(body, keys...)
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	block := binary.LittleEndian.AppendUint32(nil, 10)
	block = binary.LittleEndian.AppendUint32(block, uint32(len(body)+12))
	block = append(block, body...)
	block = binary.LittleEndian.AppendUint32(block, uint32(len(body)+12))
	data.Write(block)
	path := filepath.Join(t.TempDir(), "embedded.pcapng")
	if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLiveTLSUsesEmbeddedSecretsWithoutExternalKeylog(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, form := range []string{"positional", "in"} {
			t.Run(tls.VersionName(version)+"/"+form, func(t *testing.T) {
				cert, ca := testTLSCertificate(t)
				events, keys := captureHTTPOverTLSVersion(t, cert, version)
				classic, keyPath, caPath := writeTLSFixture(t, t.TempDir(), events, keys, ca)
				capture := embeddedTLSCapture(t, classic, keys)
				if err := os.Remove(keyPath); err != nil {
					t.Fatal(err)
				}
				target, done := startTLSHTTPPeer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
				reportPath := filepath.Join(t.TempDir(), "application.json")
				args := []string{capture, "-t", target, "-ca", caPath, "-strict", "-report", reportPath}
				if form == "in" {
					args = append([]string{"-in"}, args...)
				}
				if err := cmdLive(args); err != nil {
					t.Fatal(err)
				}
				if peer := awaitTLSHTTPPeer(t, done); peer.err != nil || len(peer.request) == 0 {
					t.Fatalf("peer: %+v", peer)
				}
				data, err := os.ReadFile(reportPath)
				if err != nil {
					t.Fatal(err)
				}
				var report reterminationReport
				if err := json.Unmarshal(data, &report); err != nil {
					t.Fatal(err)
				}
				o := report.Outcome
				if !o.Completed || !o.ApplicationReplayCompleted || !o.Verified || !o.Matched || !o.PeerIdentityChecked || o.TLSSecretsSource != "embedded" || o.Requests != 1 || o.Compared != 1 || o.Adapter != "http/1" {
					t.Fatalf("embedded secrets not used: %+v", o)
				}
				_, digest, err := loadCaptureSnapshot(capture)
				if err != nil || report.CaptureDigest != digest {
					t.Fatalf("snapshot not bound: %v", err)
				}
				for _, line := range strings.Split(string(keys), "\n") {
					if f := strings.Fields(line); len(f) == 3 && bytes.Contains(data, []byte(f[2])) {
						t.Fatal("TLS secret leaked into report")
					}
				}
			})
		}
	}
}

func TestEmbeddedTLSSecretsFailClosedAndExplicitKeylogTakesPriority(t *testing.T) {
	cert, ca := testTLSCertificate(t)
	events, keys := captureHTTPOverTLS(t, cert)
	classic, keyPath, caPath := writeTLSFixture(t, t.TempDir(), events, keys, ca)
	capture := embeddedTLSCapture(t, classic, []byte("malformed secret entry\n"))
	if err := cmdLive([]string{capture, "-t", "127.0.0.1:1", "-ca", caPath}); err == nil || !strings.Contains(err.Error(), "embedded TLS secrets") {
		t.Fatalf("malformed embedded secrets fell back: %v", err)
	}
	target, done := startTLSHTTPPeer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	reportPath := filepath.Join(t.TempDir(), "explicit.json")
	if err := cmdLive([]string{capture, "-t", target, "-keylog", keyPath, "-ca", caPath, "-report", reportPath}); err != nil {
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
	if report.Outcome.TLSSecretsSource != "external" || !report.Outcome.Matched {
		t.Fatalf("explicit priority missing: %+v", report.Outcome)
	}
}

func TestLiveInTLSWithoutSecureFlagsUsesFreshSession(t *testing.T) {
	for _, embedded := range []bool{false, true} {
		t.Run(fmt.Sprint(embedded), func(t *testing.T) {
			cert, ca := testTLSCertificate(t)
			events, keys := captureHTTPOverTLS(t, cert)
			capture, _, _ := writeTLSFixture(t, t.TempDir(), events, keys, ca)
			if embedded {
				capture = embeddedTLSCapture(t, capture, keys)
			}
			if err := cmdLive([]string{"-in", capture, "-t", "127.0.0.1:1", "-n", "2", "-dry-run"}); err != nil {
				t.Fatalf("bare -in repeat did not select common TLS planner: %v", err)
			}
			target, done := startTLSHTTPPeer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			reportPath := filepath.Join(t.TempDir(), "rejected-identity.json")
			err := cmdLive([]string{"-in", capture, "-t", target, "-report", reportPath})
			if err == nil || !strings.Contains(err.Error(), "certificate") {
				t.Fatalf("bare -in TLS failed to use verified fresh session: %v", err)
			}
			peer := awaitTLSHTTPPeer(t, done)
			if peer.err == nil || len(peer.request) != 0 {
				t.Fatalf("untrusted handshake sent application data: %+v", peer)
			}
			data, err := os.ReadFile(reportPath)
			if err != nil {
				t.Fatal(err)
			}
			var report reterminationReport
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			want := "none"
			if embedded {
				want = "embedded"
			}
			if report.Outcome.TLSSecretsSource != want || report.Outcome.Completed || report.Outcome.Verified {
				t.Fatalf("incorrect source or success: %+v", report.Outcome)
			}
		})
	}
}
