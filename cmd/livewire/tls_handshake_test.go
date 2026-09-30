package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLiveTLSWithoutSecretsCompletesOnlyFreshHandshake(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, form := range []struct{ legacy, strictExit bool }{{false, false}, {true, false}, {true, true}} {
			t.Run(fmt.Sprintf("%x/in=%v/strictExit=%v", version, form.legacy, form.strictExit), func(t *testing.T) {
				cert, ca := testTLSCertificate(t)
				events, keys := captureHTTPOverTLSVersion(t, cert, version)
				capture, _, caPath := writeTLSFixture(t, t.TempDir(), events, keys, ca)
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				done := make(chan error, 1)
				go func() {
					raw, err := listener.Accept()
					if err != nil {
						done <- err
						return
					}
					defer raw.Close()
					_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
					peer := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
					if err := peer.Handshake(); err != nil {
						done <- err
						return
					}
					var b [1]byte
					n, err := peer.Read(b[:])
					if n != 0 || err != io.EOF {
						done <- fmt.Errorf("handshake-only client sent application data or failed close: n=%d err=%v", n, err)
						return
					}
					done <- nil
				}()
				reportPath := filepath.Join(t.TempDir(), "handshake.json")
				args := []string{capture, "-t", listener.Addr().String(), "-ca", caPath, "-timeout", "2s", "-report", reportPath}
				if form.legacy {
					args = append([]string{"-in"}, args...)
				}
				if form.strictExit {
					args = append(args, "-strict-exit")
				}
				err = cmdLive(args)
				if form.strictExit && (err == nil || !strings.Contains(err.Error(), "strict exit")) || !form.strictExit && err != nil {
					t.Fatalf("wrong handshake exit behavior: %v", err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
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
				if !o.HandshakeCompleted || !o.PeerIdentityChecked || o.Completed || o.ApplicationReplayCompleted || o.Verified || o.Matched || o.Requests != 0 || o.Responses != 0 || o.Compared != 0 || o.Observed != 0 || o.Expected != 0 || o.Status != "incomplete" || o.ReasonCode != "captured_plaintext_unavailable" || o.Cleanup != "complete" || o.TLSSecretsSource != "none" {
					t.Fatalf("handshake misrepresented: %+v", o)
				}
				if o.FreshClientHello == nil || o.CapturedClientHello == nil || o.FreshClientHello.RandomSHA256 == o.CapturedClientHello.RandomSHA256 || o.ProtocolVersion != tls.VersionName(version) {
					t.Fatalf("fresh metadata evidence missing: %+v", o)
				}
				if len(report.ReplayPlan.Entries) != 1 || report.ReplayPlan.Entries[0].Fidelity != "handshake" {
					t.Fatalf("incorrect plan: %+v", report.ReplayPlan)
				}
			})
		}
	}
}

func TestTLSHandshakeRejectsUnsupportedControlsAndOutputCollisionBeforeDial(t *testing.T) {
	cert, ca := testTLSCertificate(t)
	events, keys := captureHTTPOverTLS(t, cert)
	capture, _, caPath := writeTLSFixture(t, t.TempDir(), events, keys, ca)
	for _, flags := range [][]string{{"-strict"}, {"-under-load"}, {"-response-timeout", "1s"}, {"-expect-fault", "reset"}, {"-stop-when-different"}, {"-set", "http.host=other"}, {"-scenario", "absent.json"}, {"-state-dir", filepath.Join(t.TempDir(), "state")}, {"-request", "absent.http"}, {"-keylog", "absent.keys"}, {"-report", filepath.Join(t.TempDir(), "existing.json")}} {
		t.Run(flags[0], func(t *testing.T) {
			listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if flags[0] == "-report" {
				if err := os.WriteFile(flags[1], []byte("retained"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			args := append([]string{capture, "-t", listener.Addr().String(), "-ca", caPath}, flags...)
			if err := cmdLive(args); err == nil {
				t.Fatal("unsupported operation accepted")
			}
			_ = listener.SetDeadline(time.Now().Add(20 * time.Millisecond))
			conn, err := listener.AcceptTCP()
			if conn != nil {
				conn.Close()
				t.Fatal("preflight failure dialed target")
			}
			if e, ok := err.(net.Error); !ok || !e.Timeout() {
				t.Fatalf("no-dial observation failed: %v", err)
			}
			if flags[0] == "-report" {
				data, err := os.ReadFile(flags[1])
				if err != nil || string(data) != "retained" {
					t.Fatal("existing output changed")
				}
			}
		})
	}
}
