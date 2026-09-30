package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/replay"
)

func TestFaultExpectationExcludesUnrelatedFailures(t *testing.T) {
	reset := &replay.ResponseReadError{Err: &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}}
	for _, tc := range []struct {
		name, cleanup string
		sent          int
		err           error
		want          bool
	}{
		{"response reset", "complete", 1, reset, true},
		{"dial reset", "complete", 1, reset.Err, false},
		{"cleanup failure", "failed", 1, reset, false},
		{"journal failure", "complete", 1, errors.Join(reset, errors.New("journal disk full")), false},
		{"never sent", "complete", 0, reset, false},
		{"ordinary eof", "complete", 1, &replay.ResponseReadError{Err: io.EOF}, false},
		{"maintenance deadline", "complete", 1, context.DeadlineExceeded, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := observeExpectedFault(context.Background(), "reset", tc.sent, tc.cleanup, tc.err)
			if got.Matched != tc.want {
				t.Fatalf("%+v", got)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if observeExpectedFault(ctx, "reset", 1, "complete", reset).Matched {
		t.Fatal("cancellation treated as reproduced reset")
	}
}

func TestFrontDoorsObserveFaultWithoutClaimingMatch(t *testing.T) {
	for _, command := range []struct {
		name string
		run  func([]string) error
	}{{"live", cmdLive}} {
		for _, kind := range []string{"reset", "timeout"} {
			t.Run(command.name+"/"+kind, func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				done := make(chan error, 1)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						done <- err
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
					var request []byte
					one := make([]byte, 1)
					for !strings.Contains(string(request), "\r\n\r\n") {
						if _, err = io.ReadFull(conn, one); err != nil {
							done <- err
							return
						}
						request = append(request, one...)
					}
					if kind == "reset" {
						done <- conn.(*net.TCPConn).SetLinger(0)
						return
					}
					_, _ = io.Copy(io.Discard, conn)
					done <- nil
				}()
				capture := writeIntentHTTP(t, uint16(listener.Addr().(*net.TCPAddr).Port), gzipBody(t), false)
				path := filepath.Join(t.TempDir(), "fault.json")
				err = command.run([]string{capture, "-mode", "application", "-t", "127.0.0.1", "-response-timeout", "150ms", "-expect-fault", kind, "-report", path})
				if err != nil {
					t.Fatal(err)
				}
				if err = <-done; err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var report replayReport
				if err = json.Unmarshal(data, &report); err != nil {
					t.Fatal(err)
				}
				if len(report.Sessions) != 1 {
					t.Fatal(string(data))
				}
				s := report.Sessions[0]
				if s.Fault == nil || !s.Fault.Matched || s.Completed || s.Matched || s.Sent != 1 {
					t.Fatalf("fault conflated with equivalence: %s", data)
				}
			})
		}
	}
}

func TestTLSResponseFaultAndActualRequestCount(t *testing.T) {
	cert, ca := testTLSCertificate(t)
	events, keylog := captureHTTPOverTLS(t, cert)
	capture, keys, roots := writeTLSFixture(t, t.TempDir(), events, keylog, ca)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		request := make([]byte, len("GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
		if _, err = io.ReadFull(conn, request); err != nil {
			done <- err
			return
		}
		_, _ = io.Copy(io.Discard, conn)
		done <- nil
	}()
	path := filepath.Join(t.TempDir(), "tls-fault.json")
	err = cmdLive([]string{capture, "-t", listener.Addr().String(), "-keylog", keys, "-ca", roots, "-server-name", "localhost", "-timeout", "2s", "-response-timeout", "100ms", "-expect-fault", "timeout", "-report", path})
	if err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report reterminationReport
	if err = json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Fault == nil || !report.Fault.Matched || report.Outcome.Requests != 1 || report.Outcome.Completed || report.Outcome.Matched {
		t.Fatalf("%s", data)
	}
}
