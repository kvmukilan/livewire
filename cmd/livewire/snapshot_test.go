package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestCLIReportUsesOriginalSnapshotDuringReplay(t *testing.T) {
	body := gzipBody(t)
	var path string
	ready := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-ready
		if err := os.WriteFile(path, []byte("replaced"), 0600); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body)
	}))
	defer server.Close()
	path = writeIntentHTTP(t, uint16(server.Listener.Addr().(*net.TCPAddr).Port), body, true)
	close(ready)
	want, err := sha256File(path)
	if err != nil {
		t.Fatal(err)
	}
	out, err := runBinary(t, buildBinary(t), "reproduce", path, "--mode", "application", "--session", "tcp-0", "-t", "127.0.0.1")
	if err != nil {
		t.Fatal(err, out)
	}
	data, err := os.ReadFile(strings.TrimSuffix(path, ".pcap") + ".report.json")
	if err != nil {
		t.Fatal(err)
	}
	var report replayReport
	if err = json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.CaptureDigest != want || report.ExcludedPackets != 1 || len(report.Sessions) != 1 || report.Sessions[0].Status != "matched" {
		t.Fatalf("incorrect evidence: %s", data)
	}
}

func TestCLIDisconnectedTargetCannotClaimMatch(t *testing.T) {
	body := gzipBody(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)+100))
		_, _ = w.Write(body[:len(body)/2]) // Peer closes before the promised response.
	}))
	defer server.Close()
	path := writeIntentHTTP(t, uint16(server.Listener.Addr().(*net.TCPAddr).Port), body, false)
	out, err := runBinary(t, buildBinary(t), "reproduce", path, "--mode", "application", "-t", "127.0.0.1")
	// Reproduce preserves its report-oriented exit policy. The report, rather
	// than exit zero, must identify this attempt as incomplete.
	if err != nil {
		t.Fatal("unexpected command failure", err, out)
	}
	data, err := os.ReadFile(strings.TrimSuffix(path, ".pcap") + ".report.json")
	if err != nil {
		t.Fatal(err)
	}
	var report replayReport
	if err = json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Sessions) != 1 || report.Sessions[0].Status != "incomplete" || report.Sessions[0].Matched || report.Sessions[0].Completed {
		t.Fatalf("false completion: %s", data)
	}
}
