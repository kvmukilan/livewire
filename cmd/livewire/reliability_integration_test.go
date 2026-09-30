package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/compare"
)

func TestApplicationResponseTimeoutAcrossFrontDoors(t *testing.T) {
	body := gzipBody(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(200 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body)
	}))
	defer server.Close()
	capture := writeIntentHTTP(t, uint16(server.Listener.Addr().(*net.TCPAddr).Port), body, false)
	for _, command := range []struct {
		name string
		run  func([]string) error
	}{{"live", cmdLive}} {
		for _, budget := range []string{"40ms", "2s"} {
			t.Run(command.name+"/"+budget, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "result.json")
				err := command.run([]string{capture, "-mode", "application", "-t", "127.0.0.1", "-response-timeout", budget, "-strict-exit", "-report", path})
				wantComplete := budget == "2s"
				if (err == nil) != wantComplete {
					t.Fatalf("response deadline %s: %v", budget, err)
				}
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var report replayReport
				if err = json.Unmarshal(data, &report); err != nil {
					t.Fatal(err)
				}
				if len(report.Sessions) != 1 || report.Sessions[0].Completed != wantComplete || report.Sessions[0].Matched != wantComplete {
					t.Fatalf("deadline produced misleading report: %s", data)
				}
			})
		}
	}
}

func TestCompletedReadResumeDoesNotResendAndAliasesAgree(t *testing.T) {
	body := gzipBody(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.Write(body)
	}))
	defer server.Close()
	capture := writeIntentHTTP(t, uint16(server.Listener.Addr().(*net.TCPAddr).Port), body, false)
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	args := []string{capture, "-mode", "application", "-session", "tcp-0", "-t", "127.0.0.1", "-strict-exit"}
	first := append(append([]string{}, args...), "-state-dir", state, "-report", filepath.Join(dir, "first.json"))
	if e := cmdLive(first); e != nil {
		t.Fatal(e)
	}
	if requests.Load() != 1 {
		t.Fatal("first replay request count differs")
	}
	resumed := append(append([]string{}, args...), "-resume", state, "-report", filepath.Join(dir, "resumed.json"))
	if e := cmdLive(resumed); e != nil {
		t.Fatal(e)
	}
	if requests.Load() != 1 {
		t.Fatal("confirmed session was sent again")
	}
	for _, name := range []string{"first.json", "resumed.json"} {
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		var r replayReport
		if e = json.Unmarshal(b, &r); e != nil {
			t.Fatal(e)
		}
		if len(r.Sessions) != 1 || !r.Sessions[0].Matched {
			t.Fatalf("%s did not preserve match", name)
		}
	}
	preview := append(append([]string{}, args...), "-resume", state, "-dry-run")
	if e := cmdLive(preview); e != nil {
		t.Fatal(e)
	}
	if requests.Load() != 1 {
		t.Fatal("preview sent traffic")
	}
}

func TestOfflineCompareCommandSharesHTTPPolicy(t *testing.T) {
	capture := writeIntentHTTP(t, 80, gzipBody(t), false)
	output := filepath.Join(t.TempDir(), "compare.json")
	if e := cmdCompare([]string{capture, capture, "-json", output, "-strict", "-details"}); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(output)
	if e != nil {
		t.Fatal(e)
	}
	var r compare.Report
	if e = json.Unmarshal(b, &r); e != nil {
		t.Fatal(e)
	}
	if r.Verdict != compare.Matched || len(r.Sessions) != 1 {
		t.Fatalf("%+v", r)
	}
	for _, args := range [][]string{{}, {capture}, {capture, capture, "-udp-idle", "0s"}, {capture, capture, "-unknown"}, {capture, capture, capture}} {
		if e := cmdCompare(args); e == nil {
			t.Fatalf("invalid arguments accepted: %v", args)
		}
	}
}
