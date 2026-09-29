package adapters

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/runstate"
)

func TestUncertainWriteRequiresLiveRecoveryProof(t *testing.T) {
	for _, value := range []string{"none", "unknown", "pending", "complete"} {
		t.Run(value, func(t *testing.T) {
			post := []byte("POST /change HTTP/1.1\r\nHost: device.test\r\nContent-Length: 0\r\n\r\n")
			get := []byte("GET /state HTTP/1.1\r\nHost: device.test\r\n\r\n")
			reply := []byte("HTTP/1.1 200 OK\r\nX-State: pending\r\nContent-Length: 0\r\n\r\n")
			session := &replay.Session{ID: "s", Transport: replay.TransportTCP, Events: []replay.Event{
				{Direction: replay.ClientToServer, Payload: post}, {Direction: replay.ServerToClient, Payload: reply},
				{Direction: replay.ClientToServer, Payload: get}, {Direction: replay.ServerToClient, Payload: reply},
			}}
			dir := filepath.Join(t.TempDir(), "run")
			manifest := runstate.Manifest{Version: runstate.Version, CaptureDigest: "capture", ConfigurationDigest: "config"}
			store, err := runstate.Open(dir, manifest, false, false)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = store.Begin("1/s", false); err != nil {
				t.Fatal(err)
			}
			if err = store.Record("1/s", "intent", 1); err != nil {
				t.Fatal(err)
			}
			if err = store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = runstate.Open(dir, manifest, true, false)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			scenario := &replay.Scenario{Version: 1, CaptureDigest: "capture"}
			complete := "complete"
			if value != "none" {
				scenario.Recovery = []replay.RecoveryProbe{{Session: "s", Request: 2, Field: replay.Extraction{Header: "X-State"}, RestartValue: "pending", CompleteValue: &complete}}
			}
			ctx := replay.WithExecution(context.Background(), replay.ExecutionConfig{Journal: store, Scenario: replay.NewScenarioRuntime(scenario)})
			calls := 0
			done := make(chan error, 2)
			dial := func(context.Context, string, string) (net.Conn, error) {
				calls++
				call := calls
				c, s := net.Pipe()
				go func() {
					defer s.Close()
					s.SetDeadline(time.Now().Add(2 * time.Second))
					r := bufio.NewReader(s)
					count := 1
					if call == 2 {
						count = 2
					}
					for i := 0; i < count; i++ {
						q, e := http.ReadRequest(r)
						if e != nil {
							done <- e
							return
						}
						q.Body.Close()
						if call == 1 && q.Method != "GET" {
							done <- fmt.Errorf("write sent before recovery proof")
							return
						}
						if _, e = fmt.Fprintf(s, "HTTP/1.1 200 OK\r\nX-State: %s\r\nContent-Length: 0\r\n\r\n", value); e != nil {
							done <- e
							return
						}
					}
					done <- nil
				}()
				return c, nil
			}
			result, err := replay.RunTCPSemanticContext(ctx, replay.TCPSemanticConfig{Session: session, Adapter: HTTP{}, Verify: replay.VerifyLenient, Timeout: time.Second, Dial: dial})
			wantCalls := 1
			if value == "none" {
				wantCalls = 0
			}
			if value == "pending" {
				wantCalls = 2
			}
			if calls != wantCalls {
				t.Fatalf("connections=%d want %d", calls, wantCalls)
			}
			if value == "unknown" || value == "none" {
				if err == nil || result.Completed {
					t.Fatalf("uncertain write accepted: %+v %v", result, err)
				}
			} else if err != nil || !result.Completed {
				t.Fatalf("recovery failed: %+v %v", result, err)
			}
			if value == "complete" && (result.Verified || result.Matched) {
				t.Fatal("state probe claimed captured response match")
			}
			for i := 0; i < calls; i++ {
				if e := <-done; e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}
