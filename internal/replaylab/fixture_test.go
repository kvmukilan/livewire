package replaylab

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/tlsreplay"
)

func TestMQTTFixturesPreservePacingAndIndependentBaseline(t *testing.T) {
	for _, name := range []string{"mqtt311", "mqtt5", "mqtt311-tls", "mqtt5-tls"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			dir := t.TempDir()
			fixture, err := registry[name].Setup(ctx, dir)
			if err != nil {
				t.Fatal(err)
			}
			defer fixture.Close()
			if counts := fixture.Snapshot(); counts != (Counters{}) {
				t.Fatalf("capture generation contacted the live drifted broker: %+v", counts)
			}
			file, err := os.Open(fixture.Capture)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			reader, err := pcapio.NewReader(file)
			if err != nil {
				t.Fatal(err)
			}
			var records []*pcapio.Record
			for {
				record, err := reader.Read()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				records = append(records, record)
			}
			trace := replay.ExtractTrace(records, replay.ExtractOptions{})
			if len(trace.Sessions) != 1 || len(trace.Raw) != 0 {
				t.Fatalf("fixture is not one complete TCP connection: %+v", trace)
			}
			if records[len(records)-1].Time.Sub(records[0].Time) < 2*time.Second {
				t.Fatal("fixture lost the keepalive exercise interval")
			}
			client, server, err := replay.TCPPayloadStreams(trace.Sessions[0])
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(name, "-tls") {
				keys, err := os.Open(filepath.Join(dir, "fixture.keys"))
				if err != nil {
					t.Fatal(err)
				}
				defer keys.Close()
				keylog, err := tlsreplay.ParseKeyLog(keys)
				if err != nil {
					t.Fatal(err)
				}
				messages, err := tlsreplay.NewDecryptor(keylog).DecryptFlow(client, server)
				if err != nil {
					t.Fatalf("TLS baseline cannot be independently decrypted: %v", err)
				}
				client, server = nil, nil
				for _, message := range messages {
					if message.Role == tlsreplay.FromClient {
						client = append(client, message.Data...)
					} else {
						server = append(server, message.Data...)
					}
				}
			}
			for direction, data := range map[replay.Direction][]byte{replay.ClientToServer: client, replay.ServerToClient: server} {
				messages, err := (adapters.MQTT{}).Decode(direction, data)
				want := 7
				if direction == replay.ServerToClient {
					want = 6
				}
				if err != nil || len(messages) != want {
					t.Fatalf("baseline direction %v has %d messages, want %d: %v", direction, len(messages), want, err)
				}
			}
			if err := fixture.Close(); err != nil || fixture.Snapshot().ActiveConnections != 0 {
				t.Fatalf("fixture cleanup failed: %v", err)
			}
		})
	}
}
