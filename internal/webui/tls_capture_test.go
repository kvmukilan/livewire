package webui

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replaylab"
	"github.com/kvmukilan/livewire/internal/secureexec"
	"github.com/kvmukilan/livewire/internal/wire"
)

func TestHandshakeIncompleteStatusPreservesContextFailure(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expire()
	for _, ctx := range []context.Context{canceled, expired} {
		j := &job{ctx: ctx}
		j.finishResult(false, true, "context failed after handshake")
		if j.snapshot()["applicationIncomplete"] == true {
			t.Fatal("context failure became expected handshake-only limitation")
		}
	}
}

func TestDashboardTLSCaptureHandshakeAndEmbeddedSecrets(t *testing.T) {
	for _, embedded := range []bool{false, true} {
		t.Run(fmt.Sprint(embedded), func(t *testing.T) {
			dir := t.TempDir()
			request := []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
			response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			fixture, err := replaylab.SetupStreamFixture(context.Background(), dir, []replaylab.Exchange{{Client: request, Server: response}}, func(conn net.Conn, stats *replaylab.Stats) error {
				if !embedded {
					var b [1]byte
					n, err := conn.Read(b[:])
					if n != 0 || err != io.EOF {
						return fmt.Errorf("unexpected application traffic")
					}
					return nil
				}
				got := make([]byte, len(request))
				if _, err := io.ReadFull(conn, got); err != nil {
					return err
				}
				if !bytes.Equal(got, request) {
					return fmt.Errorf("request differs")
				}
				_, err := conn.Write(response)
				return err
			}, true)
			if err != nil {
				t.Fatal(err)
			}
			defer fixture.Close()
			var target, caPath, keyPath string
			for i := 0; i < len(fixture.Args)-1; i += 2 {
				switch fixture.Args[i] {
				case "-t":
					target = fixture.Args[i+1]
				case "-ca":
					caPath = fixture.Args[i+1]
				case "-keylog":
					keyPath = fixture.Args[i+1]
				}
			}
			keys, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			capture := fixture.Capture
			if embedded {
				capture = webEmbeddedTLSCapture(t, capture, keys)
			}
			s, handler := testServerHandler(t, dir)
			plan := postJSON(t, handler, "/api/plan", map[string]any{"pcap": filepath.Base(capture), "mode": "application", "profile": "functional"})
			if plan.Code != http.StatusOK {
				t.Fatalf("plan: %d %s", plan.Code, plan.Body)
			}
			if !embedded && !strings.Contains(plan.Body.String(), "\"fidelity\":\"handshake\"") {
				t.Fatalf("handshake-only preview missing: %s", plan.Body)
			}
			if embedded {
				var preview struct {
					Readiness struct{ Requirements []string }
				}
				if err := json.Unmarshal(plan.Body.Bytes(), &preview); err != nil {
					t.Fatal(err)
				}
				requirements := strings.Join(preview.Readiness.Requirements, "; ")
				if !strings.Contains(requirements, "embedded in PCAPNG or supplied with -keylog") || strings.Contains(requirements, "matching NSS key log (-keylog)") {
					t.Fatalf("embedded TLS preview demands external-only keys: %s", requirements)
				}
			}
			result := postJSON(t, handler, "/api/run", map[string]any{"pcap": filepath.Base(capture), "targetIP": target, "mode": "application", "profile": "functional", "verify": "lenient", "secure": map[string]any{"ca": filepath.Base(caPath), "timeoutSeconds": 3}})
			if result.Code != http.StatusOK {
				t.Fatalf("start: %d %s", result.Code, result.Body)
			}
			waitServerJob(t, s)
			if got := s.job.snapshot()["applicationIncomplete"]; got != !embedded {
				t.Fatalf("handshake-only application status = %v, want %v", got, !embedded)
			}
			paths, err := filepath.Glob(filepath.Join(dir, "secure-*.report.json"))
			if err != nil || len(paths) != 1 {
				t.Fatalf("reports: %v %v", paths, err)
			}
			data, err := os.ReadFile(paths[0])
			if err != nil {
				t.Fatal(err)
			}
			var report struct{ Outcome secureexec.Outcome }
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			o := report.Outcome
			if embedded {
				if !o.Completed || !o.Verified || !o.Matched || o.TLSSecretsSource != "embedded" {
					t.Fatalf("embedded replay: %+v", o)
				}
			} else {
				if !o.HandshakeCompleted || !o.PeerIdentityChecked || o.Completed || o.Verified || o.Matched || o.TLSSecretsSource != "none" || o.Requests != 0 || s.job.snapshot()["ok"] == true {
					t.Fatalf("handshake mislabeled: %+v", o)
				}
			}
			for _, line := range strings.Split(string(keys), "\n") {
				if fields := strings.Fields(line); len(fields) == 3 && (bytes.Contains(data, []byte(fields[2])) || strings.Contains(plan.Body.String(), fields[2])) {
					t.Fatal("embedded secret exposed")
				}
			}
		})
	}
}

func webEmbeddedTLSCapture(t *testing.T, path string, keys []byte) string {
	t.Helper()
	capture, err := pcapio.LoadFile(path, pcapio.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var data bytes.Buffer
	writer, err := pcapio.NewNgWriter(&data, []pcapio.NgInterface{{LinkType: wire.LinkEthernet, SnapLen: 65535}})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range capture.Records {
		if err := writer.Write(record); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	body := binary.LittleEndian.AppendUint32(nil, 0x544c534b)
	body = binary.LittleEndian.AppendUint32(body, uint32(len(keys)))
	body = append(body, keys...)
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	block := binary.LittleEndian.AppendUint32(nil, 10)
	block = binary.LittleEndian.AppendUint32(block, uint32(len(body)+12))
	block = append(block, body...)
	block = binary.LittleEndian.AppendUint32(block, uint32(len(body)+12))
	data.Write(block)
	output := filepath.Join(filepath.Dir(path), "embedded.pcapng")
	if err := os.WriteFile(output, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return output
}
