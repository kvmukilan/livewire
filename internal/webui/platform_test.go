package webui

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

func webUDPFrame() []byte {
	u := make([]byte, 9)
	binary.BigEndian.PutUint16(u[0:2], 1200)
	binary.BigEndian.PutUint16(u[2:4], 53)
	binary.BigEndian.PutUint16(u[4:6], uint16(len(u)))
	u[8] = 1
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 64, wire.ProtoUDP
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(u)))
	src, dst := netip.MustParseAddr("192.0.2.1").As4(), netip.MustParseAddr("192.0.2.2").As4()
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	f := append(append(eth, ip...), u...)
	p, _ := wire.Parse(f, wire.LinkEthernet)
	p.RecalcChecksums()
	return p.Buf
}

func writeWebTestPcap(t *testing.T, dir string) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, "sample.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	w, err := pcapio.NewWriter(f, wire.LinkEthernet, true)
	if err != nil {
		t.Fatal(err)
	}
	frame := webUDPFrame()
	if err := w.Write(&pcapio.Record{Time: time.Now(), Data: frame, CapLen: len(frame), OrigLen: len(frame), LinkType: wire.LinkEthernet}); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

func postJSON(t *testing.T, h http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestPlanAndValidationAPIs(t *testing.T) {
	dir := t.TempDir()
	writeWebTestPcap(t, dir)
	h := NewServer(dir).Handler()
	w := postJSON(t, h, "/api/plan", map[string]any{"pcap": "sample.pcap", "profile": "functional"})
	if w.Code != 200 {
		t.Fatalf("plan status=%d body=%s", w.Code, w.Body.String())
	}
	var plan map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if plan["plan"] == nil || plan["sessions"] == nil {
		t.Fatalf("plan response=%v", plan)
	}
	topology := map[string]any{
		"version": 1, "client": map[string]any{"interface": "left"}, "server": map[string]any{"interface": "right"},
		"mappings": []any{
			map[string]any{"role": "client", "captured": map[string]any{"ip": "192.0.2.1", "port": 1200}, "live": map[string]any{"ip": "10.0.0.1", "port": 1200}},
			map[string]any{"role": "server", "captured": map[string]any{"ip": "192.0.2.2", "port": 53}, "live": map[string]any{"ip": "10.0.1.2", "port": 53}},
		},
	}
	w = postJSON(t, h, "/api/validate", map[string]any{"pcap": "sample.pcap", "topology": topology, "scenario": map[string]any{"version": 1, "seed": 1, "rules": []any{}}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"valid":true`) {
		t.Fatalf("validate status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestArtifactTraversalRejectedAndDashboardOffline(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "run.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := NewServer(dir).Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/artifact?name=../secret.json", nil))
	if w.Code != 400 {
		t.Fatalf("traversal status=%d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Protocol-adaptive replay") || strings.Contains(w.Body.String(), "https://") {
		t.Fatalf("dashboard offline/content check failed")
	}
}

func TestAdaptiveRunRejectsInvalidVariableName(t *testing.T) {
	dir := t.TempDir()
	writeWebTestPcap(t, dir)
	h := NewServer(dir).Handler()
	w := postJSON(t, h, "/api/run", map[string]any{
		"pcap": "sample.pcap", "iface": "test0", "targetIP": "192.0.2.2",
		"profile": "functional", "verify": "lenient",
		"variables": map[string]string{"bad name": "value"},
	})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid character") {
		t.Fatalf("invalid variable status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestPlanCompilesInlineRulePack(t *testing.T) {
	dir := t.TempDir()
	writeWebTestPcap(t, dir)
	h := NewServer(dir).Handler()
	w := postJSON(t, h, "/api/plan", map[string]any{
		"pcap": "sample.pcap", "profile": "functional",
		"rulePacks": []any{map[string]any{
			"name":    "vendor-datagram",
			"match":   map[string]any{"transport": "udp", "ports": []int{53}, "prefixHex": "01"},
			"framing": map[string]any{"type": "datagram"},
		}},
	})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"adapter":"rule:vendor-datagram"`) || !strings.Contains(w.Body.String(), `"rule:vendor-datagram":"sha256:`) {
		t.Fatalf("rule-pack plan status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestJobProgressRedactsProtectedValues(t *testing.T) {
	j := &job{}
	j.protectVariables(map[string]string{"mqtt.username": "operator", "mqtt.password": "hunter2", "site": "lab"})
	j.log("authentication operator/hunter2 failed in lab")
	j.progress("error", "mqtt-0", "peer echoed hunter2")
	snapshot := j.snapshot()
	text, _ := json.Marshal(snapshot)
	if strings.Contains(string(text), "operator") || strings.Contains(string(text), "hunter2") || !strings.Contains(string(text), "[REDACTED]") {
		t.Fatalf("job secrets were not redacted: %s", text)
	}
}

func TestSupportBundleAPIProducesDownloadableRedactedZip(t *testing.T) {
	dir := t.TempDir()
	report := `{"tool":"livewire","version":"0.5.0","captureDigest":"sha256:capture","plan":{"entries":[]},"variables":{"mqtt.password":"hunter2"}}`
	if err := os.WriteFile(filepath.Join(dir, "run.json"), []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "actual.pcapng"), []byte("packet hunter2"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := NewServer(dir).Handler()
	w := postJSON(t, h, "/api/bundle", map[string]any{"report": "run.json", "evidence": []string{"actual.pcapng"}})
	if w.Code != http.StatusOK {
		t.Fatalf("bundle status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || !strings.HasSuffix(response.Name, ".support.zip") {
		t.Fatalf("bundle response=%s err=%v", w.Body.String(), err)
	}
	download := httptest.NewRecorder()
	h.ServeHTTP(download, httptest.NewRequest(http.MethodGet, "/api/artifact?name="+response.Name, nil))
	if download.Code != http.StatusOK || !bytes.HasPrefix(download.Body.Bytes(), []byte("PK")) || bytes.Contains(download.Body.Bytes(), []byte("hunter2")) {
		t.Fatalf("bundle download status=%d bytes=%d", download.Code, download.Body.Len())
	}
}
