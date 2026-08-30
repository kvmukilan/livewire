package webui

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/lab"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
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

func webTCPFrame(src, dst string, sport, dport uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12], tcp[13] = 5<<4, flags
	binary.BigEndian.PutUint16(tcp[14:16], 0xffff)
	copy(tcp[20:], payload)
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 64, wire.ProtoTCP
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(tcp)))
	sa, da := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(ip[12:16], sa[:])
	copy(ip[16:20], da[:])
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	return append(append(eth, ip...), tcp...)
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

func writeBlockedTLSPcap(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, "tls.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := pcapio.NewWriter(f, wire.LinkEthernet, true)
	if err != nil {
		t.Fatal(err)
	}
	frames := [][]byte{
		webTCPFrame("192.0.2.10", "192.0.2.20", 40000, 443, 100, 0, wire.FlagSYN, nil),
		webTCPFrame("192.0.2.20", "192.0.2.10", 443, 40000, 900, 101, wire.FlagSYN|wire.FlagACK, nil),
		webTCPFrame("192.0.2.10", "192.0.2.20", 40000, 443, 101, 901, wire.FlagACK, nil),
		webTCPFrame("192.0.2.10", "192.0.2.20", 40000, 443, 101, 901, wire.FlagACK|wire.FlagPSH, []byte{22, 3, 3, 0, 1, 0}),
	}
	base := time.Unix(1_700_000_000, 0)
	for i, frame := range frames {
		if err := w.Write(&pcapio.Record{Time: base.Add(time.Duration(i) * time.Millisecond), Data: frame}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeFTPWebPcap(t *testing.T, dir string, passivePort uint16) {
	t.Helper()
	type timedFrame struct {
		at    time.Duration
		frame []byte
	}
	const client, server = "192.0.2.10", "192.0.2.20"
	var frames []timedFrame
	frames = append(frames,
		timedFrame{0, webTCPFrame(client, server, 41000, 21, 100, 0, wire.FlagSYN, nil)},
		timedFrame{time.Millisecond, webTCPFrame(server, client, 21, 41000, 900, 101, wire.FlagSYN|wire.FlagACK, nil)},
		timedFrame{2 * time.Millisecond, webTCPFrame(client, server, 41000, 21, 101, 901, wire.FlagACK, nil)},
	)
	cseq, sseq := uint32(101), uint32(901)
	control := []struct {
		at      time.Duration
		fromCli bool
		line    string
	}{
		{3 * time.Millisecond, false, "220 ready\r\n"},
		{4 * time.Millisecond, true, "USER capture\r\n"},
		{5 * time.Millisecond, false, "331 password\r\n"},
		{6 * time.Millisecond, true, "PASS capture-secret\r\n"},
		{7 * time.Millisecond, false, "230 logged in\r\n"},
		{8 * time.Millisecond, true, "EPSV\r\n"},
		{9 * time.Millisecond, false, fmt.Sprintf("229 Entering Extended Passive Mode (|||%d|)\r\n", passivePort)},
		{13 * time.Millisecond, true, "RETR file.bin\r\n"},
		{14 * time.Millisecond, false, "150 opening data\r\n"},
		{16 * time.Millisecond, false, "226 transfer complete\r\n"},
		{17 * time.Millisecond, true, "QUIT\r\n"},
		{18 * time.Millisecond, false, "221 bye\r\n"},
	}
	for _, message := range control {
		if message.fromCli {
			frames = append(frames, timedFrame{message.at, webTCPFrame(client, server, 41000, 21, cseq, sseq, wire.FlagACK|wire.FlagPSH, []byte(message.line))})
			cseq += uint32(len(message.line))
		} else {
			frames = append(frames, timedFrame{message.at, webTCPFrame(server, client, 21, 41000, sseq, cseq, wire.FlagACK|wire.FlagPSH, []byte(message.line))})
			sseq += uint32(len(message.line))
		}
	}
	frames = append(frames,
		timedFrame{10 * time.Millisecond, webTCPFrame(client, server, 42000, passivePort, 300, 0, wire.FlagSYN, nil)},
		timedFrame{11 * time.Millisecond, webTCPFrame(server, client, passivePort, 42000, 700, 301, wire.FlagSYN|wire.FlagACK, nil)},
		timedFrame{12 * time.Millisecond, webTCPFrame(client, server, 42000, passivePort, 301, 701, wire.FlagACK, nil)},
		timedFrame{15 * time.Millisecond, webTCPFrame(server, client, passivePort, 42000, 701, 301, wire.FlagACK|wire.FlagPSH, []byte("hello ftp"))},
	)
	sort.Slice(frames, func(i, j int) bool { return frames[i].at < frames[j].at })
	f, err := os.Create(filepath.Join(dir, "ftp.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	w, err := pcapio.NewWriter(f, wire.LinkEthernet, true)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_700_000_000, 0)
	for _, item := range frames {
		if err := w.Write(&pcapio.Record{Time: base.Add(item.at), Data: item.frame}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
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

func testHandler(t *testing.T, dir string) http.Handler {
	t.Helper()
	_, h := testServerHandler(t, dir)
	return h
}

func testServerHandler(t *testing.T, dir string) (*Server, http.Handler) {
	t.Helper()
	s := NewServer(dir)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			t.Errorf("shutdown dashboard: %v", err)
		}
	})
	next := s.Handler()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.Header.Set("X-Livewire-CSRF", s.CSRFToken())
		}
		next.ServeHTTP(w, r)
	})
	return s, h
}

func TestPlanAndValidationAPIs(t *testing.T) {
	dir := t.TempDir()
	writeWebTestPcap(t, dir)
	h := testHandler(t, dir)
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
	h := testHandler(t, dir)
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
	h := testHandler(t, dir)
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
	h := testHandler(t, dir)
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
	h := testHandler(t, dir)
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

func TestDashboardReadAndValidationRoutes(t *testing.T) {
	dir := t.TempDir()
	writeWebTestPcap(t, dir)
	_, h := testServerHandler(t, dir)
	for _, path := range []string{"/", "/api/ifaces", "/api/pcaps", "/api/status"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s status=%d body=%s", path, w.Code, w.Body.String())
		}
	}
	if w := postJSON(t, h, "/api/flows", map[string]any{"pcap": "sample.pcap"}); w.Code != http.StatusOK {
		t.Fatalf("flows status=%d body=%s", w.Code, w.Body.String())
	}
	cases := []struct {
		path string
		body any
	}{
		{"/api/validate", map[string]any{}},
		{"/api/plan", map[string]any{"pcap": "sample.pcap", "profile": "wrong"}},
		{"/api/plan", map[string]any{"pcap": "sample.pcap", "profile": "functional", "udpIdleMs": 3_600_001}},
		{"/api/replay", map[string]any{"pcap": "sample.pcap", "iface": "none", "port": 65536}},
		{"/api/capture", map[string]any{"iface": "", "out": "x.pcap"}},
		{"/api/capture", map[string]any{"iface": "none", "out": "x.txt"}},
		{"/api/lab", map[string]any{"pcap": "sample.pcap", "profile": "functional"}},
		{"/api/ftp", map[string]any{"pcap": "sample.pcap", "target": "bad-target"}},
		{"/api/ftp", map[string]any{"pcap": "sample.pcap", "target": "127.0.0.1:21", "verify": "wrong"}},
		{"/api/rstrule", map[string]any{"action": "add", "ip": "bad", "port": 80}},
		{"/api/rstrule", map[string]any{"action": "add", "ip": "127.0.0.1", "port": 0}},
		{"/api/rstrule", map[string]any{"action": "unknown", "ip": "127.0.0.1", "port": 80}},
	}
	for _, tc := range cases {
		if w := postJSON(t, h, tc.path, tc.body); w.Code != http.StatusBadRequest {
			t.Fatalf("POST %s status=%d body=%s", tc.path, w.Code, w.Body.String())
		}
	}
	if w := postJSON(t, h, "/api/rstrule", map[string]any{"action": "list"}); w.Code != http.StatusOK {
		t.Fatalf("RST list status=%d body=%s", w.Code, w.Body.String())
	}
	if w := postJSON(t, h, "/api/rstrule", map[string]any{"action": "del", "ip": "127.0.0.1", "port": 80}); w.Code != http.StatusOK {
		t.Fatalf("RST delete status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestDashboardFailedJobsAndStatus(t *testing.T) {
	dir := t.TempDir()
	writeWebTestPcap(t, dir)
	s, h := testServerHandler(t, dir)
	closedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddress := closedListener.Addr().String()
	if err := closedListener.Close(); err != nil {
		t.Fatal(err)
	}
	jobs := []struct {
		path string
		body any
	}{
		{"/api/replay", map[string]any{"pcap": "sample.pcap", "iface": "definitely-missing", "mode": "stateful", "flow": -1}},
		{"/api/capture", map[string]any{"iface": "definitely-missing", "out": "captured.pcap", "duration": 1}},
		{"/api/ssh", map[string]any{"target": closedAddress, "user": "secret-user", "password": "secret-pass", "commands": []string{"show"}}},
	}
	for _, tc := range jobs {
		t.Logf("starting expected-failure job %s", tc.path)
		w := postJSON(t, h, tc.path, tc.body)
		if w.Code != http.StatusOK {
			t.Fatalf("start %s status=%d body=%s", tc.path, w.Code, w.Body.String())
		}
		waitServerJob(t, s)
		if snapshot := s.job.snapshot(); snapshot["ok"] == true {
			t.Fatalf("%s unexpectedly succeeded: %v", tc.path, snapshot)
		}
	}
}

func TestBlockedTLSAdaptiveJobFinalizesRedactedReport(t *testing.T) {
	dir := t.TempDir()
	writeBlockedTLSPcap(t, dir)
	s, h := testServerHandler(t, dir)
	w := postJSON(t, h, "/api/run", map[string]any{
		"pcap": "tls.pcap", "iface": "unused", "targetIP": "192.0.2.20",
		"profile": "functional", "verify": "lenient",
		"variables": map[string]string{"ftp.password": "quoted\nsecret\\value"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("run status=%d body=%s", w.Code, w.Body.String())
	}
	waitServerJob(t, s)
	snapshot := s.job.snapshot()
	if snapshot["ok"] != false || !strings.Contains(snapshot["summary"].(string), "sessions") {
		t.Fatalf("snapshot=%v", snapshot)
	}
	artifacts := snapshot["artifacts"].([]string)
	if len(artifacts) != 1 || !strings.HasSuffix(artifacts[0], ".run.json") {
		t.Fatalf("artifacts=%v", artifacts)
	}
	report, err := os.ReadFile(filepath.Join(dir, artifacts[0]))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(report, []byte("quoted")) || bytes.Contains(report, []byte("secret")) || !bytes.Contains(report, []byte("[REDACTED]")) {
		t.Fatalf("report redaction failed: %s", report)
	}
}

func TestDashboardFTPReplayCoordinatesPassiveTransfer(t *testing.T) {
	dataListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dataListener.Close()
	liveDataPort := dataListener.Addr().(*net.TCPAddr).Port
	controlListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer controlListener.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := controlListener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		write := func(line string) error { _, err := conn.Write([]byte(line)); return err }
		if err := write("220 ready\r\n"); err != nil {
			serverErr <- err
			return
		}
		want := []struct{ command, reply string }{
			{"USER live", "331 password\r\n"},
			{"PASS live-secret", "230 logged in\r\n"},
			{"EPSV", fmt.Sprintf("229 Entering Extended Passive Mode (|||%d|)\r\n", liveDataPort)},
		}
		for _, turn := range want {
			line, err := reader.ReadString('\n')
			if err != nil || strings.TrimSpace(line) != turn.command {
				serverErr <- fmt.Errorf("command=%q want=%q err=%v", line, turn.command, err)
				return
			}
			if err := write(turn.reply); err != nil {
				serverErr <- err
				return
			}
		}
		dataConn, err := dataListener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		line, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "RETR file.bin" {
			serverErr <- fmt.Errorf("RETR=%q err=%v", line, err)
			return
		}
		if err := write("150 opening data\r\n"); err != nil {
			serverErr <- err
			return
		}
		_, err = dataConn.Write([]byte("hello ftp"))
		closeErr := dataConn.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			serverErr <- err
			return
		}
		if err := write("226 transfer complete\r\n"); err != nil {
			serverErr <- err
			return
		}
		line, err = reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "QUIT" {
			serverErr <- fmt.Errorf("QUIT=%q err=%v", line, err)
			return
		}
		if err := write("221 bye\r\n"); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	dir := t.TempDir()
	writeFTPWebPcap(t, dir, 40000)
	s, h := testServerHandler(t, dir)
	w := postJSON(t, h, "/api/ftp", map[string]any{
		"pcap": "ftp.pcap", "target": controlListener.Addr().String(), "verify": "strict", "timeoutSeconds": 5,
		"variables": map[string]string{"ftp.user": "live", "ftp.password": "live-secret"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("FTP start status=%d body=%s", w.Code, w.Body.String())
	}
	waitServerJob(t, s)
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	snapshot := s.job.snapshot()
	if snapshot["ok"] != true || !strings.Contains(snapshot["summary"].(string), "FTP complete") {
		t.Fatalf("snapshot=%v", snapshot)
	}
	artifacts := snapshot["artifacts"].([]string)
	report, err := os.ReadFile(filepath.Join(dir, artifacts[0]))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(report, []byte("live-secret")) || !bytes.Contains(report, []byte("[REDACTED]")) {
		t.Fatalf("FTP report redaction failed: %s", report)
	}
}

func TestWebReplayHelpersAndFailureBranches(t *testing.T) {
	dir := t.TempDir()
	writeBlockedTLSPcap(t, dir)
	records, _, err := loadPcap(filepath.Join(dir, "tls.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	trace := replay.ExtractTrace(records, replay.ExtractOptions{})
	if len(trace.Sessions) != 1 {
		t.Fatalf("sessions=%d", len(trace.Sessions))
	}
	session := trace.Sessions[0]
	flows := engine.ExtractFlows(records)
	if len(flows) != 1 {
		t.Fatal("captured flow was not found")
	}
	if _, err := pickFlow(flows, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := pickFlow(flows, 2); err == nil {
		t.Fatal("out-of-range flow accepted")
	}
	if _, err := pickFlow(append(flows, flows[0]), -1); err == nil {
		t.Fatal("ambiguous automatic flow accepted")
	}

	j := &job{}
	registry := adapters.DefaultRegistry()
	target := netip.MustParseAddr("192.0.2.20")
	baseReq := adaptiveRunReq{Iface: "definitely-missing", Verify: "lenient"}
	cases := []struct {
		name    string
		entry   replay.PlanEntry
		session *replay.Session
		flows   []*engine.Flow
		profile replay.Profile
		ctx     context.Context
	}{
		{"wire sender open", replay.PlanEntry{Mode: replay.ModeWire, SessionID: session.ID}, session, flows, replay.ProfileWire, context.Background()},
		{"missing session", replay.PlanEntry{Mode: replay.ModeSemantic, SessionID: "missing"}, nil, flows, replay.ProfileFunctional, context.Background()},
		{"coordinated parse", replay.PlanEntry{Mode: replay.ModeCoordinated, Adapter: "ftp", SessionID: session.ID}, session, flows, replay.ProfileFunctional, context.Background()},
		{"semantic parse", replay.PlanEntry{Mode: replay.ModeSemantic, Adapter: "http", SessionID: session.ID}, session, flows, replay.ProfileFunctional, context.Background()},
		{"missing engine flow", replay.PlanEntry{Mode: replay.ModeStateful, SessionID: session.ID}, session, nil, replay.ProfileFunctional, context.Background()},
		{"stateful backend open", replay.PlanEntry{Mode: replay.ModeStateful, SessionID: session.ID}, session, flows, replay.ProfileFunctional, context.Background()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := runWebEntry(tc.ctx, j, tc.entry, tc.session, map[string]*replay.Session{session.ID: session}, trace.Raw, tc.flows, registry, target, baseReq, tc.profile, replay.VerifyLenient, engine.VerifyLenient, time.Now())
			if result.Error == "" {
				t.Fatalf("result=%+v", result)
			}
		})
	}
	udp := &replay.Session{ID: "udp-0", Transport: replay.TransportUDP, Client: replay.Endpoint{IP: netip.MustParseAddr("192.0.2.10"), Port: 1200}, Server: replay.Endpoint{IP: target, Port: 53}}
	if result := runWebEntry(context.Background(), j, replay.PlanEntry{Mode: replay.ModeStateful, SessionID: udp.ID}, udp, nil, nil, nil, registry, target, baseReq, replay.ProfileFunctional, replay.VerifyLenient, engine.VerifyLenient, time.Now()); result.Error == "" {
		t.Fatalf("UDP failure result=%+v", result)
	}
	evidence := filepath.Join(dir, "evidence.pcapng")
	values := make([]pcapio.Record, len(records))
	for i, record := range records {
		values[i] = *record
	}
	if err := writeWebEvidence(evidence, "test", values); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(evidence); err != nil {
		t.Fatal(err)
	}
	if err := writeWebEvidence(filepath.Join(dir, "empty.pcapng"), "test", nil); err == nil {
		t.Fatal("empty evidence unexpectedly succeeded")
	}

	transformations := webLabTransformations(replay.ReplayPlan{Entries: []replay.PlanEntry{{Transformations: []string{"one", "one"}}}}, lab.Result{
		NAT:       []lab.NATTransformation{{Before: "a", After: "b"}},
		TCPClocks: []lab.TCPClockTransformation{{SessionID: "tcp-0", Direction: "client", Delta: 4}},
	})
	if len(transformations) != 3 {
		t.Fatalf("transformations=%v", transformations)
	}
	if config, err := webFTPTLSConfig("127.0.0.1:990", "", nil, true); err != nil || config.ServerName != "127.0.0.1" || !config.InsecureSkipVerify {
		t.Fatalf("TLS config=%+v err=%v", config, err)
	}
	badCA := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := webFTPTLSConfig("127.0.0.1:990", "localhost", []byte("not a certificate"), false); err == nil {
		t.Fatal("invalid CA accepted")
	}
	if mode, err := parseWebFTPVerify("off"); err != nil || mode != replay.VerifyOff {
		t.Fatalf("off verification=%q err=%v", mode, err)
	}
	statelessJob := &job{ctx: context.Background(), stop: make(chan struct{}), done: make(chan struct{})}
	(&Server{}).runStateless(statelessJob, records, "definitely-missing")
	if !statelessJob.Done || statelessJob.OK {
		t.Fatalf("stateless failure job=%+v", statelessJob.snapshot())
	}
}

func waitServerJob(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		j := s.job
		s.mu.Unlock()
		if j != nil {
			select {
			case <-j.done:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}
	t.Fatal("dashboard job did not finish")
}

func TestLabJobReportsExecutionFailureWithoutSuccess(t *testing.T) {
	dir := t.TempDir()
	writeWebTestPcap(t, dir)
	s := NewServer(dir)
	defer s.Shutdown(context.Background())
	path, err := s.pcapPath("sample.pcap")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	j := &job{Kind: "dut-lab", Running: true, ctx: ctx, cancel: cancel, stop: make(chan struct{}), done: make(chan struct{})}
	s.runLabJob(j, path, labRunReq{Pcap: "sample.pcap", Profile: "functional"})
	if !j.Done || j.OK || !strings.Contains(j.Summary, "stopped") {
		t.Fatalf("job=%+v", j.snapshot())
	}
	if len(j.Artifacts) != 2 {
		t.Fatalf("expected failed-run evidence and report, artifacts=%v", j.Artifacts)
	}
}
