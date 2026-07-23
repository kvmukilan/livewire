// Package webui serves livewire's browser dashboard: an embedded page backed
// by a small net/http JSON API. No framework, no build step. It exposes the same
// operations as the CLI (capture, flow inspection, replay, RST rules, SSH).
package webui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/kvmukilan/livewire/internal/hoststack"
)

// Server holds dashboard state: the pcap working dir, the running job, and armed RST guards.
type Server struct {
	dir string

	mu       sync.Mutex
	job      *job
	rstRules map[string]*hoststack.Guard // keyed by "ip:port"
}

// NewServer builds a dashboard server rooted at dir (where pcaps are read/written).
func NewServer(dir string) *Server {
	if dir == "" {
		dir = "."
	}
	return &Server{dir: dir, rstRules: map[string]*hoststack.Guard{}}
}

// Handler returns the HTTP handler for the dashboard.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/ifaces", s.handleIfaces)
	mux.HandleFunc("/api/pcaps", s.handlePcaps)
	mux.HandleFunc("/api/flows", s.handleFlows)
	mux.HandleFunc("/api/plan", s.handlePlan)
	mux.HandleFunc("/api/run", s.handleAdaptiveRun)
	mux.HandleFunc("/api/lab", s.handleLab)
	mux.HandleFunc("/api/validate", s.handleValidate)
	mux.HandleFunc("/api/artifact", s.handleArtifact)
	mux.HandleFunc("/api/bundle", s.handleBundle)
	mux.HandleFunc("/api/capture", s.handleCapture)
	mux.HandleFunc("/api/replay", s.handleReplay)
	mux.HandleFunc("/api/ssh", s.handleSSH)
	mux.HandleFunc("/api/rstrule", s.handleRSTRule)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/stop", s.handleStop)
	return mux
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

// --- interfaces ---

type ifaceInfo struct {
	Value string   `json:"value"` // the -iface value to pass
	Label string   `json:"label"`
	IPs   []string `json:"ips"`
	Kind  string   `json:"kind"` // "afpacket" | "npcap" | "loopback"
}

type addrRow struct {
	Name string   `json:"name"`
	IPs  []string `json:"ips"`
}

func (s *Server) handleIfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, addrs := listInterfaces()
	writeJSON(w, map[string]any{"interfaces": ifaces, "addrs": addrs})
}

// netInterfaceAddrs returns the host's interfaces and their IPs.
func netInterfaceAddrs() []addrRow {
	var rows []addrRow
	ifis, err := net.Interfaces()
	if err != nil {
		return rows
	}
	for _, ifi := range ifis {
		var ips []string
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				ips = append(ips, ipn.IP.String())
			}
		}
		rows = append(rows, addrRow{Name: ifi.Name, IPs: ips})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows
}

// --- pcaps ---

type pcapFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

func (s *Server) handlePcaps(w http.ResponseWriter, r *http.Request) {
	entries, _ := os.ReadDir(s.dir)
	var out []pcapFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, ".pcap") || strings.HasSuffix(n, ".pcapng") {
			if fi, err := e.Info(); err == nil {
				out = append(out, pcapFile{Name: n, Size: fi.Size()})
			}
		}
	}
	writeJSON(w, out)
}

// pcapPath resolves a client-supplied name to a path inside s.dir, rejecting traversal.
func (s *Server) pcapPath(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("no pcap named")
	}
	clean := filepath.Base(name)
	if clean != name {
		return "", fmt.Errorf("invalid pcap name")
	}
	return filepath.Join(s.dir, clean), nil
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func decodeBody(r *http.Request, v any) error {
	defer r.Body.Close()
	const maxAPIRequest = 16 << 20
	b, err := io.ReadAll(io.LimitReader(r.Body, maxAPIRequest+1))
	if err != nil {
		return err
	}
	if len(b) > maxAPIRequest {
		return fmt.Errorf("request body exceeds %d bytes", maxAPIRequest)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("request contains trailing JSON")
	}
	return nil
}
