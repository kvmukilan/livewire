// Package webui serves livewire's browser dashboard: an embedded page backed
// by a small net/http JSON API. No framework, no build step. It exposes the same
// operations as the CLI (capture, flow inspection, replay, RST rules, SSH).
package webui

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/kvmukilan/livewire/internal/buildinfo"
	"github.com/kvmukilan/livewire/internal/hoststack"
)

// Server holds dashboard state: the pcap working dir, the running job, and armed RST guards.
type Server struct {
	dir        string
	root       *os.Root
	csrfToken  string
	listenAddr string
	unsafe     bool
	version    string
	initErr    error

	mu       sync.Mutex
	job      *job
	rstRules map[string]*hoststack.Guard // keyed by "ip:port"
	closed   bool
}

type Config struct {
	Dir          string
	ListenAddr   string
	UnsafeListen bool
	Version      string
}

// NewServer builds a dashboard server rooted at dir (where pcaps are read/written).
func NewServer(dir string) *Server {
	s, err := NewServerWithConfig(Config{Dir: dir})
	if err != nil {
		return &Server{dir: dir, initErr: err, rstRules: map[string]*hoststack.Guard{}}
	}
	return s
}

func NewServerWithConfig(cfg Config) (*Server, error) {
	dir := cfg.Dir
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, errors.Join(fmt.Errorf("generate dashboard CSRF token: %w", err), root.Close())
	}
	if cfg.Version == "" {
		cfg.Version = buildinfo.Version
	}
	return &Server{
		dir: abs, root: root, csrfToken: base64.RawURLEncoding.EncodeToString(secret),
		listenAddr: cfg.ListenAddr, unsafe: cfg.UnsafeListen, version: cfg.Version, rstRules: map[string]*hoststack.Guard{},
	}, nil
}

func (s *Server) CSRFToken() string { return s.csrfToken }

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
	mux.HandleFunc("/api/ftp", s.handleFTP)
	mux.HandleFunc("/api/rstrule", s.handleRSTRule)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/stop", s.handleStop)
	return s.secure(mux)
}

var apiMethods = map[string]string{
	"/api/ifaces": http.MethodGet, "/api/pcaps": http.MethodGet,
	"/api/artifact": http.MethodGet, "/api/status": http.MethodGet,
	"/api/flows": http.MethodPost, "/api/plan": http.MethodPost,
	"/api/run": http.MethodPost, "/api/lab": http.MethodPost,
	"/api/validate": http.MethodPost, "/api/bundle": http.MethodPost,
	"/api/capture": http.MethodPost, "/api/replay": http.MethodPost,
	"/api/ssh": http.MethodPost, "/api/rstrule": http.MethodPost,
	"/api/ftp":  http.MethodPost,
	"/api/stop": http.MethodPost,
}

func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if s.initErr != nil {
			writeErr(w, http.StatusInternalServerError, s.initErr)
			return
		}
		if !s.unsafe && s.listenAddr != "" && !loopbackHost(r.Host) {
			writeErr(w, http.StatusForbidden, fmt.Errorf("dashboard Host must be loopback"))
			return
		}
		want, api := apiMethods[r.URL.Path]
		if api && r.Method != want {
			w.Header().Set("Allow", want)
			writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("method %s is not allowed", r.Method))
			return
		}
		if api && want == http.MethodPost {
			mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || mediaType != "application/json" {
				writeErr(w, http.StatusUnsupportedMediaType, fmt.Errorf("Content-Type must be application/json"))
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(origin, r.Host) {
				writeErr(w, http.StatusForbidden, fmt.Errorf("cross-origin dashboard request rejected"))
				return
			}
			got := r.Header.Get("X-Livewire-CSRF")
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.csrfToken)) != 1 {
				writeErr(w, http.StatusForbidden, fmt.Errorf("missing or invalid CSRF token"))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func loopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func sameOrigin(origin, host string) bool {
	for _, prefix := range []string{"http://", "https://"} {
		if strings.HasPrefix(strings.ToLower(origin), prefix) {
			return strings.EqualFold(strings.TrimSuffix(origin[len(prefix):], "/"), host)
		}
	}
	return false
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := bytes.Replace(indexHTML, []byte("__LIVEWIRE_CSRF__"), []byte(s.csrfToken), 1)
	_, _ = w.Write(page)
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
	rootDir, err := s.root.Open(".")
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	entries, err := rootDir.ReadDir(-1)
	if err != nil {
		writeErr(w, 500, errors.Join(err, rootDir.Close()))
		return
	}
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
	if err := rootDir.Close(); err != nil {
		writeErr(w, 500, err)
		return
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
	lower := strings.ToLower(clean)
	if !strings.HasSuffix(lower, ".pcap") && !strings.HasSuffix(lower, ".pcapng") {
		return "", fmt.Errorf("capture name must end in .pcap or .pcapng")
	}
	if s.root == nil {
		return "", fmt.Errorf("dashboard root is unavailable")
	}
	f, err := s.root.Open(clean)
	if err != nil {
		return "", err
	}
	info, err := f.Stat()
	closeErr := f.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("capture is not a regular file")
	}
	return filepath.Join(s.dir, clean), nil
}

// openRootedPath reopens a previously validated dashboard path through os.Root.
// Reopening at the point of use prevents symlink/reparse-point swaps from
// turning validation into access outside the configured directory.
func (s *Server) openRootedPath(path string) (*os.File, error) {
	name := filepath.Base(path)
	if name == "." || path != filepath.Join(s.dir, name) {
		return nil, fmt.Errorf("artifact path is outside the dashboard root")
	}
	return s.root.Open(name)
}

func (s *Server) readRootedBytes(path string, limit int64) ([]byte, error) {
	f, err := s.openRootedPath(path)
	if err != nil {
		return nil, err
	}
	b, readErr := io.ReadAll(io.LimitReader(f, limit+1))
	closeErr := f.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("artifact exceeds %d bytes", limit)
	}
	return b, nil
}

func (s *Server) pcapOutputPath(name string) (string, error) {
	clean := filepath.Base(name)
	if clean != name || clean == "" {
		return "", fmt.Errorf("invalid pcap name")
	}
	lower := strings.ToLower(clean)
	if !strings.HasSuffix(lower, ".pcap") && !strings.HasSuffix(lower, ".pcapng") {
		return "", fmt.Errorf("capture name must end in .pcap or .pcapng")
	}
	if _, err := s.root.Lstat(clean); err == nil {
		return "", fmt.Errorf("capture already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
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
	const maxAPIRequest = 1 << 20
	b, err := io.ReadAll(io.LimitReader(r.Body, maxAPIRequest+1))
	if err = errors.Join(err, r.Body.Close()); err != nil {
		return err
	}
	if len(b) > maxAPIRequest {
		return fmt.Errorf("request body exceeds %d bytes", maxAPIRequest)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("request contains trailing JSON")
	}
	return nil
}

// Shutdown stops background work and releases every privileged resource.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	j := s.job
	guards := make([]*hoststack.Guard, 0, len(s.rstRules))
	for _, guard := range s.rstRules {
		guards = append(guards, guard)
	}
	s.rstRules = map[string]*hoststack.Guard{}
	s.mu.Unlock()

	var errs []error
	if j != nil {
		j.stopNow()
		select {
		case <-j.done:
		case <-ctx.Done():
			errs = append(errs, ctx.Err())
		}
	}
	for _, guard := range guards {
		if err := guard.Release(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.root != nil {
		if err := s.root.Close(); err != nil {
			errs = append(errs, err)
		}
		s.root = nil
	}
	return errors.Join(errs...)
}
