package webui

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/livereplay"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/runvars"
	"github.com/kvmukilan/livewire/internal/stateless"
)

// job is one operation (capture or replay) the dashboard polls. Only one runs at a time.
type job struct {
	mu        sync.Mutex
	Kind      string     `json:"kind"`
	Running   bool       `json:"running"`
	Lines     []string   `json:"lines"`
	Done      bool       `json:"done"`
	OK        bool       `json:"ok"`
	Summary   string     `json:"summary"`
	Events    []jobEvent `json:"events"`
	Artifacts []string   `json:"artifacts,omitempty"`
	secrets   []string

	stop   chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
}

type jobEvent struct {
	At      time.Time `json:"at"`
	Stage   string    `json:"stage"`
	Session string    `json:"session,omitempty"`
	Message string    `json:"message"`
}

func (j *job) log(line string) {
	j.mu.Lock()
	line = j.scrubLocked(line)
	j.Lines = append(j.Lines, line)
	j.Events = append(j.Events, jobEvent{At: time.Now(), Stage: "log", Message: line})
	j.mu.Unlock()
}

func (j *job) progress(stage, session, message string) {
	j.mu.Lock()
	message = j.scrubLocked(message)
	j.Events = append(j.Events, jobEvent{At: time.Now(), Stage: stage, Session: session, Message: message})
	j.Lines = append(j.Lines, message)
	j.mu.Unlock()
}

func (j *job) protectVariables(values map[string]string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for name, value := range values {
		if runvars.IsSecret(name) && value != "" {
			j.secrets = append(j.secrets, value)
		}
	}
}

func (j *job) protectValue(value string) {
	if value == "" {
		return
	}
	j.mu.Lock()
	j.secrets = append(j.secrets, value)
	j.mu.Unlock()
}

func (j *job) scrubLocked(line string) string {
	for _, secret := range j.secrets {
		line = strings.ReplaceAll(line, secret, "[REDACTED]")
	}
	return line
}

func (j *job) artifact(name string) {
	j.mu.Lock()
	j.Artifacts = append(j.Artifacts, name)
	j.mu.Unlock()
}

func (j *job) finish(ok bool, summary string) {
	j.mu.Lock()
	j.Running, j.Done, j.OK, j.Summary = false, true, ok, summary
	j.mu.Unlock()
	if j.cancel != nil {
		j.cancel()
	}
}

func (j *job) snapshot() map[string]any {
	j.mu.Lock()
	defer j.mu.Unlock()
	lines := append([]string(nil), j.Lines...)
	events := append([]jobEvent(nil), j.Events...)
	artifacts := append([]string(nil), j.Artifacts...)
	return map[string]any{
		"kind": j.Kind, "running": j.Running, "lines": lines,
		"events": events, "artifacts": artifacts,
		"done": j.Done, "ok": j.OK, "summary": j.Summary,
	}
}

// startJob runs fn in a goroutine, erroring if a job is already active.
func (s *Server) startJob(kind string, fn func(j *job)) (*job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.job != nil && s.job.Running {
		return nil, fmt.Errorf("a %s job is already running; stop it first", s.job.Kind)
	}
	ctx, cancel := context.WithCancel(context.Background())
	j := &job{Kind: kind, Running: true, stop: make(chan struct{}), ctx: ctx, cancel: cancel}
	s.job = j
	go func() {
		defer func() {
			if r := recover(); r != nil {
				j.log(fmt.Sprintf("panic: %v", r))
				j.finish(false, "internal error")
			}
		}()
		fn(j)
	}()
	return j, nil
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	j := s.job
	s.mu.Unlock()
	if j == nil {
		writeJSON(w, map[string]any{"kind": "", "running": false, "lines": []string{}, "done": false})
		return
	}
	writeJSON(w, j.snapshot())
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	j := s.job
	s.mu.Unlock()
	if j != nil && j.Running && j.stop != nil {
		if j.cancel != nil {
			j.cancel()
		}
		select {
		case <-j.stop:
		default:
			close(j.stop)
		}
	}
	writeJSON(w, map[string]any{"ok": true})
}

// --- capture ---

type captureReq struct {
	Iface    string `json:"iface"`
	Out      string `json:"out"`
	Duration int    `json:"duration"` // seconds; 0 = until stopped
}

func (s *Server) handleCapture(w http.ResponseWriter, r *http.Request) {
	var req captureReq
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if req.Iface == "" || req.Out == "" {
		writeErr(w, 400, fmt.Errorf("iface and out are required"))
		return
	}
	out, err := s.pcapPath(req.Out)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	_, err = s.startJob("capture", func(j *job) { s.runCapture(j, req.Iface, out, req.Duration) })
	if err != nil {
		writeErr(w, 409, err)
		return
	}
	writeJSON(w, map[string]any{"started": true})
}

func (s *Server) runCapture(j *job, iface, out string, dur int) {
	b, err := backend.OpenCapture(iface, true)
	if err != nil {
		j.log(err.Error())
		j.finish(false, "open failed")
		return
	}
	defer b.Close()
	f, err := os.Create(out)
	if err != nil {
		j.log(err.Error())
		j.finish(false, "create failed")
		return
	}
	defer f.Close()
	wr, err := pcapio.NewWriter(f, b.LinkType(), true)
	if err != nil {
		j.log(err.Error())
		j.finish(false, "writer failed")
		return
	}
	j.log(fmt.Sprintf("capturing on %s -> %s", iface, out))
	var deadline time.Time
	if dur > 0 {
		deadline = time.Now().Add(time.Duration(dur) * time.Second)
	}
	buf := make([]byte, 65536)
	n := 0
	for {
		select {
		case <-j.stop:
			wr.Flush()
			j.finish(true, fmt.Sprintf("stopped: %d packets", n))
			return
		default:
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			wr.Flush()
			j.finish(true, fmt.Sprintf("done: %d packets in %ds", n, dur))
			return
		}
		nn, ok, err := b.Recv(buf, 500*time.Millisecond)
		if err != nil {
			j.log(err.Error())
			wr.Flush()
			j.finish(false, "recv error")
			return
		}
		if !ok {
			continue
		}
		wr.Write(&pcapio.Record{Time: b.Now(), Data: append([]byte(nil), buf[:nn]...), CapLen: nn, OrigLen: nn, LinkType: b.LinkType()})
		n++
		if n%10 == 0 {
			j.log(fmt.Sprintf("%d packets", n))
		}
	}
}

// --- replay ---

type replayReq struct {
	Pcap     string `json:"pcap"`
	Iface    string `json:"iface"`
	TargetIP string `json:"targetIP"`
	Port     int    `json:"port"`
	Flow     int    `json:"flow"` // -1 = auto (single flow)
	Mode     string `json:"mode"` // "stateful" | "stateless"
	NoGuard  bool   `json:"noGuard"`
	Seed     int64  `json:"seed"`
}

func (s *Server) handleReplay(w http.ResponseWriter, r *http.Request) {
	var req replayReq
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	path, err := s.pcapPath(req.Pcap)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	if req.Iface == "" {
		writeErr(w, 400, fmt.Errorf("iface is required"))
		return
	}
	if _, err := s.startJob("replay", func(j *job) { s.runReplay(j, path, req) }); err != nil {
		writeErr(w, 409, err)
		return
	}
	writeJSON(w, map[string]any{"started": true})
}

func (s *Server) runReplay(j *job, path string, req replayReq) {
	recs, _, err := loadPcap(path)
	if err != nil {
		j.log(err.Error())
		j.finish(false, "load failed")
		return
	}
	if req.Mode == "stateless" {
		s.runStateless(j, recs, req.Iface)
		return
	}
	flows := engine.ExtractFlows(recs)
	if len(flows) == 0 {
		j.log("no TCP flows in capture")
		j.finish(false, "no flows")
		return
	}
	f, err := pickFlow(flows, req.Flow)
	if err != nil {
		j.log(err.Error())
		j.finish(false, "flow select failed")
		return
	}
	targetIP := f.Server.Addr
	targetPort := f.Server.Port
	if req.TargetIP != "" {
		ip, perr := netip.ParseAddr(req.TargetIP)
		if perr != nil {
			j.log("invalid target IP: " + req.TargetIP)
			j.finish(false, "bad target")
			return
		}
		targetIP = ip
	}
	if req.Port > 0 {
		targetPort = uint16(req.Port)
	}
	res, err := livereplay.RunContext(j.ctx, livereplay.Config{
		Flow: f, Iface: req.Iface, TargetIP: targetIP, TargetPort: targetPort,
		Seed: req.Seed, NoGuard: req.NoGuard, Trace: true,
		// Smart defaults, matching the CLI: wait for and validate the device's
		// replies, and stay coherent if it answers differently than the capture.
		Verify: engine.VerifyLenient, Adaptive: true,
	}, j.log)
	if err != nil {
		j.log(err.Error())
		j.finish(false, "replay error")
		return
	}
	j.finish(res.Outcome.Succeeded(), res.Outcome.Phase.String())
}

func (s *Server) runStateless(j *job, recs []*pcapio.Record, iface string) {
	snd, err := backend.OpenSender(iface)
	if err != nil {
		j.log(err.Error())
		j.finish(false, "open failed")
		return
	}
	defer snd.Close()
	sched := stateless.Schedule(recs, stateless.Pace{})
	j.log(fmt.Sprintf("stateless replay: %d frames", len(recs)))
	start := time.Now()
	for i, rec := range recs {
		select {
		case <-j.stop:
			j.finish(true, fmt.Sprintf("stopped after %d frames", i))
			return
		default:
		}
		if d := sched[i] - time.Since(start); d > 0 {
			timer := time.NewTimer(d)
			select {
			case <-j.ctx.Done():
				timer.Stop()
				j.finish(true, fmt.Sprintf("stopped after %d frames", i))
				return
			case <-timer.C:
			}
		}
		if err := snd.Send(rec.Data); err != nil {
			j.log(err.Error())
			j.finish(false, "send error")
			return
		}
	}
	j.finish(true, fmt.Sprintf("sent %d frames", len(recs)))
}

// loadPcap reads all records from a pcap or pcapng file.
func loadPcap(path string) ([]*pcapio.Record, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 1<<16)
	magic, err := br.Peek(4)
	if err != nil {
		return nil, false, err
	}
	type recReader interface {
		Read() (*pcapio.Record, error)
	}
	var rd recReader
	nanos := false
	if binary.LittleEndian.Uint32(magic) == 0x0A0D0D0A { // pcapng section header
		nr, err := pcapio.NewNgReader(br)
		if err != nil {
			return nil, false, err
		}
		rd, nanos = nr, true
	} else {
		r, err := pcapio.NewReader(br)
		if err != nil {
			return nil, false, err
		}
		rd, nanos = r, r.Nanosecond()
	}
	var recs []*pcapio.Record
	for {
		rec, err := rd.Read()
		if err == io.EOF || err != nil {
			break
		}
		cp := *rec
		cp.Data = append([]byte(nil), rec.Data...)
		recs = append(recs, &cp)
	}
	return recs, nanos, nil
}

func pickFlow(flows []*engine.Flow, sel int) (*engine.Flow, error) {
	if sel < 0 {
		if len(flows) != 1 {
			return nil, fmt.Errorf("capture has %d flows; choose one", len(flows))
		}
		return flows[0], nil
	}
	if sel >= len(flows) {
		return nil, fmt.Errorf("flow %d out of range (%d flows)", sel, len(flows))
	}
	return flows[sel], nil
}
