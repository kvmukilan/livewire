package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/lab"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/supportbundle"
)

type planReq struct {
	Pcap      string            `json:"pcap"`
	Profile   string            `json:"profile"`
	RulePacks []json.RawMessage `json:"rulePacks,omitempty"`
	UDPIdleMS int               `json:"udpIdleMs,omitempty"`
}

func registryForRulePacks(packs []json.RawMessage) (*replay.Registry, error) {
	registry := adapters.DefaultRegistry()
	for i, raw := range packs {
		a, err := adapters.CompileRulePackJSON(raw)
		if err != nil {
			return nil, fmt.Errorf("rulePacks[%d]: %w", i, err)
		}
		registry.Register(a)
	}
	return registry, nil
}

func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("POST required"))
		return
	}
	var req planReq
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	path, err := s.pcapPath(req.Pcap)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	records, _, err := loadPcap(path)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	profile, err := replay.ParseProfile(req.Profile)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	if req.UDPIdleMS < 0 {
		writeErr(w, 400, fmt.Errorf("udpIdleMs must not be negative"))
		return
	}
	trace := replay.ExtractTrace(records, replay.ExtractOptions{UDPIdle: time.Duration(req.UDPIdleMS) * time.Millisecond})
	replay.MarkIntrinsicBlockers(trace)
	registry, err := registryForRulePacks(req.RulePacks)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	plan := replay.BuildPlan(trace, profile, registry)
	if err := plan.ValidateCoverage(); err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, map[string]any{
		"capture": map[string]any{"packets": trace.Packets, "sessions": len(trace.Sessions), "rawFrames": len(trace.Raw)},
		"plan":    plan, "limitations": plan.Limitations(), "adapters": registry.Names(), "adapterVersions": adapters.VersionsForRegistry(registry), "sessions": trace.Sessions,
	})
}

type validateReq struct {
	Pcap     string        `json:"pcap,omitempty"`
	Topology *lab.Topology `json:"topology,omitempty"`
	Scenario *lab.Scenario `json:"scenario,omitempty"`
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	var req validateReq
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if req.Topology == nil && req.Scenario == nil {
		writeErr(w, 400, fmt.Errorf("topology or scenario is required"))
		return
	}
	if req.Topology != nil {
		if err := req.Topology.Validate(); err != nil {
			writeErr(w, 400, err)
			return
		}
		if req.Pcap != "" {
			path, err := s.pcapPath(req.Pcap)
			if err != nil {
				writeErr(w, 400, err)
				return
			}
			records, _, err := loadPcap(path)
			if err != nil {
				writeErr(w, 400, err)
				return
			}
			if err := req.Topology.ValidateTrace(replay.ExtractTrace(records, replay.ExtractOptions{})); err != nil {
				writeErr(w, 400, err)
				return
			}
		}
	}
	if req.Scenario != nil {
		if err := req.Scenario.Validate(); err != nil {
			writeErr(w, 400, err)
			return
		}
	}
	writeJSON(w, map[string]any{"valid": true})
}

func (s *Server) handleArtifact(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" || filepath.Base(name) != name {
		writeErr(w, 400, fmt.Errorf("invalid artifact name"))
		return
	}
	lower := strings.ToLower(name)
	if !strings.HasSuffix(lower, ".json") && !strings.HasSuffix(lower, ".pcap") && !strings.HasSuffix(lower, ".pcapng") && !strings.HasSuffix(lower, ".zip") {
		writeErr(w, 400, fmt.Errorf("unsupported artifact type"))
		return
	}
	path := filepath.Join(s.dir, name)
	if _, err := os.Stat(path); err != nil {
		writeErr(w, 404, fmt.Errorf("artifact not found"))
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	http.ServeFile(w, r, path)
}

type bundleReq struct {
	Report   string   `json:"report"`
	Evidence []string `json:"evidence,omitempty"`
}

func (s *Server) handleBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("POST required"))
		return
	}
	var req bundleReq
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if filepath.Base(req.Report) != req.Report || !strings.HasSuffix(strings.ToLower(req.Report), ".json") {
		writeErr(w, 400, fmt.Errorf("report must be a JSON artifact name"))
		return
	}
	reportPath := filepath.Join(s.dir, req.Report)
	var evidencePaths []string
	for _, name := range req.Evidence {
		lower := strings.ToLower(name)
		if filepath.Base(name) != name || !strings.HasSuffix(lower, ".pcap") && !strings.HasSuffix(lower, ".pcapng") {
			writeErr(w, 400, fmt.Errorf("invalid evidence artifact %q", name))
			return
		}
		evidencePaths = append(evidencePaths, filepath.Join(s.dir, name))
	}
	base := strings.TrimSuffix(req.Report, filepath.Ext(req.Report))
	name := base + "." + time.Now().UTC().Format("20060102T150405.000000000Z") + ".support.zip"
	manifest, err := supportbundle.Create(supportbundle.Options{
		ReportPath: reportPath, EvidencePaths: evidencePaths, OutputPath: filepath.Join(s.dir, name), Version: "0.5.0",
	})
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	s.mu.Lock()
	currentJob := s.job
	s.mu.Unlock()
	if currentJob != nil {
		currentJob.artifact(name)
	}
	writeJSON(w, map[string]any{"name": name, "manifest": manifest})
}
