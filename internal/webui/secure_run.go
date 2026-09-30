package webui

import (
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/kvmukilan/livewire/internal/iterate"
	"github.com/kvmukilan/livewire/internal/orchestration"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/replayintent"
	"github.com/kvmukilan/livewire/internal/runvars"
	"github.com/kvmukilan/livewire/internal/secureexec"
)

type secureInputs struct {
	Keylog         string   `json:"keylog,omitempty"`
	CA             string   `json:"ca,omitempty"`
	ServerName     string   `json:"serverName,omitempty"`
	User           string   `json:"user,omitempty"`
	Password       string   `json:"password,omitempty"`
	PrivateKey     string   `json:"privateKey,omitempty"`
	HostKey        string   `json:"hostKey,omitempty"`
	Commands       []string `json:"commands,omitempty"`
	Expects        []string `json:"expects,omitempty"`
	TimeoutSeconds int      `json:"timeoutSeconds,omitempty"`
	Insecure       bool     `json:"insecureSkipVerify,omitempty"`
	keylogData     []byte
	keylogSource   string
}

func (s *Server) startSecureRun(w http.ResponseWriter, req adaptiveRunReq, digest string, in *replayintent.Inspection, registry *replay.Registry) {
	if in.Plan.Profile != replay.ProfileFunctional {
		writeErr(w, 400, fmt.Errorf("fresh secure sessions require functional profile; timing is not supported"))
		return
	}
	sec := req.Secure
	if in.Route.Kind == replayintent.TLS && len(sec.keylogData) == 0 && len(req.RulePacks) > 0 {
		writeErr(w, 400, fmt.Errorf("rule packs require TLS application plaintext; without matching secrets only a fresh handshake is available"))
		return
	}
	if sec.TimeoutSeconds == 0 {
		sec.TimeoutSeconds = 30
	}
	cfg := secureexec.Config{Inspection: in, Registry: registry, Target: req.TargetIP, ServerName: sec.ServerName, User: sec.User, Password: sec.Password, Commands: sec.Commands, Expects: sec.Expects, Variables: req.Variables, Insecure: sec.Insecure, Timeout: time.Duration(sec.TimeoutSeconds) * time.Second, Verify: replay.VerifyMode(req.Verify)}
	cfg.KeyLog = append([]byte(nil), sec.keylogData...)
	for _, item := range []struct {
		name string
		ext  []string
		dst  *[]byte
	}{
		{sec.CA, []string{".pem", ".crt"}, &cfg.CA},
		{sec.PrivateKey, []string{".pem", ".key", ".txt"}, &cfg.PrivateKey},
		{sec.HostKey, []string{".pub", ".txt"}, &cfg.HostKey},
	} {
		if item.name == "" {
			continue
		}
		p, err := s.existingArtifactPath(item.name, item.ext...)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		*item.dst, err = s.readRootedBytes(p, 4<<20)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
	}
	prepared, err := secureexec.Prepare(cfg)
	if err != nil {
		writeErr(w, 400, fmt.Errorf("%s", runvars.NewRedactor(req.Variables, sec.Password).Text(err.Error())))
		return
	}

	_, err = s.startJob("secure-replay", func(j *job) {
		j.protectVariables(req.Variables)
		j.protectValue(sec.Password)
		j.protectValue(sec.User)
		for _, v := range append(append([]string(nil), sec.Commands...), sec.Expects...) {
			j.protectValue(v)
		}
		gap := defaultWebGap
		if req.GapMS != nil {
			gap = time.Duration(*req.GapMS) * time.Millisecond
		}
		runs := iterate.Plan{Times: req.Attempts, Gap: gap}.Normalize()
		ok := true
		stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
		per := runs.Run(j.ctx, func(index int) iterate.Tally {
			j.progress("attempt", "", fmt.Sprintf("Attempt %d of %d", index+1, runs.Times))
			outcome, runErr := prepared.Run(j.ctx)
			outcome.TLSSecretsSource = sec.keylogSource
			if !outcome.Completed {
				ok = false
			}
			if runErr != nil {
				outcome.Error = runErr.Error()
				j.log(runErr.Error())
				ok = false
			}
			name := fmt.Sprintf("secure-%s.attempt-%d.report.json", stamp, index+1)
			doc := map[string]any{"tool": "livewire", "version": s.version, "kind": in.Route.Kind, "when": time.Now().UTC(), "captureDigest": digest, "replayPlan": in.Plan, "mode": in.Mode, "selectedPackets": in.SelectedPackets, "excludedPackets": in.ExcludedPackets, "target": req.TargetIP, "outcome": outcome, "variables": runvars.Redacted(req.Variables), "limitations": in.Plan.Limitations()}
			secrets := append(append([]string{sec.User, sec.Password}, sec.Commands...), sec.Expects...)
			if err := orchestration.WriteJSON(filepath.Join(s.dir, name), doc, runvars.NewRedactor(req.Variables, secrets...)); err != nil {
				j.log(err.Error())
				ok = false
			} else {
				j.artifact(name)
			}
			var tally iterate.Tally
			tally.Add(iterate.ClassifyVerified(outcome.Completed, outcome.Verified, outcome.Matched, false))
			j.progress("result", in.Route.Session.ID, tally.Worst().Plain())
			return tally
		})
		summary := iterate.SummarizeContext(j.ctx, per, runs.Times)
		j.finish(ok && j.ctx.Err() == nil, summary.Plain())
	})
	if err != nil {
		writeErr(w, 409, err)
		return
	}
	writeJSON(w, map[string]any{"started": true})
}

func (s *Server) planningKeyLog(name string) ([]byte, error) {
	if name == "" {
		return nil, nil
	}
	path, err := s.existingArtifactPath(name, ".keylog", ".log", ".txt", ".keys")
	if err != nil {
		return nil, err
	}
	return s.readRootedBytes(path, 4<<20)
}

func (s *Server) selectTLSKeys(name string, embedded []byte) ([]byte, string, error) {
	keys, err := s.planningKeyLog(name)
	if err != nil {
		return nil, "", err
	}
	return secureexec.SelectTLSKeyLog(embedded, keys, name != "")
}
