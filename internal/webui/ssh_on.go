//go:build ssh

package webui

import (
	"fmt"
	"net/http"
	"time"

	"github.com/kvmukilan/livewire/internal/sshreplay"
)

// sshEnabled reports whether this build includes SSH re-termination.
func sshEnabled() bool { return true }

// handleSSH runs an SSH re-termination as a job: connect, replay the commands,
// capture their output. Compiled only under -tags ssh.
func (s *Server) handleSSH(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target   string   `json:"target"` // host:port
		User     string   `json:"user"`
		Password string   `json:"password"`
		Commands []string `json:"commands"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if req.Target == "" || req.User == "" || len(req.Commands) == 0 {
		writeErr(w, 400, fmt.Errorf("target, user, and at least one command are required"))
		return
	}
	cmds := make([]sshreplay.Command, len(req.Commands))
	for i, c := range req.Commands {
		cmds[i] = sshreplay.Command{Run: c}
	}
	if _, err := s.startJob("ssh", func(j *job) {
		j.log(fmt.Sprintf("ssh re-termination -> %s as %s", req.Target, req.User))
		res, err := sshreplay.ReTerminate(sshreplay.Config{
			Address:  req.Target,
			Auth:     sshreplay.Auth{User: req.User, Password: req.Password},
			Commands: cmds,
			Timeout:  15 * time.Second,
		})
		if err != nil {
			j.log(err.Error())
			j.finish(false, "ssh failed")
			return
		}
		for i, out := range res.Outputs {
			j.log(fmt.Sprintf("=== %s ===", req.Commands[i]))
			j.log(string(out))
		}
		j.finish(true, "ssh complete")
	}); err != nil {
		writeErr(w, 409, err)
		return
	}
	writeJSON(w, map[string]any{"started": true})
}
