//go:build !ssh

package webui

import (
	"fmt"
	"net/http"
)

// sshEnabled reports whether this build includes SSH re-termination.
func sshEnabled() bool { return false }

// handleSSH reports that SSH support isn't compiled in; rebuild with -tags ssh.
func (s *Server) handleSSH(w http.ResponseWriter, r *http.Request) {
	writeErr(w, 501, fmt.Errorf("SSH support is not in this build; rebuild livewire with -tags ssh"))
}
