package webui

import (
	"fmt"
	"net/http"
	"net/netip"
	"sort"

	"github.com/kvmukilan/livewire/internal/hoststack"
)

// handleRSTRule adds or removes a standalone host-RST drop rule, keyed by target
// ip:port. Lets an operator drop the host's resets for an external tool without
// running a replay; rules live until removed or the server exits.
func (s *Server) handleRSTRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"` // "add" | "del" | "list"
		IP     string `json:"ip"`
		Port   int    `json:"port"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}

	if req.Action == "list" {
		writeJSON(w, map[string]any{"rules": s.rstRuleKeys()})
		return
	}

	ip, err := netip.ParseAddr(req.IP)
	if err != nil {
		writeErr(w, 400, fmt.Errorf("invalid IP %q", req.IP))
		return
	}
	if req.Port <= 0 || req.Port > 65535 {
		writeErr(w, 400, fmt.Errorf("invalid port %d", req.Port))
		return
	}
	key := fmt.Sprintf("%s:%d", ip, req.Port)

	s.mu.Lock()
	defer s.mu.Unlock()
	switch req.Action {
	case "add":
		if _, exists := s.rstRules[key]; exists {
			writeJSON(w, map[string]any{"ok": true, "note": "rule already active", "rules": s.rstRuleKeysLocked()})
			return
		}
		guard, err := hoststack.Arm(hoststack.Rule{TargetIP: ip, TargetPort: uint16(req.Port)})
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		s.rstRules[key] = guard
		writeJSON(w, map[string]any{"ok": true, "armed": guard.Describe(), "rules": s.rstRuleKeysLocked()})
	case "del":
		guard, exists := s.rstRules[key]
		if !exists {
			writeJSON(w, map[string]any{"ok": true, "note": "no such rule", "rules": s.rstRuleKeysLocked()})
			return
		}
		guard.Release()
		delete(s.rstRules, key)
		writeJSON(w, map[string]any{"ok": true, "rules": s.rstRuleKeysLocked()})
	default:
		writeErr(w, 400, fmt.Errorf("unknown action %q", req.Action))
	}
}

func (s *Server) rstRuleKeys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rstRuleKeysLocked()
}

func (s *Server) rstRuleKeysLocked() []string {
	keys := make([]string, 0, len(s.rstRules))
	for k := range s.rstRules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
