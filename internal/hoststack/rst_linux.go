//go:build linux

package hoststack

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// runner executes a command and returns combined output; injectable for tests.
type runner func(name string, args ...string) ([]byte, error)

func execRunner(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.Bytes(), err
}

// iptablesSuppressor drops outbound RSTs to the target via an iptables/ip6tables
// OUTPUT rule. Needs root (CAP_NET_ADMIN).
type iptablesSuppressor struct {
	rule Rule
	bin  string
	run  runner
}

func newSuppressor(r Rule) (Suppressor, error) {
	return &iptablesSuppressor{rule: r, bin: iptablesBin(r), run: execRunner}, nil
}

func (s *iptablesSuppressor) Arm() error {
	if _, err := exec.LookPath(s.bin); err != nil {
		return fmt.Errorf("hoststack: %s not found in PATH; install it or run without RST suppression: %w", s.bin, err)
	}
	if out, err := s.run(s.bin, iptablesArgs(s.rule, "-I")...); err != nil {
		return fmt.Errorf("hoststack: installing RST-drop rule failed (%s): %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (s *iptablesSuppressor) Disarm() error {
	// Delete the same rule; ignore "doesn't exist" so double-cleanup is safe.
	if out, err := s.run(s.bin, iptablesArgs(s.rule, "-D")...); err != nil {
		msg := strings.ToLower(string(out))
		if strings.Contains(msg, "no chain") || strings.Contains(msg, "does a matching rule exist") || strings.Contains(msg, "bad rule") {
			return nil
		}
		return fmt.Errorf("hoststack: removing RST-drop rule failed (%s): %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (s *iptablesSuppressor) Describe() string {
	return fmt.Sprintf("%s %s", s.bin, strings.Join(iptablesArgs(s.rule, "-I"), " "))
}
