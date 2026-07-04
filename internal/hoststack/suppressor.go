// Package hoststack stops the host kernel from RST-ing the unsolicited replies a
// stateful replay provokes. A Suppressor installs an OS-specific rule that drops
// those host-generated RSTs to the target; drive it through a Guard so the rule
// is always torn down.
package hoststack

import (
	"fmt"
	"net/netip"
	"strconv"
)

// Rule describes the connection whose host RSTs to drop. TargetIP and TargetPort
// are required; LocalPort narrows the match to one connection.
type Rule struct {
	TargetIP   netip.Addr
	TargetPort uint16
	LocalPort  uint16 // the captured client's source port; 0 = match any
}

func (r Rule) valid() error {
	if !r.TargetIP.IsValid() {
		return fmt.Errorf("hoststack: rule needs a valid target IP")
	}
	if r.TargetPort == 0 {
		return fmt.Errorf("hoststack: rule needs a non-zero target port")
	}
	return nil
}

// Suppressor installs and removes a host-RST-drop rule for one Rule.
type Suppressor interface {
	// Arm installs the drop rule; a failed Arm leaves nothing behind.
	Arm() error
	// Disarm removes the rule; safe to call if Arm never ran.
	Disarm() error
	// Describe summarises the mechanism and rule for the CLI preflight.
	Describe() string
}

// Guard ties a Suppressor to Release; defer it (and call it on SIGINT) so an
// interrupted replay doesn't leak the rule.
type Guard struct {
	s     Suppressor
	armed bool
}

// Arm builds the platform Suppressor, installs the rule, and returns a Guard.
func Arm(r Rule) (*Guard, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	s, err := newSuppressor(r)
	if err != nil {
		return nil, err
	}
	if err := s.Arm(); err != nil {
		return nil, err
	}
	return &Guard{s: s, armed: true}, nil
}

// Release removes the rule if it is still armed. Idempotent.
func (g *Guard) Release() error {
	if g == nil || !g.armed {
		return nil
	}
	g.armed = false
	return g.s.Disarm()
}

// Describe exposes the underlying suppressor's description.
func (g *Guard) Describe() string {
	if g == nil || g.s == nil {
		return "no suppressor"
	}
	return g.s.Describe()
}

// iptablesArgs builds the argv for a rule dropping outbound TCP RSTs to the
// target. op is "-I" (insert) or "-D" (delete); the match is identical for both
// so Disarm removes exactly what Arm added.
func iptablesArgs(r Rule, op string) []string {
	args := []string{
		op, "OUTPUT",
		"-p", "tcp",
		"--tcp-flags", "RST", "RST",
		"-d", r.TargetIP.String(),
		"--dport", strconv.Itoa(int(r.TargetPort)),
	}
	if r.LocalPort != 0 {
		args = append(args, "--sport", strconv.Itoa(int(r.LocalPort)))
	}
	return append(args, "-j", "DROP")
}

// iptablesBin selects the right binary for the rule's address family.
func iptablesBin(r Rule) string {
	if r.TargetIP.Is6() && !r.TargetIP.Is4In6() {
		return "ip6tables"
	}
	return "iptables"
}

// winDivertFilter builds the WinDivert filter matching the host's outbound RSTs
// to the target; a DROP-mode handle discards them.
func winDivertFilter(r Rule) string {
	af := "ip"
	if r.TargetIP.Is6() && !r.TargetIP.Is4In6() {
		af = "ipv6"
	}
	f := fmt.Sprintf("outbound and tcp.Rst and %s.DstAddr == %s and tcp.DstPort == %d",
		af, r.TargetIP.String(), r.TargetPort)
	if r.LocalPort != 0 {
		f += fmt.Sprintf(" and tcp.SrcPort == %d", r.LocalPort)
	}
	return f
}
