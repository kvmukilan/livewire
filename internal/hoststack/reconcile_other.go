//go:build !linux

package hoststack

// Windows WinDivert rules are handle scoped and disappear when the process
// exits. Other platforms do not install persistent iptables rules.
func reconcileOwned(Rule) error { return nil }
