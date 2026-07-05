package main

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/livereplay"
)

// liveReal runs a real stateful replay of one flow via the shared livereplay
// core, adding flow/target selection and the optional TUI dashboard.
func liveReal(flows []*engine.Flow, flowSel int, target string, iface string, seed int64, noGuard bool, useTUI bool, verbose bool) error {
	f, err := selectFlow(flows, flowSel)
	if err != nil {
		return err
	}
	targetIP, targetPort, err := resolveTarget(target, f)
	if err != nil {
		return err
	}

	res, err := livereplay.Run(livereplay.Config{
		Flow: f, Iface: iface, TargetIP: targetIP, TargetPort: targetPort,
		Seed: seed, NoGuard: noGuard, Trace: verbose,
	}, func(line string) { fmt.Println(line) })
	if err != nil {
		return err
	}

	if useTUI {
		out := res.Outcome
		st := tuiFlowState{
			Index: flowSel, Label: fmt.Sprintf("%s -> %s:%d", f.Client, targetIP, targetPort),
			Phase: out.Phase.String(), Sent: out.Sent, Retransmits: out.Retransmits,
			ServerISN: res.LearnedServerISN, Note: out.Reason,
		}
		fmt.Println()
		renderDashboard(iface, fmt.Sprintf("%s:%d", targetIP, targetPort), []tuiFlowState{st})
	}
	if !res.Outcome.Succeeded() {
		return fmt.Errorf("replay ended in phase %s: %s", res.Outcome.Phase, res.Outcome.Reason)
	}
	return nil
}

// liveAll replays every flow as its own stateful connection, one after another.
// Flows without a handshake are skipped. This is whole-pcap replay that still
// maintains seq/ack — each connection individually.
func liveAll(flows []*engine.Flow, target, iface string, seed int64, noGuard, verbose bool) error {
	replayed, ok, skipped := 0, 0, 0
	for i, f := range flows {
		if !f.HasSyn || !f.HasSynAck {
			fmt.Printf("flow %d: skip (no handshake)\n", i)
			skipped++
			continue
		}
		targetIP, targetPort, err := resolveTarget(target, f)
		if err != nil {
			fmt.Printf("flow %d: skip (%v)\n", i, err)
			skipped++
			continue
		}
		fmt.Printf("=== flow %d: %s -> %s:%d ===\n", i, f.Client, targetIP, targetPort)
		res, err := livereplay.Run(livereplay.Config{
			Flow: f, Iface: iface, TargetIP: targetIP, TargetPort: targetPort,
			Seed: seed, NoGuard: noGuard, Trace: verbose,
		}, func(line string) { fmt.Println(line) })
		replayed++
		if err != nil {
			fmt.Printf("  error: %v\n", err)
			continue
		}
		if res.Outcome.Succeeded() {
			ok++
		}
	}
	fmt.Printf("\nsummary: %d flow(s) replayed, %d completed, %d skipped (no handshake)\n", replayed, ok, skipped)
	return nil
}

func selectFlow(flows []*engine.Flow, sel int) (*engine.Flow, error) {
	if sel < 0 {
		if len(flows) != 1 {
			return nil, fmt.Errorf("capture has %d flows; pass -flow <index> to choose one for live replay", len(flows))
		}
		return flows[0], nil
	}
	if sel >= len(flows) {
		return nil, fmt.Errorf("-flow %d out of range (capture has %d flows)", sel, len(flows))
	}
	return flows[sel], nil
}

// resolveTarget parses an ip[:port] override, falling back to the captured server.
func resolveTarget(target string, f *engine.Flow) (netip.Addr, uint16, error) {
	if target == "" {
		return f.Server.Addr, f.Server.Port, nil
	}
	if !strings.Contains(target, ":") || (strings.Count(target, ":") > 1 && !strings.Contains(target, "]")) {
		// bare IP (v4 or v6 without a port)
		ip, err := netip.ParseAddr(target)
		if err != nil {
			return netip.Addr{}, 0, fmt.Errorf("invalid -target %q: %w", target, err)
		}
		return ip, f.Server.Port, nil
	}
	ap, err := netip.ParseAddrPort(target)
	if err != nil {
		host, portStr, ok := strings.Cut(target, ":")
		if !ok {
			return netip.Addr{}, 0, fmt.Errorf("invalid -target %q: %w", target, err)
		}
		ip, e1 := netip.ParseAddr(host)
		p, e2 := strconv.ParseUint(portStr, 10, 16)
		if e1 != nil || e2 != nil {
			return netip.Addr{}, 0, fmt.Errorf("invalid -target %q", target)
		}
		return ip, uint16(p), nil
	}
	return ap.Addr(), ap.Port(), nil
}
