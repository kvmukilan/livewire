package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/kvmukilan/livewire/internal/engine"
)

// cmdReproduce is the peer-facing, (almost) zero-flag entry point: give it a
// capture and it walks you through reproducing the issue on your device — asking
// only for your device's address and which network connection to use, with the
// right answers pre-selected — then prints a plain-language verdict.
func cmdReproduce(args []string) error {
	fs := flag.NewFlagSet("reproduce", flag.ContinueOnError)
	on := fs.String("on", "", "network connection to use (asks if not given)")
	to := fs.String("to", "", "your device's IP address (asks if not given)")
	underLoad := fs.Bool("under-load", false, "reproduce a timing/load issue (replay everything at the recorded speed)")
	exactTCP := fs.Bool("exact-tcp", false, "reproduce a low-level TCP issue (send the recorded packets exactly)")
	strict := fs.Bool("strict", false, "stop at the first difference from the recording")
	reportPath := fs.String("report", "", "where to save the shareable report (default: <capture>.report.json)")
	noGuard := fs.Bool("no-rst-guard", false, "advanced: don't suppress the host's RST (usually leave this off)")
	fs.Usage = func() {
		fmt.Println("usage: livewire reproduce <capture.pcap> [--to <device-ip>] [--on <connection>]")
		fmt.Println("\nReplay a recorded exchange against your device and report whether it")
		fmt.Println("behaves the same. Run as Administrator (Windows) or with sudo (Linux).")
		fmt.Println("\nIf the issue is timing-related add --under-load; for a low-level TCP")
		fmt.Println("issue add --exact-tcp. You normally don't need anything else.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		fs.Usage()
		return fmt.Errorf("give the capture file we sent you, e.g. livewire reproduce issue.pcap")
	}
	pcapPath := fs.Arg(0)

	recs, _, err := loadRecords(pcapPath)
	if err != nil {
		return err
	}
	flows := engine.ExtractFlows(recs)
	if len(flows) == 0 {
		return fmt.Errorf("no TCP connections found in %s", pcapPath)
	}
	capPort := flows[0].Server.Port
	fmt.Printf("Loaded %s: %d connection(s), device port %d.\n", filepath.Base(pcapPath), len(flows), capPort)

	// 1) Which device? (its IP; the port comes from the capture)
	deviceIP, err := chooseDeviceIP(*to)
	if err != nil {
		return err
	}
	// 2) Which network connection reaches it?
	iface, err := chooseInterface(*on, deviceIP)
	if err != nil {
		return err
	}
	// Run the most reliable default (adaptive + reply-checking + auto-synthesis).
	// Scenario tuning stays opt-in via flags, suggested only if the default run
	// doesn't reproduce the issue.
	pace, raw := *underLoad, *exactTCP

	verify := engine.VerifyLenient
	if *strict {
		verify = engine.VerifyStrict
	}
	o := liveOpts{
		target: deviceIP.String(), iface: iface, seed: 1, noGuard: *noGuard,
		verify: verify, adaptive: true, pace: pace, rawL4: raw,
	}

	fmt.Printf("\nReplaying against %s on %q ...\n", deviceIP, iface)
	var mu sync.Mutex
	logf := func(idx int, line string) {
		mu.Lock()
		if idx < 0 || len(flows) == 1 {
			fmt.Printf("  %s\n", line)
		} else {
			fmt.Printf("  [connection %d] %s\n", idx, line)
		}
		mu.Unlock()
	}
	results, skipped := replayAllFlows(flows, o, logf)

	// Verdicts and a shareable report.
	rep := newReplayReport(o)
	same, different, incomplete := 0, 0, 0
	for _, r := range results {
		rep.add(r.idx, r.flow, r.target, r.mode, r.res, r.err)
		label := ""
		if len(results) > 1 {
			label = fmt.Sprintf("Connection %d (%s)", r.idx, r.target)
		}
		if r.err != nil {
			fmt.Printf("\n---- %s ----\nRESULT: could not run — %v\n--------------------------------\n", label, r.err)
			incomplete++
			continue
		}
		printVerdict(label, r.res)
		switch {
		case r.res.Outcome.Succeeded() && r.res.Outcome.RepliesMatched():
			same++
		case r.res.Outcome.Succeeded():
			different++
		default:
			incomplete++
		}
	}

	out := *reportPath
	if out == "" {
		out = strings.TrimSuffix(pcapPath, filepath.Ext(pcapPath)) + ".report.json"
	}
	if werr := rep.write(out); werr != nil {
		fmt.Printf("\n(could not save report: %v)\n", werr)
	} else {
		fmt.Printf("\nA shareable report was saved to %s — send this back so we can see what happened.\n", out)
	}

	fmt.Printf("\nSummary: %d same as recording, %d different, %d did not complete", same, different, incomplete)
	if skipped > 0 {
		fmt.Printf(", %d skipped", skipped)
	}
	fmt.Println(".")

	// If the default run didn't reproduce the issue, suggest the opt-in tuning.
	if (different+incomplete) > 0 && !pace && !raw && !*strict {
		fmt.Println("\nIf you expected the issue to reproduce and it didn't, try one of these:")
		fmt.Println("  - if it's timing- or load-related:  add  --under-load")
		fmt.Println("  - if it's a low-level TCP issue:     add  --exact-tcp")
		fmt.Println("  - to flag every small difference:    add  --strict")
		fmt.Println("Otherwise, send us the report file above and we'll take a look.")
	}
	return nil
}

// subnetHasTarget reports whether any of the interface's CIDRs contains target,
// i.e. the interface is on the same network as the device.
func subnetHasTarget(cidrs []string, target netip.Addr) bool {
	if !target.IsValid() {
		return false
	}
	for _, c := range cidrs {
		if pfx, err := netip.ParsePrefix(c); err == nil && pfx.Masked().Contains(target) {
			return true
		}
	}
	return false
}

// chooseDeviceIP gets the device's IP from --to or by asking. The port always
// comes from the capture, so only an address is needed.
func chooseDeviceIP(to string) (netip.Addr, error) {
	if to != "" {
		return parseHostIP(to)
	}
	if !isTerminal(os.Stdin) {
		return netip.Addr{}, fmt.Errorf("tell me your device's IP with --to <ip> (e.g. --to 192.168.1.50)")
	}
	for {
		line := prompt("What is your device's IP address? ")
		if line == "" {
			fmt.Println("  (please enter an address, e.g. 192.168.1.50)")
			continue
		}
		ip, err := parseHostIP(line)
		if err != nil {
			fmt.Printf("  that doesn't look like an IP address (%v) — try again\n", err)
			continue
		}
		return ip, nil
	}
}

func parseHostIP(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h // tolerate an ip:port paste
	}
	return netip.ParseAddr(s)
}

// ifaceChoice is one selectable network connection.
type ifaceChoice struct {
	name        string // the value passed through to the live backend
	desc        string // human description
	recommended bool
}

// chooseInterface returns the connection to replay on: --on if given, the single
// obvious one, or a numbered menu with the connection on the device's network
// pre-selected as recommended.
func chooseInterface(on string, device netip.Addr) (string, error) {
	if on != "" {
		return on, nil
	}
	choices := candidateInterfaces(device)
	if len(choices) == 0 {
		return "", fmt.Errorf("couldn't find a usable network connection; run 'livewire ifaces' and pass --on <name>")
	}
	def := 0
	recommended := 0
	for i, c := range choices {
		if c.recommended {
			def = i
			recommended++
		}
	}
	if !isTerminal(os.Stdin) {
		if recommended == 1 || len(choices) == 1 {
			return choices[def].name, nil
		}
		return "", fmt.Errorf("more than one network connection is possible; pass --on <name> (see 'livewire ifaces')")
	}
	fmt.Println("\nWhich network connection reaches the device?")
	for i, c := range choices {
		mark := ""
		if c.recommended {
			mark = "   <- recommended (same network as the device)"
		}
		fmt.Printf("  %d) %-26s %s%s\n", i+1, c.name, c.desc, mark)
	}
	sel := promptChoice(fmt.Sprintf("Enter a number [%d]: ", def+1), def, len(choices))
	return choices[sel].name, nil
}

// candidateInterfaces lists the connections a peer might pick, marking the one
// whose subnet contains the device as recommended (subnet matching is only
// reliable on non-Windows; on Windows the backend needs Npcap device names).
func candidateInterfaces(device netip.Addr) []ifaceChoice {
	if runtime.GOOS == "windows" {
		devs, err := listPcapDevices()
		if err != nil {
			return nil
		}
		out := make([]ifaceChoice, 0, len(devs))
		for _, d := range devs {
			out = append(out, ifaceChoice{name: d.name, desc: d.desc})
		}
		return out
	}
	ifis, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []ifaceChoice
	for _, ifi := range ifis {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		var ips []string
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				ips = append(ips, ipnet.String())
			}
		}
		if len(ips) == 0 {
			continue
		}
		out = append(out, ifaceChoice{name: ifi.Name, desc: strings.Join(ips, ", "), recommended: subnetHasTarget(ips, device)})
	}
	return out
}

// stdinReader is shared so typed-ahead input isn't lost between prompts.
var stdinReader = bufio.NewReader(os.Stdin)

// prompt writes a question and returns the trimmed reply.
func prompt(q string) string {
	fmt.Print(q)
	line, _ := stdinReader.ReadString('\n')
	return strings.TrimSpace(line)
}

// promptChoice reads a 1-based menu selection, returning a 0-based index. Empty
// input takes the default; out-of-range input re-asks.
func promptChoice(q string, def, n int) int {
	for {
		s := prompt(q)
		if s == "" {
			return def
		}
		if v, err := strconv.Atoi(s); err == nil && v >= 1 && v <= n {
			return v - 1
		}
		fmt.Printf("  please enter a number between 1 and %d\n", n)
	}
}
