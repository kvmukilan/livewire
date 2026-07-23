package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
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
	profileName := fs.String("profile", "functional", "replay fidelity: functional | timing | transport | wire")
	strict := fs.Bool("strict", false, "stop at the first difference from the recording")
	reportPath := fs.String("report", "", "where to save the shareable report (default: <capture>.report.json)")
	actualPath := fs.String("actual-out", "", "where to save actual replay traffic (default: <capture>.actual.pcap)")
	noGuard := fs.Bool("no-rst-guard", false, "advanced: don't suppress the host's RST (usually leave this off)")
	udpIdle := fs.Duration("udp-idle", 30*time.Second, "split a UDP tuple into a new session after this idle interval")
	var variables setFlags
	fs.Var(&variables, "set", "set a run variable (repeatable name=value; secret names are redacted from reports)")
	var rulePacks fileFlags
	fs.Var(&rulePacks, "rules", "JSON adapter rule pack (repeatable)")
	fs.Usage = func() {
		fmt.Println("usage: livewire reproduce <capture.pcap> [flags]")
		fmt.Println("   or: livewire reproduce [flags] <capture.pcap>")
		fmt.Println("\nReplay a recorded exchange against your device and report whether it")
		fmt.Println("behaves the same. Run as Administrator (Windows) or with sudo (Linux).")
		fmt.Println("\nIf the issue is timing-related add --under-load; for a low-level TCP")
		fmt.Println("issue add --exact-tcp. You normally don't need anything else.")
		fs.PrintDefaults()
	}
	pcapPath, err := parseReproduceArgs(fs, args)
	if err != nil {
		if err == errReproduceCaptureRequired {
			fs.Usage()
		}
		return err
	}
	if pcapPath == "" {
		fs.Usage()
		return fmt.Errorf("give the capture file we sent you, e.g. livewire reproduce issue.pcap")
	}

	recs, _, err := loadRecords(pcapPath)
	if err != nil {
		return err
	}
	flows := engine.ExtractFlows(recs)
	preflight := assessCapture(recs, flows)
	printPreflight(preflight)
	selectedProfile := *profileName
	if *underLoad && strings.EqualFold(selectedProfile, "functional") {
		selectedProfile = "timing"
	}
	if *exactTCP && !strings.EqualFold(selectedProfile, "wire") {
		selectedProfile = "transport"
	}
	profile, err := parseFidelityProfile(selectedProfile)
	if err != nil {
		return err
	}
	replayProfile, err := replay.ParseProfile(profile.Name)
	if err != nil {
		return err
	}
	registry, err := registryWithRulePacks(rulePacks)
	if err != nil {
		return err
	}
	if *udpIdle <= 0 {
		return fmt.Errorf("-udp-idle must be positive")
	}
	trace, plan, err := compileCoverageWithOptions(recs, replayProfile, registry, replay.ExtractOptions{UDPIdle: *udpIdle})
	if err != nil {
		return err
	}
	if len(plan.Entries) == 0 {
		return fmt.Errorf("capture %s has no packets", pcapPath)
	}
	fmt.Printf("Loaded %s: %d session(s), %d raw frame(s).\n", filepath.Base(pcapPath), len(trace.Sessions), len(trace.Raw))
	printCoverage(plan)

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
	pace, raw := profile.Pace, profile.RawL4

	verify := profile.Verify
	if *strict {
		verify = engine.VerifyStrict
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	o := liveOpts{
		ctx:    ctx,
		target: deviceIP.String(), iface: iface, seed: 1, noGuard: *noGuard,
		profile: profile.Name, verify: verify, adaptive: profile.Adaptive, pace: pace, rawL4: raw,
		variables: variables,
	}

	fmt.Printf("\nProfile: %s — %s\n", profile.Name, profile.Description)
	fmt.Printf("Replaying against %s on %q ...\n", deviceIP, iface)
	var mu sync.Mutex
	logf := func(idx int, line string) {
		line = redactRunText(line, variables)
		mu.Lock()
		if idx < 0 || len(plan.Entries) == 1 {
			fmt.Printf("  %s\n", line)
		} else {
			fmt.Printf("  [session %d] %s\n", idx, line)
		}
		mu.Unlock()
	}
	results := executeReplayPlan(executePlanConfig{
		Context: ctx, Trace: trace, Plan: plan, Records: recs, Registry: registry,
		Flows: flows, Iface: iface, TargetIP: deviceIP, Variables: variables, Live: o, Log: logf,
	})

	// Verdicts and a shareable report.
	rep := newReplayReport(o)
	rep.AdapterVersions = adapters.VersionsForRegistry(registry)
	rep.Preflight = &preflight
	rep.Plan = &plan
	rep.Limitations = plan.Limitations()
	rep.CaptureDigest, _ = sha256File(pcapPath)
	var actualFrames []pcapio.Record
	same, different, incomplete, wireOnly := 0, 0, 0, 0
	for _, result := range results {
		target := deviceIP.String()
		if result.Session != nil && result.Session.Server.Port != 0 {
			target = netip.AddrPortFrom(deviceIP, result.Session.Server.Port).String()
		}
		rep.addPlanned(result, target)
		actualFrames = append(actualFrames, result.TCP.Evidence...)
		actualFrames = append(actualFrames, result.Transport.Evidence...)
		label := fmt.Sprintf("%s (%s, %s)", result.Entry.SessionID, result.Entry.Transport, result.Entry.Mode)
		if result.Err != nil {
			fmt.Printf("\n---- %s ----\nRESULT: could not run — %s\n--------------------------------\n", label, redactRunText(result.Err.Error(), variables))
			incomplete++
			continue
		}
		if result.Entry.Mode == replay.ModeWire {
			fmt.Printf("\n---- %s ----\nRESULT: sent %d frame(s) at captured timing; live adaptation and response equivalence were not claimed.\n--------------------------------\n", label, result.Transport.Sent)
			wireOnly++
			continue
		}
		if result.Entry.Transport == replay.TransportTCP && result.Entry.Mode == replay.ModeStateful {
			var verdict strings.Builder
			fprintVerdict(&verdict, label, result.TCP)
			fmt.Print(redactRunText(verdict.String(), variables))
		} else {
			fmt.Printf("\n---- %s ----\nRESULT: completed=%v matched=%v sent=%d received=%d\n--------------------------------\n",
				label, result.Transport.Completed, result.Transport.Matched, result.Transport.Sent, result.Transport.Received)
		}
		completed, matched := result.Transport.Completed, result.Transport.Matched
		if result.Entry.Transport == replay.TransportTCP && result.Entry.Mode == replay.ModeStateful {
			completed, matched = result.TCP.Outcome.Succeeded(), result.TCP.Matched
		}
		switch {
		case completed && matched:
			same++
		case completed:
			different++
		default:
			incomplete++
		}
	}

	out := *reportPath
	if out == "" {
		out = strings.TrimSuffix(pcapPath, filepath.Ext(pcapPath)) + ".report.json"
	}
	actual := *actualPath
	if actual == "" {
		actual = strings.TrimSuffix(pcapPath, filepath.Ext(pcapPath)) + ".actual.pcap"
	}
	if len(actualFrames) > 0 {
		if aerr := writeFrames(actual, actualFrames, true); aerr != nil {
			fmt.Printf("\n(could not save actual replay capture: %v)\n", aerr)
		} else {
			rep.ActualCapture = actual
			fmt.Printf("\nActual replay traffic was saved to %s.\n", actual)
		}
	}
	if werr := rep.write(out); werr != nil {
		fmt.Printf("\n(could not save report: %v)\n", werr)
	} else {
		fmt.Printf("\nA shareable report was saved to %s — send this back so we can see what happened.\n", out)
	}

	fmt.Printf("\nSummary: %d same as recording, %d different, %d wire-only, %d did not complete.\n", same, different, wireOnly, incomplete)

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

var errReproduceCaptureRequired = fmt.Errorf("give the capture file we sent you, e.g. livewire reproduce issue.pcap")

// parseReproduceArgs accepts both the human-friendly capture-first form shown
// in the guided command's examples and the conventional flags-first form. The
// standard flag package stops at the first positional argument, so without
// this small normalization flags written after the capture would be ignored.
func parseReproduceArgs(fs *flag.FlagSet, args []string) (string, error) {
	capture := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		capture = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	positionals := fs.Args()
	if capture != "" {
		if len(positionals) != 0 {
			return "", fmt.Errorf("unexpected positional argument %q; provide exactly one capture", positionals[0])
		}
		return capture, nil
	}
	if len(positionals) == 0 {
		return "", errReproduceCaptureRequired
	}
	if len(positionals) != 1 {
		return "", fmt.Errorf("unexpected positional argument %q; provide exactly one capture", positionals[1])
	}
	return positionals[0], nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + fmt.Sprintf("%x", h.Sum(nil)), nil
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
