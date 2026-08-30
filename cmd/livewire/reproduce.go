package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
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
	"github.com/kvmukilan/livewire/internal/iterate"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
)

// cmdReproduce is the peer-facing, (almost) zero-flag entry point: give it a
// capture and it walks you through reproducing the issue on your device — asking
// only for your device's address and which network connection to use, with the
// right answers pre-selected — then prints a plain-language verdict.
//
// With -n it replays more than once and reports how often the issue appears,
// because a fault that shows up one time in five is the common field case and a
// single replay cannot tell the difference between "fixed" and "intermittent".
func cmdReproduce(args []string) error {
	fs := flag.NewFlagSet("reproduce", flag.ContinueOnError)
	var pcapFlag string
	fs.StringVar(&pcapFlag, flagIn, "", "the capture file we sent you")
	var on string
	fs.StringVar(&on, flagIface, "", "network connection to use (asks if not given)")
	fs.StringVar(&on, "on", "", "alias for -i")
	fs.StringVar(&on, "iface", "", "alias for -i")
	var to string
	fs.StringVar(&to, flagTarget, "", "device IP or fresh secure target host:port (asks if not given)")
	fs.StringVar(&to, "to", "", "alias for -t")
	fs.StringVar(&to, "target", "", "alias for -t")
	var times int
	fs.IntVar(&times, flagCount, 1, "how many times to replay; more than 1 reports how often the issue appears")
	fs.IntVar(&times, "times", 1, "alias for -n")
	fs.IntVar(&times, "iterations", 1, "alias for -n")
	underLoad := fs.Bool("under-load", false, "reproduce a timing/load issue (replay everything at the recorded speed)")
	exactTCP := fs.Bool("exact-tcp", false, "reproduce a low-level TCP issue (send the recorded packets exactly)")
	details := fs.Bool(flagDetails, false, "show the expert tables: capture assessment, replay plan, and every session's verdict")
	gap := fs.Duration("gap", time.Second, "settle time between attempts when -n is more than 1")
	stopWhenDifferent := fs.Bool("stop-when-different", false, "with -n, stop at the first attempt that doesn't match the recording")
	profileName := fs.String("profile", "functional", "replay fidelity: functional | timing | transport | wire")
	strict := fs.Bool("strict", false, "abort a session at the first structural difference from the recording")
	wireMode := fs.Bool("wire", false, "explicitly inject captured frames without session adaptation or response verification")
	reportPath := fs.String("report", "", "where to save the shareable report (default: <capture>.report.json)")
	actualPath := fs.String("actual-out", "", "where to save actual replay traffic (default: <capture>.actual.pcap)")
	noGuard := fs.Bool("no-rst-guard", false, "advanced: don't suppress the host's RST (usually leave this off)")
	udpIdle := fs.Duration("udp-idle", 30*time.Second, "split a UDP tuple into a new session after this idle interval")
	var variables setFlags
	fs.Var(&variables, "set", "set a run variable (repeatable name=value; secret names are redacted from reports)")
	var rulePacks fileFlags
	fs.Var(&rulePacks, "rules", "JSON adapter rule pack (repeatable)")
	keylogPath := fs.String("keylog", "", "matching NSS key log for TLS/FTPS (never auto-consumed or logged)")
	serverName := fs.String("server-name", "", "TLS certificate DNS name (default: target host)")
	caPath := fs.String("ca", "", "optional PEM CA bundle for TLS/FTPS verification")
	insecure := fs.Bool("insecure-skip-verify", false, "explicitly disable TLS certificate verification (lab only)")
	secureTimeout := fs.Duration("timeout", 30*time.Second, "fresh TLS, FTPS, or SSH connection timeout")
	sshUser := fs.String("user", "", "SSH username")
	sshPass := fs.String("pass", "", "SSH password (or use -key; never written to reports)")
	sshKey := fs.String("key", "", "SSH private-key file (alternative to -pass)")
	sshHostKey := fs.String("host-key", "", "pinned OpenSSH public host-key file (required in unified mode)")
	var sshCommands multiFlag
	var sshExpects multiFlag
	fs.Var(&sshCommands, "cmd", "explicit SSH command to run (repeatable)")
	fs.Var(&sshExpects, "expect", "expected SSH output substring, one per -cmd")
	allFlags := registerAllFlags(fs)
	fs.Usage = func() {
		fmt.Println("usage: livewire reproduce <capture.pcap> [options]")
		fmt.Println("   or: livewire reproduce -in <capture.pcap> -t <device-ip> -i <connection>")
		fmt.Println("\nReplay a recorded exchange against your device and report whether it")
		fmt.Println("behaves the same. Run as Administrator (Windows) or with sudo (Linux).")
		fmt.Println("\nIf the issue comes and goes, add -n 5 to replay five times and see how")
		fmt.Println("often it happens. If it's timing-related add -under-load; for a low-level")
		fmt.Println("TCP issue add -exact-tcp. You normally don't need anything else.")
		printFlags(fs, flagIn, flagTarget, flagIface, flagCount, "under-load", "exact-tcp", "wire", flagDetails)
	}
	pcapPath, err := parseCaptureArgs(fs, args, &pcapFlag)
	if err != nil {
		return err
	}
	if handleAllFlags(fs, *allFlags, reproduceAliases) {
		return errAllFlags
	}
	if pcapPath == "" {
		fs.Usage()
		return errReproduceCaptureRequired
	}
	if times < 1 {
		return fmt.Errorf("-n must be at least 1")
	}
	if times > maxReplayAttempts {
		return fmt.Errorf("-n must not exceed %d", maxReplayAttempts)
	}
	if *gap < 0 {
		return fmt.Errorf("-gap cannot be negative")
	}
	if *gap > 10*time.Minute {
		return fmt.Errorf("-gap must not exceed 10m")
	}

	recs, _, err := loadRecords(pcapPath)
	if err != nil {
		return err
	}
	handled, err := orchestrateProtocolCapture(recs, orchestratorOptions{
		capture: pcapPath, iface: on, target: to,
		keylog: *keylogPath, serverName: *serverName, ca: *caPath,
		insecure: *insecure, strict: *strict, wire: *wireMode,
		user: *sshUser, password: *sshPass, privateKey: *sshKey, hostKey: *sshHostKey,
		commands: sshCommands, expects: sshExpects, timeout: *secureTimeout,
		report: *reportPath, times: times, gap: *gap, stopWhenDifferent: *stopWhenDifferent,
		variables: variables, rulePacks: rulePacks,
	})
	if handled {
		return err
	}
	flows := engine.ExtractFlows(recs)
	preflight := assessCapture(recs, flows)
	if *details {
		printPreflight(preflight)
	}
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
	if *udpIdle <= 0 || *udpIdle > time.Hour {
		return fmt.Errorf("-udp-idle must be greater than zero and at most 1h")
	}
	trace, plan, err := compileCoverageWithOptions(recs, replayProfile, registry, replay.ExtractOptions{UDPIdle: *udpIdle})
	if err != nil {
		return err
	}
	if len(plan.Entries) == 0 {
		return fmt.Errorf("capture %s has no packets", pcapPath)
	}
	if !strings.EqualFold(selectedProfile, "wire") {
		for _, entry := range plan.Entries {
			if entry.Mode == replay.ModeWire {
				return fmt.Errorf("%s contains traffic that has no safe stateful driver; no packets were sent. Inspect it with 'livewire check %s -details', or explicitly choose raw injection with --wire -i <connection>", filepath.Base(pcapPath), pcapPath)
			}
		}
	}
	fmt.Printf("Loaded %s: %d session(s), %d raw frame(s).\n", filepath.Base(pcapPath), len(trace.Sessions), len(trace.Raw))
	if *details {
		printCoverage(plan)
	}
	if blockers := planBlockers(plan); len(blockers) > 0 {
		fmt.Println("\nSome of this capture can't be replayed faithfully:")
		for _, b := range blockers {
			fmt.Printf("  - %s\n", b)
		}
		if !planHasExecutableEntry(plan) {
			return fmt.Errorf("the capture has no safely executable session; no packets were sent")
		}
	}
	base := strings.TrimSuffix(pcapPath, filepath.Ext(pcapPath))
	out, err := resolveOutputPath(*reportPath, base+".report.json", "-report")
	if err != nil {
		return err
	}
	actual, err := resolveOutputPath(*actualPath, base+".actual.pcap", "-actual-out")
	if err != nil {
		return err
	}
	if sameOutputPath(out, actual) {
		return fmt.Errorf("-report and -actual-out must name different files")
	}

	// 1) Which device? (its IP; the port comes from the capture)
	deviceIP, err := chooseDeviceIP(to)
	if err != nil {
		return err
	}
	// 2) Which network connection reaches it?
	iface, err := chooseInterface(on, deviceIP)
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

	runs := iterate.Plan{Times: times, Gap: *gap, StopWhenDifferent: *stopWhenDifferent}.Normalize()
	// Quiet mode is the default for a repeated run: N copies of the progress log
	// and N verdict blocks bury the one number the reader wants, which is how
	// often it happened. -details restores the full per-attempt output.
	quiet := runs.Repeats() && !*details
	if runs.Repeats() {
		fmt.Printf("Running %d attempts, %s apart. Each attempt opens a fresh connection.\n", runs.Times, runs.Gap)
	}

	rep := newReplayReport(o)
	rep.AdapterVersions = adapters.VersionsForRegistry(registry)
	rep.Preflight = &preflight
	rep.Plan = &plan
	rep.Limitations = plan.Limitations()
	rep.CaptureDigest, _ = sha256File(pcapPath)

	var mu sync.Mutex
	var actualFrames []pcapio.Record
	baseSeed := o.seed

	attempt := func(i int) iterate.Tally {
		// Every attempt must look like a new connection to the device: the same
		// four-tuple and ISN sent twice in a row is an old duplicate segment as
		// far as TCP is concerned, and the device resets it. That would read as
		// a failure to reproduce when it is really an artefact of repeating.
		att := o
		att.seed = baseSeed + int64(i)
		att.portStride = i
		if runs.Repeats() {
			rep.startAttempt(i + 1)
		}
		logf := func(idx int, line string) {
			if quiet {
				return
			}
			line = redactRunText(line, variables)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case runs.Repeats():
				fmt.Printf("  [attempt %d] %s\n", i+1, line)
			case idx < 0 || len(plan.Entries) == 1:
				fmt.Printf("  %s\n", line)
			default:
				fmt.Printf("  [session %d] %s\n", idx, line)
			}
		}
		if !quiet && runs.Repeats() {
			fmt.Printf("\n---- attempt %d of %d ----\n", i+1, runs.Times)
		}

		results := executeReplayPlan(executePlanConfig{
			Context: ctx, Trace: trace, Plan: plan, Registry: registry,
			Flows: flows, Iface: iface, TargetIP: deviceIP, Variables: variables, Live: att, Log: logf,
		})

		var tally iterate.Tally
		note := ""
		for _, result := range results {
			target := deviceIP.String()
			if result.Session != nil && result.Session.Server.Port != 0 {
				target = netip.AddrPortFrom(deviceIP, result.Session.Server.Port).String()
			}
			rep.addPlanned(result, target)
			actualFrames = append(actualFrames, result.TCP.Evidence...)
			actualFrames = append(actualFrames, result.Transport.Evidence...)

			verdict, why := sessionVerdict(result, variables)
			tally.Add(verdict)
			if note == "" && why != "" {
				note = why
			}
			if !quiet {
				printSessionResult(result, variables)
			}
		}
		if runs.Repeats() {
			line := fmt.Sprintf("Attempt %d of %d: %s", i+1, runs.Times, tally.Worst().Plain())
			if note != "" {
				line += " — " + note
			}
			fmt.Println(line)
		}
		return tally
	}

	per := runs.Run(ctx, attempt)
	summary := iterate.Summarize(per, runs.Times)
	if runs.Repeats() {
		rep.recordIterations(summary)
	}

	var artifactErrs []error
	if len(actualFrames) > 0 {
		if aerr := writeFrames(actual, actualFrames, true); aerr != nil {
			artifactErrs = append(artifactErrs, fmt.Errorf("save actual replay capture: %w", aerr))
			fmt.Printf("\n(could not save actual replay capture: %v)\n", aerr)
		} else {
			rep.ActualCapture = actual
			fmt.Printf("\nActual replay traffic was saved to %s.\n", actual)
		}
	}
	if werr := rep.write(out); werr != nil {
		artifactErrs = append(artifactErrs, fmt.Errorf("save replay report: %w", werr))
		fmt.Printf("\n(could not save report: %v)\n", werr)
	} else {
		fmt.Printf("\nA shareable report was saved to %s — send this back so we can see what happened.\n", out)
	}

	if runs.Repeats() {
		fmt.Print(summary.Plain())
	} else {
		s := summary.Sessions
		fmt.Printf("\nSummary: %d same as recording, %d different, %d unverified, %d wire-only, %d did not complete.\n",
			s.Same, s.Different, s.Unverified, s.WireOnly, s.Incomplete)
	}

	// If the run didn't reproduce the issue, suggest the opt-in tuning.
	if (summary.Sessions.Different+summary.Sessions.Incomplete) > 0 && !pace && !raw && !*strict {
		fmt.Println("\nIf you expected the issue to reproduce and it didn't, try one of these:")
		if !runs.Repeats() {
			fmt.Println("  - if it only happens sometimes:      add  -n 5")
		}
		fmt.Println("  - if it's timing- or load-related:   add  -under-load")
		fmt.Println("  - if it's a low-level TCP issue:     add  -exact-tcp")
		fmt.Println("  - to flag every small difference:    add  -strict")
		fmt.Println("Otherwise, send us the report file above and we'll take a look.")
	}
	return errors.Join(artifactErrs...)
}

var errReproduceCaptureRequired = fmt.Errorf("give the capture file we sent you, e.g. livewire reproduce issue.pcap")

// reproduceAliases names the flags kept only so older docs and scripts keep
// working. They behave identically to the short name they shadow.
var reproduceAliases = aliasSet{
	"on": true, "iface": true, "to": true, "target": true,
	"times": true, "iterations": true,
}

// sessionVerdict reduces one planned session to its verdict plus, when something
// went wrong, a short plain-language reason. The reason is what a repeated run
// shows next to each attempt, so the reader learns *why* without wading through
// the full per-session block.
func sessionVerdict(result plannedResult, variables map[string]string) (iterate.Verdict, string) {
	if result.Err != nil {
		return iterate.Incomplete, redactRunText(result.Err.Error(), variables)
	}
	if result.Entry.Mode == replay.ModeWire {
		return iterate.WireOnly, ""
	}
	completed, matched := result.Transport.Completed, result.Transport.Matched
	if result.Entry.Transport == replay.TransportTCP && result.Entry.Mode == replay.ModeStateful {
		completed, matched = result.TCP.Outcome.Succeeded(), result.TCP.Matched
		v := iterate.ClassifyVerified(completed, result.TCP.Verified, matched, false)
		switch v {
		case iterate.Incomplete:
			return v, redactRunText(plainReason(result.TCP.Outcome), variables)
		case iterate.Different:
			return v, redactRunText(firstDivergence(result.TCP.Outcome), variables)
		default:
			return v, ""
		}
	}
	if result.Entry.Mode == replay.ModeCoordinated && result.Entry.Adapter == "ftp" {
		matched := result.FTP.Completed && len(result.FTP.Differences) == 0
		for _, transfer := range result.FTP.Transfers {
			matched = matched && transfer.Matched
		}
		v := iterate.ClassifyVerified(result.FTP.Completed, result.FTP.Verified, matched, false)
		if v == iterate.Different && len(result.FTP.Differences) > 0 {
			d := result.FTP.Differences[0]
			return v, redactRunText(fmt.Sprintf("%s: expected %s, got %s", d.Field, d.Expected, d.Actual), variables)
		}
		if v == iterate.Different {
			return v, "FTP data length or digest differs from the capture"
		}
		return v, ""
	}
	v := iterate.ClassifyVerified(completed, result.Transport.Verified, matched, false)
	if v == iterate.Different && len(result.Transport.Differences) > 0 {
		d := result.Transport.Differences[0]
		return v, redactRunText(fmt.Sprintf("%s: expected %s, got %s", d.Field, d.Expected, d.Actual), variables)
	}
	if v == iterate.Incomplete && result.Transport.Error != "" {
		return v, redactRunText(result.Transport.Error, variables)
	}
	return v, ""
}

// firstDivergence names the first way the device's answer differed, for the
// one-line-per-attempt output.
func firstDivergence(out engine.Outcome) string {
	for _, m := range out.Mismatches {
		if m.Structural {
			return m.Detail
		}
	}
	if len(out.Mismatches) > 0 {
		return out.Mismatches[0].Detail
	}
	return "the device answered differently"
}

// printSessionResult writes one session's full verdict block.
func printSessionResult(result plannedResult, variables map[string]string) {
	label := fmt.Sprintf("%s (%s, %s)", result.Entry.SessionID, result.Entry.Transport, result.Entry.Mode)
	switch {
	case result.Err != nil:
		fmt.Printf("\n---- %s ----\nRESULT: could not run — %s\n--------------------------------\n",
			label, redactRunText(result.Err.Error(), variables))
	case result.Entry.Mode == replay.ModeWire:
		fmt.Printf("\n---- %s ----\nRESULT: sent %d frame(s) at captured timing; live adaptation and response equivalence were not claimed.\n--------------------------------\n",
			label, result.Transport.Sent)
	case result.Entry.Transport == replay.TransportTCP && result.Entry.Mode == replay.ModeStateful:
		var verdict strings.Builder
		fprintVerdict(&verdict, label, result.TCP)
		fmt.Print(redactRunText(verdict.String(), variables))
	case result.Entry.Mode == replay.ModeCoordinated && result.Entry.Adapter == "ftp":
		matched := result.FTP.Completed && len(result.FTP.Differences) == 0
		for _, transfer := range result.FTP.Transfers {
			matched = matched && transfer.Matched
		}
		matched = result.FTP.Verified && matched
		fmt.Printf("\n---- %s ----\nRESULT: completed=%v verified=%v matched=%v commands=%d replies=%d transfers=%d\n--------------------------------\n",
			label, result.FTP.Completed, result.FTP.Verified, matched, result.FTP.Commands, result.FTP.Replies, len(result.FTP.Transfers))
	default:
		fmt.Printf("\n---- %s ----\nRESULT: completed=%v matched=%v sent=%d received=%d\n--------------------------------\n",
			label, result.Transport.Completed, result.Transport.Matched, result.Transport.Sent, result.Transport.Received)
	}
}

// planBlockers lists, without jargon, the parts of the capture that cannot be
// replayed faithfully. The full per-session table is behind -details, but a
// blocker changes what the result means, so it is always worth saying.
func planBlockers(plan replay.ReplayPlan) []string {
	var out []string
	seen := map[string]bool{}
	for _, e := range plan.Entries {
		for _, b := range e.Blockers {
			if !seen[b] {
				seen[b] = true
				out = append(out, b)
			}
		}
	}
	return out
}

func planHasExecutableEntry(plan replay.ReplayPlan) bool {
	for _, entry := range plan.Entries {
		if entry.Mode != replay.ModeBlocked {
			return true
		}
	}
	return false
}

func sha256File(path string) (digest string, retErr error) {
	// #nosec G703 -- the CLI intentionally hashes an operator-selected local capture; dashboard paths use os.Root.
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := f.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close capture after hashing: %w", err))
		}
	}()
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

// chooseDeviceIP gets the device's IP from -t or by asking. The port always
// comes from the capture, so only an address is needed.
func chooseDeviceIP(to string) (netip.Addr, error) {
	if to != "" {
		return parseHostIP(to)
	}
	if !isTerminal(os.Stdin) {
		return netip.Addr{}, fmt.Errorf("tell me your device's IP with -t <ip> (e.g. -t 192.168.1.50)")
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

// chooseInterface returns the connection to replay on: -i if given, the single
// obvious one, or a numbered menu with the connection on the device's network
// pre-selected as recommended.
func chooseInterface(on string, device netip.Addr) (string, error) {
	if on != "" {
		return on, nil
	}
	choices := candidateInterfaces(device)
	if len(choices) == 0 {
		return "", fmt.Errorf("couldn't find a usable network connection; run 'livewire ifaces' and pass -i <name>")
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
		return "", fmt.Errorf("more than one network connection is possible; pass -i <name> (see 'livewire ifaces')")
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
