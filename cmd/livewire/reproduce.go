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
	"github.com/kvmukilan/livewire/internal/evidence"
	"github.com/kvmukilan/livewire/internal/iterate"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/replayintent"
)

// cmdReproduce is the peer-facing, (almost) zero-flag entry point: give it a
// capture and it walks you through reproducing the issue on your device — asking
// only for your device's address and which network connection to use, with the
// right answers pre-selected — then prints a plain-language verdict.
//
// With -n it replays more than once and reports how often the issue appears,
// because a fault that shows up one time in five is the common field case and a
// single replay cannot tell the difference between "fixed" and "intermittent".
func cmdReproduce(args []string) (retErr error) {
	return cmdCaptureReplay("reproduce", args)
}

// cmdCaptureReplay gives live and reproduce the same fresh-session execution
// contract while retaining their own help and diagnostics.
func cmdCaptureReplay(command string, args []string) (retErr error) {
	o, err := parseCaptureReplayFlags(command, args)
	if err != nil {
		return err
	}
	capture, captureDigest, err := loadCaptureSnapshot(o.capture)
	if err != nil {
		return err
	}
	recs := capture.Records
	profile, registry, err := resolveReproduceIntent(&o)
	if err != nil {
		return err
	}
	inspection, secureRoute, err := inspectReproduce(&o, recs, registry)
	if err != nil {
		return err
	}
	if o.scenarioPath != "" {
		file, err := os.Open(o.scenarioPath)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		if err := errors.Join(readErr, file.Close()); err != nil {
			return err
		}
		o.scenario, err = replay.ParseScenario(data, captureDigest)
		if err != nil {
			return err
		}
		if inspection.Mode == "wire" || inspection.Mode == "transport" {
			return fmt.Errorf("-scenario requires application replay")
		}
		if err = o.scenario.ValidateTrace(inspection.Trace, registry); err != nil {
			return err
		}
		if _, err = o.scenario.Order(inspection.Plan.Entries); err != nil {
			return err
		}
	}
	if o.stateDir != "" || o.resumeDir != "" {
		if o.target == "" && inspection.Mode != "wire" {
			return fmt.Errorf("durable replay requires an explicit -t so resume can verify the target")
		}
		identity, err := reproduceIdentity(o, inspection, registry)
		if err != nil {
			return err
		}
		if err = o.openState(captureDigest, identity, o.dryRun); err != nil {
			return err
		}
		if o.journal != nil {
			defer func() { retErr = errors.Join(retErr, o.journal.Close()) }()
		}
	}
	if o.dryRun {
		return reproduceDryRun(o, inspection, secureRoute)
	}
	if !inspection.Readiness.Supported {
		return blockedReplayError(o.capture, inspection.Readiness.Blocker)
	}
	handled, err := orchestrateProtocolCapture(recs, orchestratorOptions{
		executionFlags: o.executionFlags,
		captureDigest:  captureDigest,
		capture:        o.capture, iface: o.iface, target: o.target, keylog: o.keylog, serverName: o.serverName, ca: o.ca,
		insecure: o.insecure, strict: o.strict, wire: inspection.Mode == "wire", user: o.sshUser, password: o.sshPass, privateKey: o.sshKey, hostKey: o.sshHostKey,
		commands: o.sshCommands, expects: o.sshExpects, timeout: o.timeout, responseTimeout: o.responseTimeout, expectFault: o.expectFault, report: o.report, times: o.times, gap: o.gap, stopWhenDifferent: o.stopWhenDifferent,
		variables: o.variables, rulePacks: o.rulePacks, sessions: o.sessions, inspection: inspection,
	})
	if handled {
		return err
	}
	return runGenericReproduce(o, recs, captureDigest, inspection, profile, registry)
}

// reproduceOptions is everything the command learned from its flags and
// arguments, so each phase below takes one value instead of thirty locals.
type reproduceOptions struct {
	executionFlags
	capture           string
	iface             string
	target            string
	times             int
	gap               time.Duration
	stopWhenDifferent bool
	underLoad         bool
	exactTCP          bool
	details           bool
	dryRun            bool
	strict            bool
	wire              bool
	noGuard           bool
	insecure          bool
	// mode and profile hold the raw request until resolveReproduceIntent
	// replaces them with the resolved intent and fidelity profile.
	mode            string
	profile         string
	sessions        []string
	rulePacks       []string
	report          string
	actual          string
	udpIdle         time.Duration
	timeout         time.Duration
	responseTimeout time.Duration
	expectFault     string
	variables       map[string]string
	keylog          string
	serverName      string
	ca              string
	sshUser         string
	sshPass         string
	sshKey          string
	sshHostKey      string
	sshCommands     []string
	sshExpects      []string
	// specified records which flags were given explicitly, so a flag the
	// selected route cannot honor is refused instead of silently ignored.
	specified map[string]bool
}

// parseReproduceFlags declares the command line, parses it, and applies the
// checks that need nothing but the flags themselves.
func parseReproduceFlags(args []string) (reproduceOptions, error) {
	return parseCaptureReplayFlags("reproduce", args)
}

func parseCaptureReplayFlags(command string, args []string) (reproduceOptions, error) {
	var o reproduceOptions
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	o.executionFlags.register(fs)
	var pcapFlag string
	inputHelp := "input capture file (or use its positional path)"
	if command == "live" {
		inputHelp = "legacy TCP controls unless explicit secure inputs are supplied; prefer a positional capture"
	}
	fs.StringVar(&pcapFlag, flagIn, "", inputHelp)
	fs.StringVar(&o.iface, flagIface, "", "network connection for packet-based replay (asks when required)")
	fs.StringVar(&o.iface, "on", "", "alias for -i")
	fs.StringVar(&o.iface, "iface", "", "alias for -i")
	fs.StringVar(&o.target, flagTarget, "", "device IP or fresh secure target host:port (asks if not given)")
	fs.StringVar(&o.target, "to", "", "alias for -t")
	fs.StringVar(&o.target, "target", "", "alias for -t")
	fs.IntVar(&o.times, flagCount, 1, "how many times to replay; more than 1 reports how often the issue appears")
	fs.IntVar(&o.times, "times", 1, "alias for -n")
	fs.IntVar(&o.times, "iterations", 1, "alias for -n")
	fs.BoolVar(&o.underLoad, "under-load", false, "reproduce a timing/load issue (replay everything at the recorded speed)")
	fs.BoolVar(&o.exactTCP, "exact-tcp", false, "use stateful transport replay for a low-level TCP issue")
	fs.BoolVar(&o.details, flagDetails, false, "show the expert tables: capture assessment, replay plan, and every session's verdict")
	fs.DurationVar(&o.gap, "gap", time.Second, "settle time between attempts when -n is more than 1")
	fs.BoolVar(&o.stopWhenDifferent, "stop-when-different", false, "with -n, stop at the first attempt that doesn't match the recording")
	fs.StringVar(&o.mode, "mode", "", "advanced compatibility override: application | transport | wire | auto (default: fresh application sessions)")
	fs.BoolVar(&o.dryRun, "dry-run", false, "preview selected sessions and requirements without network activity")
	var selectedSessions fileFlags
	fs.Var(&selectedSessions, "session", "select a session ID from check -details (repeatable; includes related FTP data)")
	fs.StringVar(&o.profile, "profile", "functional", "replay fidelity: functional | timing | transport | wire")
	fs.BoolVar(&o.strict, "strict", false, "abort a session at the first structural difference from the recording")
	fs.BoolVar(&o.wire, "wire", false, "explicitly inject captured frames without session adaptation or response verification")
	fs.StringVar(&o.report, "report", "", "where to save the shareable report (default: <capture>.report.json)")
	fs.StringVar(&o.actual, "actual-out", "", "where to save actual replay traffic (default: <capture>.actual.pcap)")
	fs.BoolVar(&o.noGuard, "no-rst-guard", false, "advanced: don't suppress the host's RST (usually leave this off)")
	fs.DurationVar(&o.udpIdle, "udp-idle", 30*time.Second, "split a UDP tuple into a new session after this idle interval")
	var variables setFlags
	fs.Var(&variables, "set", "set a run variable (repeatable name=value; secret names are redacted from reports)")
	var rulePacks fileFlags
	fs.Var(&rulePacks, "rules", "JSON adapter rule pack (repeatable)")
	fs.StringVar(&o.keylog, "keylog", "", "matching NSS key log for TLS/FTPS (never auto-consumed or logged)")
	fs.StringVar(&o.serverName, "server-name", "", "TLS certificate DNS name (default: target host)")
	fs.StringVar(&o.ca, "ca", "", "optional PEM CA bundle for TLS/FTPS verification")
	fs.BoolVar(&o.insecure, "insecure-skip-verify", false, "explicitly disable TLS certificate verification (lab only)")
	fs.DurationVar(&o.timeout, "timeout", 30*time.Second, "fresh TLS, FTPS, or SSH connection timeout")
	fs.DurationVar(&o.responseTimeout, "response-timeout", 0, "application or datagram response deadline (0 uses the protocol default; at most 10m)")
	fs.StringVar(&o.expectFault, "expect-fault", "", "require a reset or timeout while reading an application response; separate from a response match")
	fs.StringVar(&o.sshUser, "user", "", "SSH username")
	fs.StringVar(&o.sshPass, "pass", "", "SSH password (prefer the prompt or LIVEWIRE_SSH_PASSWORD; never written to reports)")
	fs.StringVar(&o.sshKey, "key", "", "SSH private-key file (alternative to -pass)")
	fs.StringVar(&o.sshHostKey, "host-key", "", "pinned OpenSSH public host-key file (required in unified mode)")
	var sshCommands multiFlag
	var sshExpects multiFlag
	fs.Var(&sshCommands, "cmd", "explicit SSH command to run (repeatable)")
	fs.Var(&sshExpects, "expect", "expected SSH output substring, one per -cmd")
	allFlags := registerAllFlags(fs)
	fs.Usage = func() {
		fmt.Printf("usage: livewire %s <capture.pcap> -t <device-ip> [options]\n", command)
		fmt.Println("\nReplay application requests through fresh connections and compare live responses.")
		fmt.Println("The OS maintains TCP state. TLS uses -keylog to recover captured requests,")
		fmt.Println("then opens a fresh certificate-verified TLS session. No -mode is needed.")
		fmt.Println("Use check -details to find session IDs; -session <id> -dry-run previews without sending.")
		fmt.Println("For intermittent issues add -n 5; -under-load preserves supported captured pacing.")
		fmt.Println("Stateless captured-packet injection: livewire replay -in <capture> -i <connection>.")
		if command == "live" {
			fmt.Println("Legacy live -in controls remain available: livewire live -in <capture> -h.")
		}
		printFlags(fs, flagIn, flagTarget, flagCount, "under-load", "session", "dry-run", "keylog", "ca", "server-name", "report", flagDetails)
	}
	pcapPath, err := parseCaptureArgs(fs, args, &pcapFlag)
	if err != nil {
		return o, err
	}
	if handleAllFlags(fs, *allFlags, reproduceAliases) {
		return o, errAllFlags
	}
	warnDeprecatedFlags(fs)
	if pcapPath == "" {
		fs.Usage()
		return o, fmt.Errorf("give a capture file, e.g. livewire %s issue.pcap", command)
	}
	if o.times < 1 {
		return o, fmt.Errorf("-n must be at least 1")
	}
	if o.times > maxReplayAttempts {
		return o, fmt.Errorf("-n must not exceed %d", maxReplayAttempts)
	}
	if o.gap < 0 {
		return o, fmt.Errorf("-gap cannot be negative")
	}
	if o.gap > 10*time.Minute {
		return o, fmt.Errorf("-gap must not exceed 10m")
	}
	o.capture = pcapPath
	o.sessions = []string(selectedSessions)
	o.rulePacks = []string(rulePacks)
	o.variables = map[string]string(variables)
	o.sshCommands = []string(sshCommands)
	o.sshExpects = []string(sshExpects)
	o.specified = map[string]bool{}
	fs.Visit(func(f *flag.Flag) { o.specified[f.Name] = true })
	return o, o.executionFlags.validate()
}

// resolveReproduceIntent turns the requested mode, profile, and shortcuts into
// one resolved intent and fidelity profile. Primary commands use application
// sessions without requiring an additional mode choice.
func resolveReproduceIntent(o *reproduceOptions) (fidelityProfile, *replay.Registry, error) {
	selectedProfile := o.profile
	if o.underLoad && strings.EqualFold(selectedProfile, "functional") {
		selectedProfile = "timing"
	}
	if o.exactTCP && !strings.EqualFold(selectedProfile, "wire") {
		selectedProfile = "transport"
	}
	if o.wire {
		if o.mode != "" && o.mode != "auto" && o.mode != "wire" {
			return fidelityProfile{}, nil, fmt.Errorf("-wire conflicts with -mode %s", o.mode)
		}
		o.mode = "wire"
	}
	o.mode = defaultReplayMode(o.mode, selectedProfile)
	resolvedMode, resolvedProfile, err := replayintent.Resolve(o.mode, selectedProfile)
	if err != nil {
		return fidelityProfile{}, nil, err
	}
	o.mode, o.profile = resolvedMode, string(resolvedProfile)
	profile, err := parseFidelityProfile(o.profile)
	if err != nil {
		return fidelityProfile{}, nil, err
	}
	registry, err := registryWithRulePacks(o.rulePacks)
	if err != nil {
		return fidelityProfile{}, nil, err
	}
	if o.udpIdle <= 0 || o.udpIdle > time.Hour {
		return fidelityProfile{}, nil, fmt.Errorf("-udp-idle must be greater than zero and at most 1h")
	}
	if o.timeout <= 0 || o.timeout > 10*time.Minute {
		return fidelityProfile{}, nil, fmt.Errorf("-timeout must be greater than zero and at most 10m")
	}
	if o.responseTimeout < 0 || o.responseTimeout > 10*time.Minute {
		return fidelityProfile{}, nil, fmt.Errorf("-response-timeout must be between 0 and 10m")
	}
	if o.expectFault != "" {
		if o.expectFault != "reset" && o.expectFault != "timeout" {
			return fidelityProfile{}, nil, fmt.Errorf("-expect-fault must be reset or timeout")
		}
		if o.strictExit || o.stopWhenDifferent {
			return fidelityProfile{}, nil, fmt.Errorf("-expect-fault cannot be combined with -strict-exit or -stop-when-different")
		}
	}
	return profile, registry, nil
}

// Inspection and execution must agree when the operator omits an override.
func defaultReplayMode(mode, profile string) string {
	if mode != "" {
		return mode
	}
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "transport":
		return "transport"
	case "wire":
		return "wire"
	default:
		return "application"
	}
}

// inspectReproduce compiles the replay plan for the resolved intent and refuses
// any flag the selected route cannot honor. It reports whether the route opens
// fresh secure sessions, which changes what the later phases may claim.
func inspectReproduce(o *reproduceOptions, recs []*pcapio.Record, registry *replay.Registry) (*replayintent.Inspection, bool, error) {
	var selectedKeyLog []byte
	if o.keylog != "" && o.mode != "wire" && detectProtocolRoute(recs).kind != protocolTLS {
		var err error
		// #nosec G703 -- the local CLI explicitly selects a keylog path; it is not a remotely supplied or rooted-server path.
		selectedKeyLog, err = os.ReadFile(o.keylog)
		if err != nil {
			return nil, false, err
		}
	}
	inspection, err := replayintent.Inspect(recs, replayintent.Options{KeyLog: selectedKeyLog, Mode: o.mode, Profile: o.profile, Sessions: o.sessions, UDPIdle: o.udpIdle}, registry)
	if err != nil {
		return nil, false, err
	}
	fmt.Printf("Replay intent: %s; %d selected packet(s), %d explicitly excluded.\n", inspection.Mode, inspection.SelectedPackets, inspection.ExcludedPackets)
	secureRoute := inspection.Route.Kind == replayintent.TLS || inspection.Route.Kind == replayintent.SSH || inspection.Route.Kind == replayintent.FTP
	if inspection.Mode != "wire" && secureRoute && inspection.Mode != "transport" {
		if o.exactTCP || (o.profile != "functional" && inspection.Route.Kind != replayintent.TLS) {
			return nil, false, fmt.Errorf("this fresh-session driver does not support timing or exact transport options; choose a supported intent explicitly")
		}
		if o.actual != "" {
			return nil, false, fmt.Errorf("-actual-out is not supported for fresh secure sessions; use -report for redacted evidence")
		}
	}
	if err := refuseUnsupportedFlags(o, inspection, secureRoute); err != nil {
		return nil, false, err
	}
	if o.details && secureRoute {
		printCoverage(inspection.Plan)
	}
	return inspection, secureRoute, nil
}

// refuseUnsupportedFlags rejects an explicitly given flag that the selected
// route would silently ignore, so a peer never believes a control took effect.
func refuseUnsupportedFlags(o *reproduceOptions, inspection *replayintent.Inspection, secureRoute bool) error {
	unsupported := []string{}
	if o.expectFault != "" {
		if inspection.Mode == "wire" || inspection.Mode == "transport" || (secureRoute && inspection.Route.Kind != replayintent.TLS) {
			return fmt.Errorf("-expect-fault requires TCP application or TLS application replay")
		}
		for _, entry := range inspection.Plan.Entries {
			if !entry.Excluded && (entry.Transport != replay.TransportTCP || entry.Mode != replay.ModeSemantic) {
				return fmt.Errorf("-expect-fault requires a framed application adapter for every selected TCP session")
			}
		}
	}
	if inspection.Mode == "wire" || inspection.Mode == "transport" || (secureRoute && inspection.Route.Kind != replayintent.TLS) {
		if o.specified["response-timeout"] {
			return fmt.Errorf("-response-timeout requires TCP application, TLS application, UDP, or ICMP replay")
		}
	}
	if o.specified["response-timeout"] && !secureRoute {
		for _, entry := range inspection.Plan.Entries {
			if entry.Mode == replay.ModeStateful || entry.Mode == replay.ModeCoordinated {
				return fmt.Errorf("-response-timeout requires a framed application adapter for TCP; the stateful packet engine uses bounded retransmission timers")
			}
		}
	}
	if inspection.Mode == "wire" {
		unsupported = []string{"t", "to", "target", "strict", "actual-out", "set", "gap", "stop-when-different", "keylog", "ca", "server-name", "insecure-skip-verify", "user", "pass", "key", "host-key", "cmd", "expect", "exact-tcp"}
	}
	if !secureRoute && inspection.Mode != "wire" {
		unsupported = []string{"keylog", "ca", "server-name", "insecure-skip-verify", "user", "pass", "key", "host-key", "cmd", "expect", "timeout"}
	}
	if secureRoute && inspection.Mode != "wire" && inspection.Mode != "transport" {
		unsupported = append(unsupported, "no-rst-guard")
		if inspection.Route.Kind != replayintent.SSH {
			unsupported = append(unsupported, "user", "pass", "key", "host-key", "cmd", "expect")
		} else {
			unsupported = append(unsupported, "keylog", "ca", "server-name", "insecure-skip-verify", "set", "rules")
		}
	}
	for _, name := range unsupported {
		if o.specified[name] {
			return fmt.Errorf("-%s is not supported by the selected %s replay route", name, inspection.Mode)
		}
	}
	return nil
}

// reproduceDryRun validates the target and output paths and prints what a real
// run would do, without opening an interface or a connection.
func reproduceDryRun(o reproduceOptions, inspection *replayintent.Inspection, secureRoute bool) error {
	if o.target != "" {
		if secureRoute && inspection.Mode != "wire" && inspection.Mode != "transport" {
			if _, err := resolveSecureTarget(o.target, inspection.Route.Session.Server); err != nil {
				return err
			}
		} else if inspection.Mode != "wire" {
			if _, err := parseHostIP(o.target); err != nil {
				return err
			}
		}
	}
	for _, out := range []struct{ value, name string }{{o.report, "-report"}, {o.actual, "-actual-out"}} {
		if out.value != "" {
			if err := outputPathAvailable(out.value); err != nil {
				return fmt.Errorf("%s: %w", out.name, err)
			}
		}
	}
	if o.report != "" && o.actual != "" && sameOutputPath(o.report, o.actual) {
		return fmt.Errorf("-report and -actual-out must name different files")
	}
	base := strings.TrimSuffix(o.capture, filepath.Ext(o.capture))
	preferred := base + ".report.json"
	if secureRoute || inspection.Mode == "wire" {
		kind := inspection.Route.Kind
		if inspection.Mode == "wire" {
			kind = "wire"
		}
		preferred = defaultProtocolReportPath(o.capture, protocolKind(kind))
	}
	output, err := resolveAttemptReportBase(o.report, preferred, o.times)
	if err != nil {
		return err
	}
	fmt.Printf("Report destination: %s\n", output)
	printCoverage(inspection.Plan)
	printProtocolReadiness(readinessFromInspection(inspection.Readiness))
	if o.target != "" {
		fmt.Printf("Target: %s\n", o.target)
	}
	if o.iface != "" {
		fmt.Printf("Interface: %s\n", o.iface)
	}
	fmt.Println("Dry run: no network connections opened and no packets sent.")
	if !inspection.Readiness.Supported {
		return blockedReplayError(o.capture, inspection.Readiness.Blocker)
	}
	return nil
}

// runGenericReproduce drives the plaintext and transport plan: choose the
// device and interface, replay every selected session as many times as asked,
// then save the evidence and print the verdict.
func runGenericReproduce(o reproduceOptions, recs []*pcapio.Record, captureDigest string, inspection *replayintent.Inspection, profile fidelityProfile, registry *replay.Registry) error {
	trace, plan := inspection.Trace, inspection.Plan
	flows := engine.ExtractFlows(recs)
	preflight := assessCapture(recs, flows)
	if o.details {
		printPreflight(preflight)
	}
	fmt.Printf("Loaded %s: %d session(s), %d raw frame(s).\n", filepath.Base(o.capture), len(trace.Sessions), len(trace.Raw))
	if o.details {
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
	base := strings.TrimSuffix(o.capture, filepath.Ext(o.capture))
	out, err := resolveOutputPath(o.report, base+".report.json", "-report")
	if err != nil {
		return err
	}
	actual, err := resolveOutputPath(o.actual, base+".actual.pcap", "-actual-out")
	if err != nil {
		return err
	}
	if sameOutputPath(out, actual) {
		return fmt.Errorf("-report and -actual-out must name different files")
	}

	// 1) Which device? (its IP; the port comes from the capture)
	var deviceIP netip.Addr
	if inspection.Mode != "wire" {
		deviceIP, err = chooseDeviceIP(o.target)
		if err != nil {
			return err
		}
	}
	// 2) Which network connection reaches it?
	iface := o.iface
	if inspection.Mode == "wire" {
		if iface == "" {
			return fmt.Errorf("explicit wire replay needs -i <connection>; no packets were sent")
		}
	} else if inspection.Readiness.NeedsInterface {
		iface, err = chooseInterface(o.iface, deviceIP)
		if err != nil {
			return err
		}
	}
	// Run the most reliable default (adaptive + reply-checking + auto-synthesis).
	// Scenario tuning stays opt-in via flags, suggested only if the default run
	// doesn't reproduce the issue.
	verify := profile.Verify
	if o.strict {
		verify = engine.VerifyStrict
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := o.executionFlags.context(ctx)
	defer cancel()
	evidenceStream := evidence.New(actual)
	evidenceStream.SetJournal(o.journal)
	defer evidenceStream.Close()
	exec := replay.Execution(ctx)
	exec.Evidence = evidenceStream.Record
	ctx = replay.WithExecution(ctx, exec)
	live := liveOpts{
		ctx:    ctx,
		target: deviceIP.String(), iface: iface, seed: 1, noGuard: o.noGuard,
		profile: profile.Name, verify: verify, adaptive: profile.Adaptive, pace: profile.Pace, rawL4: profile.RawL4,
		variables: o.variables, responseTimeout: o.responseTimeout,
	}

	fmt.Printf("\nProfile: %s — %s\n", profile.Name, profile.Description)
	if inspection.Mode == "wire" {
		fmt.Printf("Injecting captured frames on %q ...\n", iface)
	} else {
		fmt.Printf("Replaying against %s on %q ...\n", deviceIP, iface)
	}

	runs := iterate.Plan{Times: o.times, Gap: o.gap, StopWhenDifferent: o.stopWhenDifferent}.Normalize()
	if runs.Repeats() {
		fmt.Printf("Running %d attempts, %s apart. Each attempt opens a fresh connection.\n", runs.Times, runs.Gap)
	}

	rep := newReplayReport(live)
	rep.Intent = inspection.Mode
	rep.SelectedPackets = inspection.SelectedPackets
	rep.ExcludedPackets = inspection.ExcludedPackets
	rep.AdapterVersions = adapters.VersionsForRegistry(registry)
	rep.Preflight = &preflight
	rep.Plan = &plan
	rep.Limitations = plan.Limitations()
	if o.resumeDir != "" {
		rep.Limitations = append(rep.Limitations, "Resumed execution starts a new timing segment; completed session results may come from prior checkpoint evidence.")
	}
	rep.CaptureDigest = captureDigest

	run := &genericReproduceRun{
		evidence: evidenceStream,
		options:  o, ctx: ctx, trace: trace, plan: plan, registry: registry, flows: flows,
		iface: iface, deviceIP: deviceIP, live: live, runs: runs, report: rep,
		// Quiet mode is the default for a repeated run: N copies of the progress
		// log and N verdict blocks bury the one number the reader wants, which
		// is how often it happened. -details restores the full per-attempt output.
		quiet: runs.Repeats() && !o.details,
	}
	per := runs.Run(ctx, run.attempt)
	summary := iterate.SummarizeContext(ctx, per, runs.Times)
	if runs.Repeats() {
		rep.recordIterations(summary)
	}
	artifactErrs := run.publish(out, actual)
	artifactErrs = append(artifactErrs, strictExitError(o.strictExit, ctx, summary))
	var faults []*faultObservation
	for _, session := range rep.Sessions {
		faults = append(faults, session.Fault)
	}
	artifactErrs = append(artifactErrs, faultExpectationError(ctx, o.expectFault, faults))
	printReproduceSummary(summary, runs, profile, o.strict)
	return errors.Join(artifactErrs...)
}

// genericReproduceRun is the state one replay run accumulates across attempts.
type genericReproduceRun struct {
	evidence *evidence.Stream
	options  reproduceOptions
	ctx      context.Context
	trace    *replay.Trace
	plan     replay.ReplayPlan
	registry *replay.Registry
	flows    []*engine.Flow
	iface    string
	deviceIP netip.Addr
	live     liveOpts
	runs     iterate.Plan
	report   *replayReport
	quiet    bool

	mu           sync.Mutex
	actualFrames []pcapio.Record
}

// attempt replays every selected session once and tallies the session verdicts.
func (r *genericReproduceRun) attempt(i int) iterate.Tally {
	exec := replay.Execution(r.ctx)
	exec.Attempt = i
	exec.Scenario = replay.NewScenarioRuntime(r.options.scenario)
	attemptCtx := replay.WithExecution(r.ctx, exec)
	// Every attempt must look like a new connection to the device: the same
	// four-tuple and ISN sent twice in a row is an old duplicate segment as
	// far as TCP is concerned, and the device resets it. That would read as
	// a failure to reproduce when it is really an artefact of repeating.
	att := r.live
	att.seed = r.live.seed + int64(i)
	att.portStride = i
	if r.runs.Repeats() {
		r.report.startAttempt(i + 1)
	}
	logf := func(idx int, line string) {
		if r.quiet {
			return
		}
		line = redactRunText(line, r.options.variables)
		r.mu.Lock()
		defer r.mu.Unlock()
		switch {
		case r.runs.Repeats():
			fmt.Printf("  [attempt %d] %s\n", i+1, line)
		case idx < 0 || len(r.plan.Entries) == 1:
			fmt.Printf("  %s\n", line)
		default:
			fmt.Printf("  [session %d] %s\n", idx, line)
		}
	}
	if !r.quiet && r.runs.Repeats() {
		fmt.Printf("\n---- attempt %d of %d ----\n", i+1, r.runs.Times)
	}

	results := executeReplayPlan(executePlanConfig{
		Context: attemptCtx, Trace: r.trace, Plan: r.plan, Registry: r.registry,
		Flows: r.flows, Iface: r.iface, TargetIP: r.deviceIP, Variables: r.options.variables, Live: att, Log: logf,
	})
	r.report.secretValues = append(r.report.secretValues, exec.Scenario.SecretValues()...)

	var tally iterate.Tally
	note := ""
	for _, result := range results {
		target := r.deviceIP.String()
		if result.Entry.Mode == replay.ModeWire {
			target = "captured destinations"
		} else if result.Session != nil && result.Session.Server.Port != 0 {
			target = netip.AddrPortFrom(r.deviceIP, result.Session.Server.Port).String()
		}
		r.report.addPlanned(result, target)
		if r.options.expectFault != "" {
			sr := &r.report.Sessions[len(r.report.Sessions)-1]
			sr.Fault = observeExpectedFault(attemptCtx, r.options.expectFault, sr.Sent, sr.Cleanup, result.Err)
		}
		r.actualFrames = append(r.actualFrames, result.TCP.Evidence...)
		r.actualFrames = append(r.actualFrames, result.Transport.Evidence...)

		verdict, why := sessionVerdict(result, r.options.variables)
		tally.Add(verdict)
		if note == "" && why != "" {
			note = why
		}
		if !r.quiet {
			printSessionResult(result, r.options.variables)
			fmt.Print(timingLine(result.Transport.Timing))
		}
	}
	if r.runs.Repeats() {
		line := fmt.Sprintf("Attempt %d of %d: %s", i+1, r.runs.Times, tally.Worst().Plain())
		if note != "" {
			line += " — " + note
		}
		fmt.Println(line)
	}
	return tally
}

// publish saves the actual traffic and the report, telling the reader where
// each landed. A failure to save is reported, not hidden.
func (r *genericReproduceRun) publish(reportPath, actualPath string) []error {
	var errs []error
	if r.evidence != nil {
		count, err := r.evidence.Commit()
		if err != nil {
			errs = append(errs, fmt.Errorf("publish actual packet evidence: %w", err))
		} else if count > 0 {
			r.report.ActualCapture = actualPath
			fmt.Printf("\nActual replay traffic was saved to %s.\n", actualPath)
		}
	}
	if len(r.actualFrames) > 0 {
		if err := writeFrames(actualPath, r.actualFrames, true); err != nil {
			errs = append(errs, fmt.Errorf("save actual replay capture: %w", err))
			fmt.Printf("\n(could not save actual replay capture: %v)\n", err)
		} else {
			r.report.ActualCapture = actualPath
			fmt.Printf("\nActual replay traffic was saved to %s.\n", actualPath)
		}
	}
	if err := r.report.write(reportPath); err != nil {
		errs = append(errs, fmt.Errorf("save replay report: %w", err))
		fmt.Printf("\n(could not save report: %v)\n", err)
	} else {
		fmt.Printf("\nA shareable report was saved to %s — send this back so we can see what happened.\n", reportPath)
	}
	return errs
}

// printReproduceSummary prints the one-line answer and, when the issue did not
// reproduce, the opt-in tuning worth trying next.
func printReproduceSummary(summary iterate.Summary, runs iterate.Plan, profile fidelityProfile, strict bool) {
	if runs.Repeats() {
		fmt.Print(summary.Plain())
	} else {
		s := summary.Sessions
		fmt.Printf("\nSummary: %d same as recording, %d different, %d unverified, %d wire-only, %d did not complete.\n",
			s.Same, s.Different, s.Unverified, s.WireOnly, s.Incomplete)
	}
	if (summary.Sessions.Different+summary.Sessions.Incomplete) > 0 && !profile.Pace && !profile.RawL4 && !strict {
		fmt.Println("\nIf you expected the issue to reproduce and it didn't, try one of these:")
		if !runs.Repeats() {
			fmt.Println("  - if it only happens sometimes:      add  -n 5")
		}
		fmt.Println("  - if it's timing- or load-related:   add  -under-load")
		fmt.Println("  - if it's a low-level TCP issue:     add  -exact-tcp")
		fmt.Println("  - to flag every small difference:    add  -strict")
		fmt.Println("Otherwise, send us the report file above and we'll take a look.")
	}
}

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
