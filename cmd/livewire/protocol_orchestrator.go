package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/iterate"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
	"golang.org/x/term"
)

// protocolKind is the capture-level driver selected by the common front door.
// Plaintext and ordinary transport captures remain with the generic replay
// planner; only exchanges that need fresh security state are intercepted here.
type protocolKind string

const (
	protocolGeneric protocolKind = "generic"
	protocolTLS     protocolKind = "tls"
	protocolFTP     protocolKind = "ftp"
	protocolSSH     protocolKind = "ssh"
	protocolOpaque  protocolKind = "opaque"
)

type protocolRoute struct {
	kind    protocolKind
	session *replay.Session
	trace   *replay.Trace
	reason  string
}

type protocolReadiness struct {
	Route        protocolKind `json:"route"`
	Supported    bool         `json:"supported"`
	Requirements []string     `json:"requirements,omitempty"`
	Blocker      string       `json:"blocker,omitempty"`
}

func assessProtocolReadiness(route protocolRoute) protocolReadiness {
	ready := protocolReadiness{Route: route.kind, Supported: route.reason == ""}
	if route.reason != "" {
		ready.Blocker = route.reason
		return ready
	}
	switch route.kind {
	case protocolGeneric:
		ready.Requirements = []string{"target device IP", "network connection for on-wire replay"}
	case protocolTLS:
		ready.Requirements = []string{"fresh target host:port", "matching NSS key log", "trusted server certificate or explicit lab override"}
	case protocolFTP:
		ready.Requirements = []string{"fresh FTP target host:port"}
		if route.session != nil && ftpNeedsKeyLog(route.session) {
			ready.Requirements = append(ready.Requirements, "matching NSS key log for FTPS", "trusted server certificate or explicit lab override")
		}
	case protocolSSH:
		ready.Requirements = []string{"fresh SSH target host:port", "username and one credential", "pinned host key", "explicit command script"}
	default:
		ready.Supported = false
		ready.Blocker = "no safe automatic driver is available"
	}
	return ready
}

func printProtocolReadiness(ready protocolReadiness) {
	if !ready.Supported {
		fmt.Printf("\nAutomatic route: BLOCKED (%s)\n", ready.Blocker)
		return
	}
	fmt.Printf("\nAutomatic route: %s\n", ready.Route)
	if len(ready.Requirements) > 0 {
		fmt.Println("Live replay will require:")
		for _, requirement := range ready.Requirements {
			fmt.Printf("  - %s\n", requirement)
		}
	}
}

// orchestratorOptions contains the requirements shared by `reproduce` and the
// positional `live` experience. It deliberately contains values, not flag-set
// details, so protocol runners do not need to know which front door was used.
type orchestratorOptions struct {
	capture, iface, target              string
	keylog, serverName, ca              string
	insecure, strict, wire              bool
	user, password, privateKey, hostKey string
	commands, expects                   []string
	timeout                             time.Duration
	gap                                 time.Duration
	report                              string
	times                               int
	stopWhenDifferent                   bool
	variables                           map[string]string
	rulePacks                           []string
}

// The old protocol-specific commands remain callable compatibility aliases.
// They enter through the same driver dispatch used by the primary commands,
// while retaining their established flags and exit behavior.
func cmdTLSReplay(args []string) error { return runProtocolCompatibility(protocolTLS, args) }
func cmdFTPReplay(args []string) error { return runProtocolCompatibility(protocolFTP, args) }
func cmdSSHReplay(args []string) error { return runProtocolCompatibility(protocolSSH, args) }

func runProtocolCompatibility(kind protocolKind, args []string) error {
	switch kind {
	case protocolTLS:
		return runTLSReplayArgs(args)
	case protocolFTP:
		return runFTPReplayArgs(args)
	case protocolSSH:
		return runSSHReplayArgs(args)
	default:
		return fmt.Errorf("unsupported protocol driver %q", kind)
	}
}

// orchestrateProtocolCapture runs a secure or explicitly wire-level capture.
// handled=false means the caller should use the normal protocol/transport plan.
func orchestrateProtocolCapture(records []*pcapio.Record, opts orchestratorOptions) (handled bool, err error) {
	if opts.wire {
		if opts.iface == "" {
			return true, fmt.Errorf("explicit wire replay needs -i <connection>; no packets were sent")
		}
		reportPath, err := resolveOutputPath(opts.report, defaultProtocolReportPath(opts.capture, protocolKind("wire")), "-report")
		if err != nil {
			return true, err
		}
		args := []string{"-in", opts.capture, "-i", opts.iface, "-multiplier", "1", "-n", fmt.Sprint(opts.times), "-report", reportPath}
		fmt.Println("Mode: explicit wire replay - captured frames will be injected without session adaptation or response verification.")
		return true, cmdReplay(args)
	}

	route := detectProtocolRoute(records)
	if route.kind == protocolGeneric {
		return false, nil
	}
	if route.reason != "" {
		return true, errors.New(route.reason)
	}
	resolved, err := resolveProtocolRequirements(route, opts)
	if err != nil {
		return true, err
	}
	if route.kind == protocolFTP && !ftpNeedsKeyLog(route.session) {
		fmt.Println("Detected FTP. Opening fresh coordinated control and data connections; captured endpoints will be renegotiated.")
	} else {
		fmt.Printf("Detected %s. Opening a fresh authenticated session; captured ciphertext will not be transmitted.\n", strings.ToUpper(string(route.kind)))
	}
	return true, runProtocolAttempts(route.kind, resolved)
}

func detectProtocolRoute(records []*pcapio.Record) protocolRoute {
	trace := replay.ExtractTrace(records, replay.ExtractOptions{})
	// FTP must win before generic TLS: implicit FTPS control and protected data
	// lanes are TLS sessions, but they must be coordinated as one FTP exchange.
	var ftp, tlsSessions, sshSessions, opaqueSessions []*replay.Session
	for _, session := range trace.Sessions {
		if session.Transport != replay.TransportTCP {
			continue
		}
		client, server, err := replay.TCPPayloadStreams(session)
		if err != nil {
			continue
		}
		if (adapters.FTP{}).Detect(*session) >= 100 || session.Server.Port == 990 && dissect.DetectTLS(client).IsTLS {
			ftp = append(ftp, session)
			continue
		}
		switch {
		case (adapters.SSH{}).Detect(*session) > 0:
			sshSessions = append(sshSessions, session)
		case isTLSSession(session):
			tlsSessions = append(tlsSessions, session)
		case looksOpaqueEncrypted(client) || looksOpaqueEncrypted(server):
			opaqueSessions = append(opaqueSessions, session)
		}
	}
	if len(ftp) > 0 {
		if len(ftp) > 1 {
			return protocolRoute{kind: protocolOpaque, trace: trace, reason: "capture contains more than one FTP/FTPS control session; isolate the intended exchange first so no session is selected by guesswork. No packets were sent"}
		}
		if len(sshSessions) > 0 {
			return protocolRoute{kind: protocolOpaque, trace: trace, reason: "capture mixes FTP/FTPS with an SSH session; automatic execution would leave part of the capture unreproduced. Isolate the intended exchange first; no packets were sent"}
		}
		return protocolRoute{kind: protocolFTP, session: ftp[0], trace: trace}
	}
	if len(sshSessions) > 0 && len(tlsSessions) > 0 {
		return protocolRoute{kind: protocolOpaque, trace: trace, reason: "capture mixes SSH and TLS sessions; each needs different fresh-session requirements. Isolate one secure exchange first; no ciphertext was sent"}
	}
	if len(sshSessions) > 1 {
		return protocolRoute{kind: protocolOpaque, trace: trace, reason: "capture contains more than one SSH session; isolate the intended exchange first so credentials and commands cannot be applied to the wrong device. No ciphertext was sent"}
	}
	if len(tlsSessions) > 1 {
		return protocolRoute{kind: protocolOpaque, trace: trace, reason: "capture contains more than one TLS session; isolate the intended exchange first so key material is not applied by guesswork. No ciphertext was sent"}
	}
	if len(opaqueSessions) > 0 && len(sshSessions)+len(tlsSessions) > 0 {
		return protocolRoute{kind: protocolOpaque, trace: trace, reason: "capture includes a recognized secure session and another opaque session with no safe driver. Isolate the intended exchange first; no ciphertext was sent"}
	}
	if len(sshSessions) > 0 {
		return protocolRoute{kind: protocolSSH, session: sshSessions[0], trace: trace}
	}
	if len(tlsSessions) > 0 {
		return protocolRoute{kind: protocolTLS, session: tlsSessions[0], trace: trace}
	}
	if len(opaqueSessions) > 0 {
		return protocolRoute{kind: protocolOpaque, session: opaqueSessions[0], trace: trace, reason: "a TCP session appears encrypted or opaque, but Livewire cannot identify a safe fresh-session driver. No ciphertext was sent; inspect with 'livewire check <capture> -details' or use explicit --wire only when raw injection is truly intended"}
	}
	return protocolRoute{kind: protocolGeneric, trace: trace}
}

// looksOpaqueEncrypted is intentionally conservative. It catches sustained,
// high-entropy binary payloads that would otherwise be mislabeled as ordinary
// TCP, while leaving short binary industrial messages to the normal planner.
func looksOpaqueEncrypted(payload []byte) bool {
	if len(payload) < 256 {
		return false
	}
	counts := [256]int{}
	printable := 0
	for _, b := range payload {
		counts[b]++
		if b == '\r' || b == '\n' || b == '\t' || b >= 0x20 && b <= 0x7e {
			printable++
		}
	}
	if float64(printable)/float64(len(payload)) > 0.55 {
		return false
	}
	entropy := 0.0
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / float64(len(payload))
		entropy -= p * math.Log2(p)
	}
	return entropy >= 7.0
}

func resolveProtocolRequirements(route protocolRoute, opts orchestratorOptions) (orchestratorOptions, error) {
	if route.session == nil {
		return opts, fmt.Errorf("%s was detected but its session could not be selected", route.kind)
	}
	var err error
	opts.target, err = resolveSecureTarget(opts.target, route.session.Server)
	if err != nil {
		return opts, err
	}
	switch route.kind {
	case protocolTLS:
		opts.keylog, err = resolveKeyLog(opts.capture, opts.keylog, "TLS")
	case protocolFTP:
		if ftpNeedsKeyLog(route.session) {
			opts.keylog, err = resolveKeyLog(opts.capture, opts.keylog, "FTPS")
		}
	case protocolSSH:
		err = resolveSSHRequirements(&opts)
	}
	return opts, err
}

func resolveSecureTarget(value string, captured replay.Endpoint) (string, error) {
	if value == "" {
		if !isTerminal(os.Stdin) {
			return "", fmt.Errorf("a fresh secure session needs a target; pass -t <host:port> (captured endpoint was %s)", captured)
		}
		value = prompt(fmt.Sprintf("Fresh-session target [%s]: ", captured))
		if value == "" {
			value = captured.String()
		}
	}
	if _, _, err := net.SplitHostPort(value); err != nil {
		if captured.Port == 0 {
			return "", fmt.Errorf("target %q has no port; pass -t <host:port>", value)
		}
		value = net.JoinHostPort(strings.Trim(value, "[]"), fmt.Sprint(captured.Port))
	}
	if err := validateNetworkTarget(value, "-t"); err != nil {
		return "", err
	}
	return value, nil
}

func resolveKeyLog(capture, explicit, label string) (string, error) {
	return resolveKeyLogWithPrompt(capture, explicit, label, isTerminal(os.Stdin), prompt)
}

func resolveKeyLogWithPrompt(capture, explicit, label string, interactive bool, ask func(string) string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	candidates := keyLogCandidates(capture)
	if !interactive {
		hint := ""
		if len(candidates) > 0 {
			hint = fmt.Sprintf(" A possible key log is %q; it was not read automatically.", candidates[0])
		}
		return "", fmt.Errorf("%s needs the matching NSS key log; pass -keylog <file>.%s", label, hint)
	}
	def := ""
	if len(candidates) > 0 {
		def = candidates[0]
		fmt.Printf("Found a possible key log at %s. Livewire will use it only if you confirm it.\n", def)
	}
	question := fmt.Sprintf("Matching %s key log path", label)
	if def != "" {
		question += fmt.Sprintf(" [%s]", def)
	}
	value := ask(question + ": ")
	if value == "" {
		value = def
	}
	if value == "" {
		return "", fmt.Errorf("%s cannot be reproduced without a matching key log; rerun with -keylog <file>", label)
	}
	return value, nil
}

func keyLogCandidates(capture string) []string {
	base := strings.TrimSuffix(capture, filepath.Ext(capture))
	wants := []string{base + ".keylog", base + ".keys", filepath.Join(filepath.Dir(capture), "sslkeys.log")}
	if env := strings.TrimSpace(os.Getenv("SSLKEYLOGFILE")); env != "" {
		wants = append(wants, env)
	}
	seen := map[string]bool{}
	var found []string
	for _, path := range wants {
		if seen[path] {
			continue
		}
		seen[path] = true
		// #nosec G703 -- candidates are operator-selected local CLI paths and are
		// only suggested; they are never consumed without explicit confirmation.
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			found = append(found, path)
		}
	}
	return found
}

func ftpNeedsKeyLog(session *replay.Session) bool {
	client, _, err := replay.TCPPayloadStreams(session)
	if err != nil {
		return session.Server.Port == 990
	}
	return session.Server.Port == 990 || strings.Contains(strings.ToUpper(string(client)), "AUTH TLS\r\n")
}

func resolveSSHRequirements(opts *orchestratorOptions) error {
	if opts.user == "" && isTerminal(os.Stdin) {
		opts.user = prompt("SSH username: ")
	}
	if opts.user == "" {
		return fmt.Errorf("SSH needs a username; pass -user <name>")
	}
	if opts.password != "" && opts.privateKey != "" {
		return fmt.Errorf("SSH accepts exactly one authentication method; pass either -pass or -key, not both")
	}
	if opts.password == "" && opts.privateKey == "" && isTerminal(os.Stdin) {
		opts.privateKey = prompt("SSH private-key path (leave blank to enter a password): ")
		if opts.privateKey == "" {
			fmt.Print("SSH password (input hidden): ")
			secret, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				return fmt.Errorf("read SSH password: %w", err)
			}
			opts.password = string(secret)
		}
	}
	if opts.password == "" && opts.privateKey == "" {
		return fmt.Errorf("SSH needs credentials; pass exactly one of -pass <password> or -key <private-key-file>")
	}
	if opts.hostKey == "" && isTerminal(os.Stdin) {
		opts.hostKey = prompt("Pinned SSH host-key file: ")
	}
	if opts.hostKey == "" {
		return fmt.Errorf("SSH host identity verification is required in unified mode; pass -host-key <OpenSSH-public-key-file>")
	}
	if len(opts.commands) == 0 && isTerminal(os.Stdin) {
		for {
			command := prompt("SSH command (blank when finished): ")
			if command == "" {
				break
			}
			opts.commands = append(opts.commands, command)
			opts.expects = append(opts.expects, prompt("Expected output substring (blank for no check): "))
		}
	}
	if len(opts.commands) == 0 {
		return fmt.Errorf("SSH ciphertext does not reveal commands; pass at least one explicit -cmd <command>")
	}
	if len(opts.expects) != 0 && len(opts.expects) != len(opts.commands) {
		return fmt.Errorf("when -expect is used, provide exactly one for each -cmd")
	}
	opts.expects = normalizeSSHExpects(opts.expects)
	return nil
}

func normalizeSSHExpects(expects []string) []string {
	for _, expect := range expects {
		if strings.TrimSpace(expect) != "" {
			return expects
		}
	}
	return nil
}

func runProtocolAttempts(kind protocolKind, opts orchestratorOptions) error {
	if opts.times < 1 {
		opts.times = 1
	}
	var err error
	opts.report, err = resolveAttemptReportBase(opts.report, defaultProtocolReportPath(opts.capture, kind), opts.times)
	if err != nil {
		return err
	}
	var errs []error
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	runs := iterate.Plan{Times: opts.times, Gap: opts.gap, StopWhenDifferent: opts.stopWhenDifferent}.Normalize()
	per := runs.Run(ctx, func(index int) iterate.Tally {
		attempt := index + 1
		if opts.times > 1 {
			fmt.Printf("\n---- fresh secure attempt %d of %d ----\n", attempt, opts.times)
		}
		args := protocolRunnerArgs(kind, opts, attempt)
		runErr := runProtocolCompatibility(kind, args)
		if runErr != nil {
			runErr = redactProtocolError(runErr, opts)
			errs = append(errs, fmt.Errorf("attempt %d: %w", attempt, runErr))
		}
		outcome, reportErr := readReterminationOutcome(protocolAttemptReportPath(opts.report, attempt, opts.times), kind)
		var tally iterate.Tally
		if reportErr != nil {
			tally.Add(iterate.Incomplete)
			if runErr == nil {
				errs = append(errs, fmt.Errorf("attempt %d report: %w", attempt, reportErr))
			}
		} else {
			tally.Add(iterate.ClassifyVerified(outcome.Completed, outcome.Verified, outcome.Matched, false))
		}
		if opts.times > 1 {
			fmt.Printf("Attempt %d of %d: %s\n", attempt, opts.times, tally.Worst().Plain())
		}
		return tally
	})
	if ctx.Err() != nil {
		errs = append(errs, ctx.Err())
	}
	if opts.times > 1 {
		summary := iterate.Summarize(per, runs.Times)
		fmt.Print(summary.Plain())
		if len(per) > 0 {
			fmt.Printf("Secure report paths: %s through %s\n",
				protocolAttemptReportPath(opts.report, 1, opts.times),
				protocolAttemptReportPath(opts.report, len(per), opts.times))
		}
	}
	return errors.Join(errs...)
}

func protocolRunnerArgs(kind protocolKind, opts orchestratorOptions, attempt int) []string {
	args := []string{"-in", opts.capture, "-t", opts.target, "-timeout", opts.timeout.String(), "-require-complete-capture"}
	if opts.report != "" {
		args = append(args, "-report", protocolAttemptReportPath(opts.report, attempt, opts.times))
	}
	if opts.keylog != "" {
		args = append(args, "-keylog", opts.keylog)
	}
	if opts.serverName != "" {
		args = append(args, "-server-name", opts.serverName)
	}
	if opts.ca != "" {
		args = append(args, "-ca", opts.ca)
	}
	if opts.insecure {
		args = append(args, "-insecure-skip-verify")
	}
	switch kind {
	case protocolTLS:
		if opts.strict {
			args = append(args, "-strict")
		}
		for _, name := range sortedVariableNames(opts.variables) {
			value := opts.variables[name]
			args = append(args, "-set", name+"="+value)
		}
		for _, path := range opts.rulePacks {
			args = append(args, "-rules", path)
		}
	case protocolFTP:
		verify := "lenient"
		if opts.strict {
			verify = "strict"
		}
		args = append(args, "-verify", verify)
		for _, name := range sortedVariableNames(opts.variables) {
			value := opts.variables[name]
			args = append(args, "-set", name+"="+value)
		}
	case protocolSSH:
		args = append(args, "-user", opts.user, "-host-key", opts.hostKey)
		if opts.password != "" {
			args = append(args, "-pass", opts.password)
		} else {
			args = append(args, "-key", opts.privateKey)
		}
		for _, command := range opts.commands {
			args = append(args, "-cmd", command)
		}
		for _, expect := range opts.expects {
			args = append(args, "-expect", expect)
		}
	}
	return args
}

func sortedVariableNames(variables map[string]string) []string {
	names := make([]string, 0, len(variables))
	for name := range variables {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func redactProtocolError(err error, opts orchestratorOptions) error {
	if err == nil {
		return nil
	}
	message := redactRunText(err.Error(), opts.variables)
	if opts.password != "" {
		message = strings.ReplaceAll(message, opts.password, "[REDACTED]")
	}
	return errors.New(message)
}

func attemptReportPath(path string, attempt, times int) string {
	if times <= 1 {
		return path
	}
	ext := filepath.Ext(path)
	return fmt.Sprintf("%s.attempt-%d%s", strings.TrimSuffix(path, ext), attempt, ext)
}

func defaultProtocolReportPath(capture string, kind protocolKind) string {
	return strings.TrimSuffix(capture, filepath.Ext(capture)) + "." + string(kind) + ".report.json"
}

func protocolAttemptReportPath(base string, attempt, times int) string {
	return attemptReportPath(base, attempt, times)
}

func resolveAttemptReportBase(requested, preferred string, times int) (string, error) {
	if times <= 1 {
		return resolveOutputPath(requested, preferred, "-report")
	}
	for n := 1; n <= 10_000; n++ {
		candidate := requested
		if candidate == "" {
			candidate = preferred
			if n > 1 {
				ext := filepath.Ext(preferred)
				candidate = strings.TrimSuffix(preferred, ext) + fmt.Sprintf("-%d", n) + ext
			}
		}
		available := true
		for attempt := 1; attempt <= times; attempt++ {
			if err := outputPathAvailable(protocolAttemptReportPath(candidate, attempt, times)); err != nil {
				if requested != "" || !errors.Is(err, os.ErrExist) {
					return "", fmt.Errorf("-report output %q: %w", protocolAttemptReportPath(candidate, attempt, times), err)
				}
				available = false
				break
			}
		}
		if available {
			return candidate, nil
		}
		if requested != "" {
			break
		}
	}
	return "", fmt.Errorf("could not find unused secure-attempt report names near %q", preferred)
}

func readReterminationOutcome(path string, kind protocolKind) (reterminationOutcome, error) {
	// #nosec G703 -- path was generated or explicitly selected by the local CLI
	// and was just written through securefile's no-replace publication.
	f, err := os.Open(path)
	if err != nil {
		return reterminationOutcome{}, err
	}
	defer f.Close()
	var report reterminationReport
	decoder := json.NewDecoder(io.LimitReader(f, 16<<20))
	if err := decoder.Decode(&report); err != nil {
		return reterminationOutcome{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if report.Tool != "livewire" || report.Kind != string(kind) {
		return reterminationOutcome{}, fmt.Errorf("%s is not a Livewire %s report", path, kind)
	}
	return report.Outcome, nil
}
