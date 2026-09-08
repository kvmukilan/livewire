package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/replayintent"
	"github.com/kvmukilan/livewire/internal/secureexec"
	"github.com/kvmukilan/livewire/internal/tlsreplay"
)

func runTLSReplayArgs(args []string) error {
	fs := flag.NewFlagSet("tls-replay", flag.ContinueOnError)
	var inPath string
	fs.StringVar(&inPath, flagIn, "", "capture containing one TLS session")
	keylogPath := fs.String("keylog", "", "NSS SSLKEYLOGFILE matching the capture (required; never logged)")
	var target string
	fs.StringVar(&target, flagTarget, "", "fresh TLS target host:port")
	fs.StringVar(&target, "target", "", "alias for -t")
	serverName := fs.String("server-name", "", "certificate DNS name (default: target host)")
	caPath := fs.String("ca", "", "optional PEM CA bundle")
	insecure := fs.Bool("insecure-skip-verify", false, "explicitly disable certificate verification (lab only)")
	strict := fs.Bool("strict", false, "require live plaintext responses to byte-match the capture")
	timeout := fs.Duration("timeout", 10*time.Second, "fresh connection timeout")
	reportPath := fs.String("report", "", "output redacted JSON report (default: <capture>.tls.report.json)")
	var selectedSessions fileFlags
	fs.Var(&selectedSessions, "session", "select session ID (repeatable)")
	requireComplete := fs.Bool("require-complete-capture", false, "refuse to run when any capture lane would be left unreplayed")
	var variables setFlags
	fs.Var(&variables, "set", "set an inner-protocol variable (repeatable name=value)")
	var rulePacks fileFlags
	fs.Var(&rulePacks, "rules", "JSON inner-protocol adapter rule pack (repeatable)")
	allFlags := registerAllFlags(fs)
	fs.Usage = func() {
		fmt.Println("usage: livewire tls-replay -in trace.pcap -keylog sslkeys.log -t host:port [-server-name name] [-set name=value]")
		fmt.Println("\nDecrypts supported TLS 1.2/1.3 AEAD records with the supplied key log, opens a fresh verified TLS connection, and replays plaintext through the detected inner adapter.")
		printFlags(fs, flagIn, "keylog", flagTarget, "server-name", "ca", "strict", "report")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if handleAllFlags(fs, *allFlags, aliasSet{"target": true}) {
		return errAllFlags
	}
	if inPath == "" || *keylogPath == "" || target == "" {
		fs.Usage()
		return fmt.Errorf("-in, -keylog, and -t are required")
	}
	if err := validateNetworkTarget(target, "-target"); err != nil {
		return err
	}
	if *timeout <= 0 || *timeout > 10*time.Minute {
		return fmt.Errorf("-timeout must be greater than zero and at most 10m")
	}
	records, _, err := loadRecords(inPath)
	if err != nil {
		return err
	}
	trace := replay.ExtractTrace(records, replay.ExtractOptions{})
	trace, err = replayintent.Select(trace, selectedSessions, nil)
	if err != nil {
		return err
	}
	var session *replay.Session
	for _, s := range trace.Sessions {
		if s.Transport == replay.TransportTCP && isTLSSession(s) {
			if session != nil {
				return fmt.Errorf("capture contains more than one TLS session; isolate the intended session first")
			}
			session = s
		}
	}
	if session == nil {
		return fmt.Errorf("no TLS session found in capture")
	}
	clientTimeline, serverTimeline, err := replay.TCPPayloadTimelines(session)
	if err != nil {
		return fmt.Errorf("TLS TCP stream reconstruction: %w", err)
	}
	kf, err := os.Open(*keylogPath)
	if err != nil {
		return err
	}
	keylog, parseErr := tlsreplay.ParseKeyLog(kf)
	if err := errors.Join(parseErr, kf.Close()); err != nil {
		return err
	}
	messages, err := tlsreplay.NewDecryptor(keylog).DecryptFlowTimed(
		clientTimeline.Data, serverTimeline.Data,
		clientTimeline.CompletionPoint, serverTimeline.CompletionPoint,
	)
	if err != nil {
		return err
	}
	registry, err := registryWithRulePacks(rulePacks)
	if err != nil {
		return err
	}
	innerSession := replay.Session{Transport: replay.TransportTCP, Client: session.Client, Server: session.Server}
	for i, m := range messages {
		dir := replay.ClientToServer
		if m.Role == tlsreplay.FromServer {
			dir = replay.ServerToClient
		}
		innerSession.Events = append(innerSession.Events, replay.Event{PacketIndex: i, Direction: dir, Payload: m.Data})
	}
	inner, confidence := registry.Best(innerSession)
	if confidence == 0 || inner == nil || inner.Name() == "tls-reterminate" || inner.Name() == "ssh-reterminate" {
		inner = nil
	}
	state := &replay.RuntimeState{Variables: copyStringMap(variables), Learned: map[string][]byte{}}
	script := tlsreplay.ConversationOrder(messages)
	if inner != nil {
		script, err = buildTLSAdapterScript(messages, inner, state)
		if err != nil {
			return err
		}
	}
	plan := buildReterminationPlan(trace, session, "tls-reterminate", "tls-reterminate")
	if err := plan.ValidateCoverage(); err != nil {
		return fmt.Errorf("TLS replay plan coverage: %w", err)
	}
	if err := validateReterminationExecution(plan, *requireComplete); err != nil {
		return fmt.Errorf("TLS replay plan: %w", err)
	}
	printCoverage(plan)
	resolvedReport, err := resolveOutputPath(*reportPath, strings.TrimSuffix(inPath, filepath.Ext(inPath))+".tls.report.json", "-report")
	if err != nil {
		return err
	}
	*reportPath = resolvedReport
	digest, err := sha256File(inPath)
	if err != nil {
		return fmt.Errorf("capture digest: %w", err)
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid -target: %w", err)
	}
	if *serverName == "" {
		*serverName = strings.Trim(host, "[]")
	}
	tlsCfg := &tls.Config{ServerName: *serverName, InsecureSkipVerify: *insecure} // #nosec G402 -- explicit lab flag
	if *caPath != "" {
		pem, err := os.ReadFile(*caPath)
		if err != nil {
			return err
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return fmt.Errorf("-ca contains no parseable certificates")
		}
		tlsCfg.RootCAs = roots
	}
	verifyMode := replay.VerifyLenient
	if *strict {
		verifyMode = replay.VerifyStrict
	}
	innerName := "opaque plaintext"
	if inner != nil {
		innerName = inner.Name()
	}
	report := newReterminationReport("tls", digest, target, plan, registry, variables)
	report.Transformations = []string{
		"captured TLS records decrypted with operator-supplied session secrets (secrets excluded from this report)",
		"fresh TLS connection established to the live target",
		"decrypted application chronology replayed through " + innerName,
	}
	if *insecure {
		report.Limitations = append(report.Limitations, "TLS peer identity verification was explicitly disabled")
	}
	report.Outcome.Adapter = innerName
	report.Outcome.Requests = countTLSRole(script, tlsreplay.FromClient)
	report.Outcome.Verified = *strict || inner != nil

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	res, runErr := tlsreplay.ReTerminateContext(ctx, tlsreplay.ReTermConfig{Address: target, TLSConfig: tlsCfg, Script: script, Timeout: *timeout, Verify: *strict, Adapter: inner, State: state, VerifyMode: verifyMode})
	if runErr != nil {
		runErr = errors.New(redactRunText(runErr.Error(), variables))
	}
	if res != nil {
		report.Outcome.ProtocolVersion = tlsVersionName(res.HandshakeState.Version)
		report.Outcome.CipherSuite = tls.CipherSuiteName(res.HandshakeState.CipherSuite)
		report.Outcome.ALPN = res.HandshakeState.NegotiatedProtocol
		report.Outcome.Responses = len(res.Responses)
		report.Outcome.Mismatches = res.Mismatches
		report.Outcome.Differences = res.Differences
		report.Outcome.Matched = report.Outcome.Verified && res.Mismatches == 0
		report.Outcome.PeerIdentityChecked = !*insecure
	}
	if runErr != nil {
		report.Outcome.Error = runErr.Error()
	} else {
		report.Outcome.Completed = true
	}
	if err := report.write(*reportPath); err != nil {
		if runErr != nil {
			return fmt.Errorf("%w (also could not write TLS report: %v)", runErr, err)
		}
		return fmt.Errorf("write TLS report: %w", err)
	}
	if runErr != nil {
		return fmt.Errorf("%w (report: %s)", runErr, *reportPath)
	}
	fmt.Printf("TLS retermination complete: version=0x%04x cipher=0x%04x inner=%s responses=%d mismatches=%d certificateVerified=%v\n",
		res.HandshakeState.Version, res.HandshakeState.CipherSuite, innerName, len(res.Responses), res.Mismatches, !*insecure)
	fmt.Printf("Report: %s\n", *reportPath)
	if *strict && res.Mismatches > 0 {
		return fmt.Errorf("strict TLS verification found %d mismatched response(s)", res.Mismatches)
	}
	return nil
}

func countTLSRole(script []tlsreplay.AppMessage, role tlsreplay.AppRole) int {
	n := 0
	for _, message := range script {
		if message.Role == role {
			n++
		}
	}
	return n
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func buildTLSAdapterScript(m []tlsreplay.AppMessage, a replay.Adapter, s *replay.RuntimeState) ([]tlsreplay.AppMessage, error) {
	return secureexec.BuildTLSAdapterScript(m, a, s)
}
func copyStringMap(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func isTLSSession(s *replay.Session) bool {
	client, _, err := replay.TCPPayloadStreams(s)
	return err == nil && dissect.DetectTLS(client).IsTLS
}
