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
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/ftpreplay"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/tlsreplay"
)

func runFTPReplayArgs(args []string) error {
	fs := flag.NewFlagSet("ftp-replay", flag.ContinueOnError)
	var inPath, target string
	fs.StringVar(&inPath, flagIn, "", "capture containing one FTP or FTPS control session")
	fs.StringVar(&target, flagTarget, "", "fresh FTP target host:port")
	fs.StringVar(&target, "target", "", "alias for -t")
	keylogPath := fs.String("keylog", "", "NSS SSLKEYLOGFILE matching an FTPS capture")
	serverName := fs.String("server-name", "", "certificate DNS name (default: target host)")
	caPath := fs.String("ca", "", "optional PEM CA bundle")
	insecure := fs.Bool("insecure-skip-verify", false, "explicitly disable FTPS certificate verification (lab only)")
	verifyText := fs.String("verify", "lenient", "response verification: off, lenient, or strict")
	timeout := fs.Duration("timeout", 30*time.Second, "control and data operation timeout")
	reportPath := fs.String("report", "", "output redacted JSON report (default: <capture>.ftp.report.json)")
	requireComplete := fs.Bool("require-complete-capture", false, "refuse to run when any capture lane would be left unreplayed")
	var variables setFlags
	fs.Var(&variables, "set", "set an FTP variable such as ftp.user, ftp.password, ftp.account, or ftp.advertise-ip")
	allFlags := registerAllFlags(fs)
	fs.Usage = func() {
		fmt.Println("usage: livewire ftp-replay -in trace.pcap -t host:port [-keylog sslkeys.log] [-set ftp.password=...] [-verify strict]")
		fmt.Println("\nCoordinates FTP control and negotiated data connections. A matching key log is required for explicit or implicit FTPS captures.")
		printFlags(fs, flagIn, flagTarget, "keylog", "server-name", "ca", "verify", "report")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if handleAllFlags(fs, *allFlags, aliasSet{"target": true}) {
		return errAllFlags
	}
	if inPath == "" || target == "" {
		fs.Usage()
		return fmt.Errorf("-in and -t are required")
	}
	if *timeout <= 0 || *timeout > 10*time.Minute {
		return fmt.Errorf("-timeout must be greater than zero and at most 10m")
	}
	verify, err := parseReplayVerify(*verifyText)
	if err != nil {
		return err
	}
	if err := validateNetworkTarget(target, "-target"); err != nil {
		return err
	}
	records, _, err := loadRecords(inPath)
	if err != nil {
		return err
	}
	trace := replay.ExtractTrace(records, replay.ExtractOptions{})
	control, err := selectFTPControl(trace)
	if err != nil {
		return err
	}
	var keylog *tlsreplay.KeyLog
	if *keylogPath != "" {
		f, err := os.Open(*keylogPath)
		if err != nil {
			return err
		}
		keylog, err = tlsreplay.ParseKeyLog(f)
		closeErr := f.Close()
		if err := errors.Join(err, closeErr); err != nil {
			return err
		}
	}
	script, err := ftpreplay.BuildScript(control, keylog)
	if err != nil {
		return err
	}
	data, err := ftpreplay.MatchDataSessions(trace, control, script)
	if err != nil {
		return err
	}
	plan := buildFTPPlan(trace, control, data)
	if err := plan.ValidateCoverage(); err != nil {
		return fmt.Errorf("FTP replay plan coverage: %w", err)
	}
	if err := validateReterminationExecution(plan, *requireComplete); err != nil {
		return fmt.Errorf("FTP replay plan: %w", err)
	}
	printCoverage(plan)

	var tlsConfig *tls.Config
	if script.Explicit || script.Implicit || script.ProtectData {
		tlsConfig, err = ftpTLSConfig(target, *serverName, *caPath, *insecure)
		if err != nil {
			return err
		}
	}
	resolvedReport, err := resolveOutputPath(*reportPath, strings.TrimSuffix(inPath, filepath.Ext(inPath))+".ftp.report.json", "-report")
	if err != nil {
		return err
	}
	*reportPath = resolvedReport
	digest, err := sha256File(inPath)
	if err != nil {
		return err
	}
	report := newReterminationReport("ftp", digest, target, plan, nil, variables)
	report.Transformations = []string{
		"FTP control messages decoded and replayed on a fresh connection",
		"PASV, EPSV, PORT, and EPRT endpoints replaced with live negotiated endpoints",
		"FTP data sessions coordinated with their owning transfer commands",
	}
	if script.Explicit || script.Implicit {
		report.Transformations = append(report.Transformations, "captured FTPS records decrypted with operator-supplied secrets and re-terminated with fresh verified TLS")
	}
	if *insecure {
		report.Limitations = append(report.Limitations, "FTPS peer identity verification was explicitly disabled")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, runErr := ftpreplay.RunContext(ctx, ftpreplay.Config{
		Control: control, Data: data, Address: target, Script: script,
		Variables: variables, TLSConfig: tlsConfig, Timeout: *timeout, Verify: verify,
		Progress: func(line string) { fmt.Println("  " + redactRunText(line, variables)) },
	})
	if runErr != nil {
		runErr = errors.New(redactRunText(runErr.Error(), variables))
	}
	report.Outcome.Completed = result.Completed
	report.Outcome.Verified = result.Verified
	report.Outcome.Matched = result.Verified && ftpResultMatched(result)
	report.Outcome.Adapter = "ftp"
	report.Outcome.ProtocolVersion = ftpProtocolVersion(script)
	report.Outcome.PeerIdentityChecked = result.TLS && !*insecure
	report.Outcome.Requests, report.Outcome.Responses = result.Commands, result.Replies
	report.Outcome.Mismatches = len(result.Differences)
	report.Outcome.Differences = result.Differences
	report.Outcome.Transfers = result.Transfers
	if runErr != nil {
		report.Outcome.Error = redactRunText(runErr.Error(), variables)
	}
	if err := report.write(*reportPath); err != nil {
		return fmt.Errorf("write FTP report: %w", err)
	}
	fmt.Printf("FTP replay complete: control commands=%d replies=%d transfers=%d matched=%v\nReport: %s\n", result.Commands, result.Replies, len(result.Transfers), report.Outcome.Matched, *reportPath)
	return runErr
}

func selectFTPControl(trace *replay.Trace) (*replay.Session, error) {
	var selected *replay.Session
	for _, session := range trace.Sessions {
		if session.Transport != replay.TransportTCP {
			continue
		}
		client, _, err := replay.TCPPayloadStreams(session)
		if err != nil {
			continue
		}
		isFTP := (adapters.FTP{}).Detect(*session) >= 100 || session.Server.Port == 990 && dissect.DetectTLS(client).IsTLS
		if !isFTP {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("capture contains more than one FTP control session; isolate the intended session first")
		}
		selected = session
	}
	if selected == nil {
		return nil, fmt.Errorf("no FTP or FTPS control session found")
	}
	return selected, nil
}

func parseReplayVerify(value string) (replay.VerifyMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "lenient", "on", "warn":
		return replay.VerifyLenient, nil
	case "off", "none":
		return replay.VerifyOff, nil
	case "strict":
		return replay.VerifyStrict, nil
	default:
		return "", fmt.Errorf("invalid verify mode %q (want off|lenient|strict)", value)
	}
}

func ftpTLSConfig(target, serverName, caPath string, insecure bool) (*tls.Config, error) {
	host, _, _ := net.SplitHostPort(target)
	if serverName == "" {
		serverName = strings.Trim(host, "[]")
	}
	config := &tls.Config{ServerName: serverName, InsecureSkipVerify: insecure} // #nosec G402 -- explicit lab-only flag
	if caPath == "" {
		return config, nil
	}
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("-ca contains no parseable certificates")
	}
	config.RootCAs = roots
	return config, nil
}

func buildFTPPlan(trace *replay.Trace, control *replay.Session, data []*replay.Session) replay.ReplayPlan {
	plan := replay.ReplayPlan{Profile: replay.ProfileFunctional, Packets: trace.Packets}
	selected := map[string]bool{control.ID: true}
	entry := replay.PlanEntry{SessionID: control.ID, Transport: replay.TransportTCP, Driver: "ftp-coordinator", Adapter: "ftp", Mode: replay.ModeCoordinated, Fidelity: replay.FidelitySemantic, PacketIndexes: reterminationPacketIndexes(control.Events)}
	for _, session := range data {
		selected[session.ID] = true
		entry.RelatedSessionIDs = append(entry.RelatedSessionIDs, session.ID)
		entry.PacketIndexes = append(entry.PacketIndexes, reterminationPacketIndexes(session.Events)...)
	}
	sort.Ints(entry.PacketIndexes)
	entry.Transformations = []string{"FTP control and negotiated data sessions coordinated on fresh connections"}
	plan.Entries = append(plan.Entries, entry)
	for _, session := range trace.Sessions {
		if selected[session.ID] {
			continue
		}
		plan.Entries = append(plan.Entries, replay.PlanEntry{SessionID: session.ID, Transport: session.Transport, Driver: "none", Mode: replay.ModeBlocked, Fidelity: replay.FidelityBlocked, PacketIndexes: reterminationPacketIndexes(session.Events), Blockers: []string{"session is outside the selected FTP exchange"}})
	}
	if len(trace.Raw) > 0 {
		plan.Entries = append(plan.Entries, replay.PlanEntry{SessionID: "raw-0", Transport: replay.TransportRaw, Driver: "none", Mode: replay.ModeBlocked, Fidelity: replay.FidelityBlocked, PacketIndexes: reterminationPacketIndexes(trace.Raw), Blockers: []string{"raw frames are outside the selected FTP exchange"}})
	}
	return plan
}

func ftpResultMatched(result ftpreplay.Result) bool {
	if len(result.Differences) > 0 {
		return false
	}
	for _, transfer := range result.Transfers {
		if !transfer.Matched {
			return false
		}
	}
	return result.Completed
}

func ftpProtocolVersion(script ftpreplay.Script) string {
	switch {
	case script.Explicit:
		return "FTP with explicit TLS"
	case script.Implicit:
		return "FTP with implicit TLS"
	default:
		return "FTP"
	}
}
