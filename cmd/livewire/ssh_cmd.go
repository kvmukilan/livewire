package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/sshreplay"
	"golang.org/x/crypto/ssh"
)

// Registers itself at init to keep the command's credential-heavy flags
// separate from the common command table.
func init() {
	commands = append(commands, command{
		"ssh-replay", "re-terminate an SSH session against a live device", cmdSSHReplay,
	})
}

type multiFlag []string

func (m *multiFlag) String() string     { return fmt.Sprintf("%d command(s)", len(*m)) }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func cmdSSHReplay(args []string) error {
	fs := flag.NewFlagSet("ssh-replay", flag.ContinueOnError)
	inPath := fs.String("in", "", "capture containing one SSH session (required)")
	target := fs.String("target", "", "live device host:port (required)")
	user := fs.String("user", "", "SSH username (required)")
	pass := fs.String("pass", "", "SSH password (or use -key)")
	keyPath := fs.String("key", "", "path to a PEM private key (alternative to -pass)")
	hostKeyPath := fs.String("host-key", "", "OpenSSH public host key to pin (recommended)")
	reportPath := fs.String("report", "", "output redacted JSON report (default: <capture>.ssh.report.json)")
	timeout := fs.Duration("timeout", 15*time.Second, "connection timeout")
	var cmds multiFlag
	var expects multiFlag
	fs.Var(&cmds, "cmd", "a command to run on the device (repeatable)")
	fs.Var(&expects, "expect", "required output substring for the corresponding command (repeat for every -cmd)")
	fs.Usage = func() {
		fmt.Println("usage: livewire ssh-replay -in trace.pcap -target host:port -user U (-pass P | -key file) -cmd '...' [-expect '...']")
		fmt.Println("\nAccounts for the captured SSH lane, opens a fresh authenticated SSH connection, and replays the supplied command/expect script.")
		fmt.Println("Captured SSH ciphertext cannot be replayed directly; supply the operations to reproduce.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inPath == "" || *target == "" || *user == "" {
		fs.Usage()
		return fmt.Errorf("-in, -target, and -user are required")
	}
	if len(cmds) == 0 {
		return fmt.Errorf("at least one -cmd is required")
	}
	if len(expects) != 0 && len(expects) != len(cmds) {
		return fmt.Errorf("when -expect is used, provide exactly one for each -cmd")
	}
	if (*pass == "") == (*keyPath == "") {
		return fmt.Errorf("provide exactly one of -pass or -key")
	}

	records, _, err := loadRecords(*inPath)
	if err != nil {
		return err
	}
	trace := replay.ExtractTrace(records, replay.ExtractOptions{})
	var session *replay.Session
	for _, candidate := range trace.Sessions {
		if candidate.Transport == replay.TransportTCP && (adapters.SSH{}).Detect(*candidate) > 0 {
			if session != nil {
				return fmt.Errorf("capture contains more than one SSH session; isolate the intended session first")
			}
			session = candidate
		}
	}
	if session == nil {
		return fmt.Errorf("no SSH session found in capture")
	}
	plan := buildReterminationPlan(trace, session, "ssh-reterminate", "ssh-reterminate")
	if err := plan.ValidateCoverage(); err != nil {
		return fmt.Errorf("SSH replay plan coverage: %w", err)
	}
	printCoverage(plan)
	if *reportPath == "" {
		*reportPath = strings.TrimSuffix(*inPath, filepath.Ext(*inPath)) + ".ssh.report.json"
	}
	digest, err := sha256File(*inPath)
	if err != nil {
		return fmt.Errorf("capture digest: %w", err)
	}

	auth := sshreplay.Auth{User: *user, Password: *pass}
	if *pass == "" && *keyPath != "" {
		pem, err := os.ReadFile(*keyPath)
		if err != nil {
			return err
		}
		auth.PrivateKey = pem
	}
	var pinnedHostKey ssh.PublicKey
	if *hostKeyPath != "" {
		data, err := os.ReadFile(*hostKeyPath)
		if err != nil {
			return err
		}
		pinnedHostKey, _, _, data, err = ssh.ParseAuthorizedKey(data)
		if err != nil {
			return fmt.Errorf("parse -host-key: %w", err)
		}
		if len(bytes.TrimSpace(data)) != 0 {
			return fmt.Errorf("-host-key must contain exactly one OpenSSH public key")
		}
	}

	commandsList := make([]sshreplay.Command, len(cmds))
	for i, c := range cmds {
		commandsList[i] = sshreplay.Command{Run: c}
		if len(expects) > 0 {
			commandsList[i].Expect = expects[i]
		}
	}

	report := newReterminationReport("ssh", digest, *target, plan, nil, nil, append([]string{*user, *pass}, expects...)...)
	report.Transformations = []string{
		"captured SSH ciphertext not reused or interpreted as commands",
		"fresh SSHv2 connection authenticated with operator-supplied credentials (credentials excluded from this report)",
		"operator-supplied command script executed over fresh SSH channels",
	}
	report.Outcome.Adapter = "ssh-reterminate"
	report.Outcome.ProtocolVersion = "SSHv2"
	report.Outcome.Requests = len(commandsList)
	report.Outcome.Verified = len(expects) > 0
	if pinnedHostKey == nil {
		report.Limitations = append(report.Limitations, "SSH host key was observed but not pinned; use -host-key to verify peer identity")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	res, runErr := sshreplay.ReTerminateContext(ctx, sshreplay.Config{
		Address: *target, Auth: auth, Commands: commandsList, Timeout: *timeout,
		Verify: len(expects) > 0, HostKey: pinnedHostKey,
	})
	if res != nil {
		report.Outcome.Responses = len(res.Outputs)
		report.Outcome.Mismatches = res.Mismatches
		report.Outcome.Matched = report.Outcome.Verified && res.Mismatches == 0
		report.Outcome.PeerIdentityChecked = pinnedHostKey != nil && res.HostKey != nil
		for i, output := range res.Outputs {
			sum := sha256.Sum256(output)
			matched := false
			if len(expects) > 0 {
				matched = bytes.Contains(output, []byte(expects[i]))
			}
			report.Outcome.Commands = append(report.Outcome.Commands, commandEvidence{Index: i, OutputBytes: len(output), OutputSHA256: fmt.Sprintf("sha256:%x", sum), Matched: matched})
		}
		if res.HostKey != nil {
			report.Transformations = append(report.Transformations, "live SSH host key fingerprint observed: "+ssh.FingerprintSHA256(res.HostKey))
		}
	}
	if runErr != nil {
		report.Outcome.Error = runErr.Error()
	} else {
		report.Outcome.Completed = true
	}
	if err := report.write(*reportPath); err != nil {
		if runErr != nil {
			return fmt.Errorf("%w (also could not write SSH report: %v)", runErr, err)
		}
		return fmt.Errorf("write SSH report: %w", err)
	}
	if runErr != nil {
		return fmt.Errorf("%w (report: %s)", runErr, *reportPath)
	}
	for i, out := range res.Outputs {
		sum := sha256.Sum256(out)
		fmt.Printf("command %d: %d output bytes, sha256:%x (body excluded from logs)\n", i, len(out), sum)
	}
	fmt.Printf("Report: %s\n", *reportPath)
	if len(expects) > 0 && res.Mismatches > 0 {
		return fmt.Errorf("SSH verification found %d mismatched command output(s)", res.Mismatches)
	}
	return nil
}
