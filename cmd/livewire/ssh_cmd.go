//go:build ssh

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/kvmukilan/livewire/internal/sshreplay"
)

// Compiled only under -tags ssh, keeping x/crypto/ssh out of the default build.
// Registers itself at init so the command table needs no build-tag awareness.
func init() {
	commands = append(commands, command{
		"ssh-replay", "re-terminate an SSH session against a live device (needs -tags ssh)", cmdSSHReplay,
	})
}

type multiFlag []string

func (m *multiFlag) String() string     { return fmt.Sprint(*m) }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func cmdSSHReplay(args []string) error {
	fs := flag.NewFlagSet("ssh-replay", flag.ContinueOnError)
	target := fs.String("target", "", "live device host:port (required)")
	user := fs.String("user", "", "SSH username (required)")
	pass := fs.String("pass", "", "SSH password (or use -key)")
	keyPath := fs.String("key", "", "path to a PEM private key (alternative to -pass)")
	timeout := fs.Duration("timeout", 15*time.Second, "connection timeout")
	var cmds multiFlag
	fs.Var(&cmds, "cmd", "a command to run on the device (repeatable)")
	fs.Usage = func() {
		fmt.Println("usage: livewire ssh-replay -target host:port -user U (-pass P | -key file) -cmd '...' [-cmd '...']")
		fmt.Println("\nOpens a fresh authenticated SSH connection and replays the given commands.")
		fmt.Println("Captured SSH ciphertext cannot be replayed directly; supply the operations to reproduce.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" || *user == "" {
		fs.Usage()
		return fmt.Errorf("-target and -user are required")
	}
	if len(cmds) == 0 {
		return fmt.Errorf("at least one -cmd is required")
	}

	auth := sshreplay.Auth{User: *user, Password: *pass}
	if *pass == "" && *keyPath != "" {
		pem, err := os.ReadFile(*keyPath)
		if err != nil {
			return err
		}
		auth.PrivateKey = pem
	}

	commandsList := make([]sshreplay.Command, len(cmds))
	for i, c := range cmds {
		commandsList[i] = sshreplay.Command{Run: c}
	}

	res, err := sshreplay.ReTerminate(sshreplay.Config{
		Address: *target, Auth: auth, Commands: commandsList, Timeout: *timeout,
	})
	if err != nil {
		return err
	}
	for i, out := range res.Outputs {
		fmt.Printf("=== command %d: %s ===\n%s\n", i, cmds[i], out)
	}
	return nil
}
