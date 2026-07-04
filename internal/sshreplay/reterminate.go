//go:build ssh

// Package sshreplay re-terminates captured SSH sessions: it opens a fresh,
// authenticated connection to the device and replays application-layer commands.
//
// Built only under the "ssh" tag, since it's the one part of livewire that
// pulls in golang.org/x/crypto/ssh (see AGENTS.md). SSH doesn't expose session
// keys, so the input is an explicit command script the operator provides.
package sshreplay

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// Auth selects how to authenticate to the live device.
type Auth struct {
	User       string
	Password   string // used if non-empty
	PrivateKey []byte // PEM; used if Password is empty
}

// Command is one operation to replay on the device.
type Command struct {
	Run    string // the remote command line
	Expect string // if set and Verify is on, the output must contain this
}

// Config drives a re-termination.
type Config struct {
	Address  string // host:port of the live device
	Auth     Auth
	Commands []Command
	Timeout  time.Duration
	Verify   bool
	// HostKey, if set, must match the device's key; if nil, the key is accepted
	// and recorded (lab use). Pin it in production.
	HostKey ssh.PublicKey
}

// Result reports the outcome.
type Result struct {
	Outputs    [][]byte
	Mismatches int
	HostKey    ssh.PublicKey // the key the device actually presented
}

// ReTerminate opens a fresh SSH connection and replays the command script,
// capturing each command's output.
func ReTerminate(cfg Config) (*Result, error) {
	if cfg.Auth.User == "" {
		return nil, fmt.Errorf("sshreplay: a username is required")
	}
	res := &Result{}
	hostKeyCB := ssh.HostKeyCallback(func(_ string, _ net.Addr, key ssh.PublicKey) error {
		res.HostKey = key
		if cfg.HostKey != nil && !bytes.Equal(key.Marshal(), cfg.HostKey.Marshal()) {
			return fmt.Errorf("host key mismatch: device is not the pinned host")
		}
		return nil
	})

	auths, err := authMethods(cfg.Auth)
	if err != nil {
		return nil, err
	}
	ccfg := &ssh.ClientConfig{
		User:            cfg.Auth.User,
		Auth:            auths,
		HostKeyCallback: hostKeyCB,
		Timeout:         cfg.Timeout,
	}

	client, err := ssh.Dial("tcp", cfg.Address, ccfg)
	if err != nil {
		return res, fmt.Errorf("sshreplay: fresh SSH handshake/auth to %s failed: %w", cfg.Address, err)
	}
	defer client.Close()

	for i, cmd := range cfg.Commands {
		out, err := runOne(client, cmd.Run)
		if err != nil {
			return res, fmt.Errorf("sshreplay: command %d (%q): %w", i, cmd.Run, err)
		}
		res.Outputs = append(res.Outputs, out)
		if cfg.Verify && cmd.Expect != "" && !bytes.Contains(out, []byte(cmd.Expect)) {
			res.Mismatches++
		}
	}
	return res, nil
}

// runOne runs one command on a new session channel and returns its combined output.
func runOne(client *ssh.Client, command string) ([]byte, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	return sess.CombinedOutput(command)
}

func authMethods(a Auth) ([]ssh.AuthMethod, error) {
	if a.Password != "" {
		return []ssh.AuthMethod{ssh.Password(a.Password)}, nil
	}
	if len(a.PrivateKey) > 0 {
		signer, err := ssh.ParsePrivateKey(a.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("sshreplay: parsing private key: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	}
	return nil, fmt.Errorf("sshreplay: no credentials (set a password or private key)")
}
