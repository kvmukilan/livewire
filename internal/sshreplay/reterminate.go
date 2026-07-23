// Package sshreplay re-terminates captured SSH sessions: it opens a fresh,
// authenticated connection to the device and replays application-layer commands.
//
// SSH does not expose session keys, so the input is an explicit command script
// the operator provides.
package sshreplay

import (
	"bytes"
	"context"
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
	return ReTerminateContext(context.Background(), cfg)
}

// ReTerminateContext is ReTerminate with cancellation spanning the TCP dial,
// SSH handshake, channel creation, and every command. The owned connection is
// closed when the context ends so a stopped job cannot strand blocked SSH I/O.
func ReTerminateContext(ctx context.Context, cfg Config) (*Result, error) {
	if cfg.Auth.User == "" {
		return nil, fmt.Errorf("sshreplay: a username is required")
	}
	if ctx == nil {
		ctx = context.Background()
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

	dialer := &net.Dialer{Timeout: cfg.Timeout}
	raw, err := dialer.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		return res, fmt.Errorf("sshreplay: fresh TCP connection to %s failed: %w", cfg.Address, sshContextError(ctx, err))
	}
	cancelWatchDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = raw.Close()
		case <-cancelWatchDone:
		}
	}()
	defer close(cancelWatchDone)
	if cfg.Timeout > 0 {
		_ = raw.SetDeadline(time.Now().Add(cfg.Timeout))
	}
	conn, chans, reqs, err := ssh.NewClientConn(raw, cfg.Address, ccfg)
	if err != nil {
		_ = raw.Close()
		return res, fmt.Errorf("sshreplay: fresh SSH handshake/auth to %s failed: %w", cfg.Address, sshContextError(ctx, err))
	}
	_ = raw.SetDeadline(time.Time{})
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()

	for i, cmd := range cfg.Commands {
		out, err := runOneContext(ctx, client, cmd.Run)
		if err != nil {
			// Command text can itself contain credentials or tokens. Keep it out
			// of errors because those errors may be logged or included in reports.
			return res, fmt.Errorf("sshreplay: command %d failed: %w", i, err)
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
	return runOneContext(context.Background(), client, command)
}

func runOneContext(ctx context.Context, client *ssh.Client, command string) ([]byte, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, sshContextError(ctx, err)
	}
	defer sess.Close()
	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := sess.CombinedOutput(command)
		done <- result{out: out, err: err}
	}()
	select {
	case <-ctx.Done():
		_ = sess.Close()
		<-done
		return nil, ctx.Err()
	case got := <-done:
		return got.out, got.err
	}
}

func sshContextError(ctx context.Context, fallback error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fallback
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
