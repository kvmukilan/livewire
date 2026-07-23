package sshreplay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startSSHServer runs an in-process SSH server that accepts one password and
// answers every exec request with a fixed banner.
func startSSHServer(t *testing.T, user, pass, reply string) string {
	t.Helper()
	addr, _ := startSSHServerWithKey(t, user, pass, reply)
	return addr
}

func startSSHServerWithKey(t *testing.T, user, pass, reply string) (string, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if c.User() == user && string(p) == pass {
				return &ssh.Permissions{}, nil
			}
			return nil, ssh.ErrNoAuth
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
		if err != nil {
			return
		}
		go ssh.DiscardRequests(reqs)
		for nc := range chans {
			if nc.ChannelType() != "session" {
				nc.Reject(ssh.UnknownChannelType, "only sessions")
				continue
			}
			ch, requests, err := nc.Accept()
			if err != nil {
				return
			}
			go func() {
				for req := range requests {
					if req.Type == "exec" {
						if req.WantReply {
							req.Reply(true, nil)
						}
						ch.Write([]byte(reply))
						sendExitStatus(ch, 0)
						ch.Close()
					} else if req.WantReply {
						req.Reply(false, nil)
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), signer.PublicKey()
}

func sendExitStatus(ch ssh.Channel, code uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], code)
	ch.SendRequest("exit-status", false, b[:])
}

func TestSSHReTerminate(t *testing.T) {
	addr := startSSHServer(t, "lab", "secret", "Cisco IOS Software, Version 15.2\n")

	res, err := ReTerminate(Config{
		Address: addr,
		Auth:    Auth{User: "lab", Password: "secret"},
		Commands: []Command{
			{Run: "show version", Expect: "IOS"},
		},
		Timeout: 5 * time.Second,
		Verify:  true,
	})
	if err != nil {
		t.Fatalf("ReTerminate: %v", err)
	}
	if len(res.Outputs) != 1 || !strings.Contains(string(res.Outputs[0]), "IOS") {
		t.Fatalf("command output not recovered: %q", res.Outputs)
	}
	if res.Mismatches != 0 {
		t.Fatalf("expected verified output, got %d mismatches", res.Mismatches)
	}
	if res.HostKey == nil {
		t.Fatal("device host key not recorded")
	}
}

func TestSSHReTerminateBadAuth(t *testing.T) {
	addr := startSSHServer(t, "lab", "secret", "banner\n")
	_, err := ReTerminate(Config{
		Address:  addr,
		Auth:     Auth{User: "lab", Password: "wrong"},
		Commands: []Command{{Run: "x"}},
		Timeout:  5 * time.Second,
	})
	if err == nil {
		t.Fatal("expected auth failure with wrong password")
	}
}

func TestSSHReTerminateNoCreds(t *testing.T) {
	if _, err := ReTerminate(Config{Address: "127.0.0.1:1", Auth: Auth{User: "x"}}); err == nil {
		t.Fatal("expected error with no credentials")
	}
}

func TestSSHReTerminatePinsHostKey(t *testing.T) {
	addr, hostKey := startSSHServerWithKey(t, "lab", "secret", "ok\n")
	res, err := ReTerminate(Config{
		Address: addr, Auth: Auth{User: "lab", Password: "secret"},
		Commands: []Command{{Run: "show"}}, Timeout: time.Second, HostKey: hostKey,
	})
	if err != nil || res.HostKey == nil {
		t.Fatalf("pinned retermination result=%+v err=%v", res, err)
	}
	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongSigner, err := ssh.NewSignerFromKey(wrongPrivate)
	if err != nil {
		t.Fatal(err)
	}
	addr, _ = startSSHServerWithKey(t, "lab", "secret", "ok\n")
	if _, err := ReTerminate(Config{
		Address: addr, Auth: Auth{User: "lab", Password: "secret"},
		Commands: []Command{{Run: "show"}}, Timeout: time.Second, HostKey: wrongSigner.PublicKey(),
	}); err == nil || !strings.Contains(err.Error(), "host key mismatch") {
		t.Fatalf("expected host key mismatch, got %v", err)
	}
}

func TestSSHReTerminateContextCancelsHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = ReTerminateContext(ctx, Config{
		Address: ln.Addr().String(), Auth: Auth{User: "lab", Password: "secret"},
		Commands: []Command{{Run: "show"}}, Timeout: 5 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), context.DeadlineExceeded.Error()) {
		t.Fatalf("expected context deadline, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("cancellation took %s", elapsed)
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("cancelled SSH connection was not released")
	}
}
