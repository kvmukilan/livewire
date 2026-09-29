package sshreplay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/ssh"
	"net"
	"testing"
	"time"
)

func TestSSHBoundsChannelOpenAfterSuccessfulHandshake(t *testing.T) {
	for _, manual := range []bool{true, false} {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			t.Fatal(err)
		}
		cfg := &ssh.ServerConfig{NoClientAuth: true}
		cfg.AddHostKey(signer)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		opened := make(chan struct{})
		released := make(chan struct{})
		go func() {
			defer close(released)
			c, e := ln.Accept()
			if e != nil {
				return
			}
			defer c.Close()
			_, channels, requests, e := ssh.NewServerConn(c, cfg)
			if e != nil {
				return
			}
			go ssh.DiscardRequests(requests)
			first := true
			for range channels {
				if first {
					close(opened)
					first = false
				}
			}
		}()
		ctx, cancel := context.WithCancel(context.Background())
		timeout := time.Second
		if manual {
			timeout = 30 * time.Second
		}
		done := make(chan error, 1)
		go func() {
			_, e := ReTerminateContext(ctx, Config{Address: ln.Addr().String(), Auth: Auth{User: "test", Password: "test"}, HostKey: signer.PublicKey(), Commands: []Command{{Run: "show status"}}, Timeout: timeout})
			done <- e
		}()
		select {
		case <-opened:
		case <-time.After(2 * time.Second):
			cancel()
			ln.Close()
			t.Fatal("SSH never opened channel")
		}
		if manual {
			cancel()
		}
		select {
		case err = <-done:
			want := context.DeadlineExceeded
			if manual {
				want = context.Canceled
			}
			if !errors.Is(err, want) {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			cancel()
			t.Fatal("SSH channel open outlived deadline/cancel")
		}
		cancel()
		ln.Close()
		select {
		case <-released:
		case <-time.After(time.Second):
			t.Fatal("SSH connection leaked")
		}
	}
}
