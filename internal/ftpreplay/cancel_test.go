package ftpreplay

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/replay"
)

func TestFTPCancellationReleasesBlockedControlRead(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{})
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		close(accepted)
		var b [1]byte
		_, _ = c.Read(b[:])
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	control := ftpControlSession(1234)
	script, err := BuildScript(control, nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		r, e := RunContext(ctx, Config{Address: ln.Addr().String(), Control: control, Script: script, Timeout: 30 * time.Second, Verify: replay.VerifyStrict})
		if r.Completed {
			e = errors.New("cancelled exchange claimed completion")
		}
		done <- e
	}()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("no connection")
	}
	cancel()
	select {
	case err = <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FTP did not stop within two seconds")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("control connection leaked")
	}
}

func TestFTPDataReadCancellationAndDeadline(t *testing.T) {
	for _, manual := range []bool{true, false} {
		ctx, cancel := context.WithCancel(context.Background())
		client, peer := net.Pipe()
		timeout := 30 * time.Second
		if !manual {
			timeout = 50 * time.Millisecond
		}
		conn, err := bindConnection(ctx, client, timeout)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, e := runTransfer(conn, ftpControlSession(1234), ftpDataSession(1234, "expected"), "RETR")
			done <- e
		}()
		if manual {
			cancel()
		}
		select {
		case err = <-done:
			if err == nil {
				t.Fatal("stalled transfer succeeded")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("data read did not stop")
		}
		_ = conn.Close()
		_ = peer.Close()
		cancel()
	}
}

func TestFTPActiveAcceptCancellationReleasesListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { _, e := acceptContext(ctx, ln, 30*time.Second); done <- e }()
	select {
	case err = <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("active accept did not stop")
	}
}
