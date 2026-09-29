package replaylab

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// delayedAcceptListener models Accept winning its socket race immediately
// before Close, while registration of that socket happens after Close.
type delayedAcceptListener struct {
	conn     net.Conn
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
	accepted bool
}

func (l *delayedAcceptListener) Accept() (net.Conn, error) {
	if l.accepted {
		return nil, net.ErrClosed
	}
	l.accepted = true
	close(l.entered)
	<-l.release
	return l.conn, nil
}
func (l *delayedAcceptListener) Close() error   { l.once.Do(func() { close(l.release) }); return nil }
func (l *delayedAcceptListener) Addr() net.Addr { return l.conn.LocalAddr() }

func TestFixtureCloseClosesSocketAcceptedDuringShutdown(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	listener := &delayedAcceptListener{conn: peer, entered: make(chan struct{}), release: make(chan struct{})}
	called := make(chan struct{}, 1)
	server := ServeListener(context.Background(), listener, func(conn net.Conn, _ *Stats) error {
		called <- struct{}{}
		var b [1]byte
		_, err := conn.Read(b[:])
		return err
	})
	<-listener.entered
	done := make(chan error, 1)
	go func() { done <- server.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		_ = peer.Close()
		t.Fatal("fixture shutdown missed a concurrently accepted socket")
	}
	select {
	case <-called:
		t.Fatal("fixture started a new handler after shutdown")
	default:
	}
	if server.Stats.Snapshot().ActiveConnections != 0 {
		t.Fatal("fixture retained active sockets")
	}
}
