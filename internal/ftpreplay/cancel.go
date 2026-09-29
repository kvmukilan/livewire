package ftpreplay

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// Bind cancellation to each owned raw connection, including connections later
// wrapped in TLS. Closing stops the callback and never races mutable run state.
type cancelConn struct {
	net.Conn
	once sync.Once
	err  error
	stop func() bool
}

func (c *cancelConn) closeRaw()    { c.once.Do(func() { c.err = c.Conn.Close() }) }
func (c *cancelConn) Close() error { c.stop(); c.closeRaw(); return c.err }

func bindConnection(ctx context.Context, conn net.Conn, timeout time.Duration) (net.Conn, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	c := &cancelConn{Conn: conn}
	c.stop = context.AfterFunc(ctx, c.closeRaw)
	return c, nil
}
