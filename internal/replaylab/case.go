// Package replaylab exercises the real command-line binary against independent
// loopback protocol peers. It records software-lab evidence, never physical
// device or network-driver qualification.
package replaylab

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Case struct {
	Name  string
	Setup func(context.Context, string) (*Fixture, error)
}

type Fixture struct {
	Capture  string
	Args     []string
	Snapshot func() Counters
	Events   func() []string
	Close    func() error
}

type Counters struct {
	Requests          int64 `json:"requests"`
	Responses         int64 `json:"responses"`
	ActiveConnections int64 `json:"activeConnections"`
	Errors            int64 `json:"errors"`
}

var registry = map[string]Case{}

// Register is intended for package initialization by protocol case files.
func Register(c Case) {
	if c.Name == "" || c.Setup == nil {
		panic("invalid replay lab case")
	}
	if _, exists := registry[c.Name]; exists {
		panic("duplicate replay lab case: " + c.Name)
	}
	registry[c.Name] = c
}

func Cases() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Stats contains only counters and explicit synthetic-peer notes. Capture
// payloads, passwords, keys and session secrets must never be put in notes.
type Stats struct {
	requests  atomic.Int64
	responses atomic.Int64
	active    atomic.Int64
	errors    atomic.Int64
	mu        sync.Mutex
	events    []string
}

func (s *Stats) Request()  { s.requests.Add(1) }
func (s *Stats) Response() { s.responses.Add(1) }
func (s *Stats) Note(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) < 4096 {
		s.events = append(s.events, fmt.Sprintf(format, args...))
	}
}
func (s *Stats) Snapshot() Counters {
	return Counters{Requests: s.requests.Load(), Responses: s.responses.Load(), ActiveConnections: s.active.Load(), Errors: s.errors.Load()}
}
func (s *Stats) Events() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	events := s.events
	s.events = nil
	return events
}

type TCPServer struct {
	listener    net.Listener
	Stats       *Stats
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	wg          sync.WaitGroup
	closed      chan struct{}
	once        sync.Once
}

func ServeTCP(ctx context.Context, handler func(net.Conn, *Stats) error) (*TCPServer, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return ServeListener(ctx, listener, handler), nil
}

// ServeListener also accepts TLS listeners and is useful for protocol fixtures
// that must choose their own listener configuration.
func ServeListener(ctx context.Context, listener net.Listener, handler func(net.Conn, *Stats) error) *TCPServer {
	s := &TCPServer{listener: listener, Stats: &Stats{}, connections: map[net.Conn]struct{}{}, closed: make(chan struct{})}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			select {
			case <-s.closed:
				s.mu.Unlock()
				_ = conn.Close()
				return
			default:
			}
			s.connections[conn] = struct{}{}
			s.Stats.active.Add(1)
			s.wg.Add(1)
			s.mu.Unlock()
			go func() {
				defer s.wg.Done()
				defer func() {
					_ = conn.Close()
					s.mu.Lock()
					delete(s.connections, conn)
					s.Stats.active.Add(-1)
					s.mu.Unlock()
				}()
				_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
				if err := handler(conn, s.Stats); err != nil {
					s.Stats.errors.Add(1)
					s.Stats.Note("peer validation failed: %v", err)
				}
			}()
		}
	}()
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-s.closed:
		}
	}()
	return s
}

func (s *TCPServer) Address() string { return s.listener.Addr().String() }
func (s *TCPServer) Port() uint16    { return uint16(s.listener.Addr().(*net.TCPAddr).Port) }
func (s *TCPServer) Close() error {
	var result error
	s.once.Do(func() {
		close(s.closed)
		result = s.listener.Close()
		s.mu.Lock()
		for conn := range s.connections {
			_ = conn.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return result
}

// Exchange contains exactly the bytes exchanged by the independent fixture.
// Empty sides model server banners and client-only protocol controls.
type Exchange struct {
	Client []byte
	Server []byte
	At     time.Duration
}
