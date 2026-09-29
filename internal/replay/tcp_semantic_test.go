package replay

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

type closeErrorConn struct {
	net.Conn
	err error
}

func TestRunTCPSemanticClientHalfCloseAllowsResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		request, err := io.ReadAll(conn)
		if err == nil && string(request) != "ping" {
			err = errors.New("unexpected request")
		}
		if err == nil {
			_, err = conn.Write([]byte("pong"))
		}
		serverDone <- err
	}()
	session := tcpStreamTestSession([]tcpStreamTestSegment{{100, wire.FlagSYN, ""}, {101, 0, "ping"}, {105, wire.FlagFIN, ""}})
	response := tcpStreamTestSession([]tcpStreamTestSegment{{500, 0, "pong"}}).Events[0]
	response.Direction = ServerToClient
	response.PacketIndex = len(session.Events)
	session.Events = append(session.Events, response)
	result, err := RunTCPSemanticContext(context.Background(), TCPSemanticConfig{
		Session: session, Adapter: fourByteAdapter{}, Verify: VerifyStrict, Timeout: time.Second,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		},
	})
	if serverErr := <-serverDone; serverErr != nil {
		t.Fatalf("server did not receive client EOF: %v (replay error: %v)", serverErr, err)
	}
	if err != nil || !result.Completed || !result.Matched || result.Sent != 1 || result.Received != 1 {
		t.Fatalf("half-close result=%+v err=%v", result, err)
	}
}

func TestRunTCPSemanticRejectsMissingPrefixBeforeDial(t *testing.T) {
	session := tcpStreamTestSession([]tcpStreamTestSegment{{100, wire.FlagSYN, ""}, {103, 0, "ping"}})
	dialed := false
	_, err := RunTCPSemanticContext(context.Background(), TCPSemanticConfig{
		Session: session, Adapter: fourByteAdapter{},
		Dial: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("unexpected dial")
		},
	})
	if err == nil || !strings.Contains(err.Error(), "missing 2 byte") || dialed {
		t.Fatalf("incomplete capture reached target: err=%v dialed=%v", err, dialed)
	}
}

func (c *closeErrorConn) Close() error { return errors.Join(c.Conn.Close(), c.err) }

type fourByteAdapter struct{}

func (fourByteAdapter) Name() string              { return "four" }
func (fourByteAdapter) Detect(Session) Confidence { return 100 }
func (fourByteAdapter) Decode(_ Direction, b []byte) ([]Message, error) {
	if len(b) < 4 {
		return nil, net.UnknownNetworkError("incomplete")
	}
	return []Message{{Kind: "four", Raw: append([]byte(nil), b[:4]...)}}, nil
}

type eofAdapter struct{ fourByteAdapter }

type timedFourAdapter struct{ fourByteAdapter }

func (timedFourAdapter) Decode(_ Direction, data []byte) ([]Message, error) {
	if len(data)%4 != 0 {
		return nil, io.ErrUnexpectedEOF
	}
	var out []Message
	for len(data) > 0 {
		out = append(out, Message{Raw: append([]byte(nil), data[:4]...)})
		data = data[4:]
	}
	return out, nil
}

type timedFourNormalizer struct{ timedFourAdapter }

func (timedFourNormalizer) NormalizeConversation(turns []ConversationTurn) ([]ConversationTurn, error) {
	return turns, nil
}

func TestTimingPreservesPauseBetweenSameDirectionMessages(t *testing.T) {
	for _, adapter := range []Adapter{timedFourAdapter{}, timedFourNormalizer{}} {
		client, server := net.Pipe()
		done := make(chan time.Duration, 1)
		go func() {
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 4)
			_, _ = io.ReadFull(server, buf)
			first := time.Now()
			_, _ = io.ReadFull(server, buf)
			done <- time.Since(first)
			_, _ = server.Write([]byte("done"))
		}()
		session := &Session{ID: "timing", Transport: TransportTCP, Events: []Event{{Direction: ClientToServer, Payload: []byte("ping")}, {Direction: ClientToServer, Payload: []byte("pong"), At: 150 * time.Millisecond}, {Direction: ServerToClient, Payload: []byte("done"), At: 160 * time.Millisecond}}}
		result, err := RunTCPSemanticContext(context.Background(), TCPSemanticConfig{Session: session, Adapter: adapter, Profile: ProfileTiming, Verify: VerifyStrict, Timeout: time.Second, Dial: func(context.Context, string, string) (net.Conn, error) { return client, nil }})
		gap := <-done
		if err != nil || !result.Matched || result.Sent != 2 || gap < 130*time.Millisecond {
			t.Fatalf("same-direction pause lost (%T): gap=%s result=%+v err=%v", adapter, gap, result, err)
		}
	}
}

func (eofAdapter) Decode(_ Direction, b []byte) ([]Message, error) {
	if len(b) == 0 {
		return nil, net.UnknownNetworkError("incomplete")
	}
	return []Message{{Kind: "eof", Raw: append([]byte(nil), b...)}}, nil
}
func (eofAdapter) RequiresEOF(Direction, Message) bool { return true }
func (fourByteAdapter) Prepare(_ Direction, m Message, _ *RuntimeState) ([]byte, error) {
	return m.Raw, nil
}
func (fourByteAdapter) Correlate(_, _ Message, _ *RuntimeState) Match { return Match{Matched: true} }
func (fourByteAdapter) Compare(w, g Message, _ VerifyMode) []Difference {
	if string(w.Raw) == string(g.Raw) {
		return nil
	}
	return []Difference{{Field: "body", Structural: true}}
}

func TestRunTCPSemanticContext(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	dial := func(context.Context, string, string) (net.Conn, error) { return client, nil }
	go func() {
		buf := make([]byte, 4)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("pong"))
	}()
	s := &Session{ID: "tcp-0", Transport: TransportTCP, Events: []Event{
		{Direction: ClientToServer, Record: &pcapio.Record{}, Payload: []byte("ping")},
		{Direction: ServerToClient, Record: &pcapio.Record{}, Payload: []byte("pong")},
	}}
	res, err := RunTCPSemanticContext(context.Background(), TCPSemanticConfig{Session: s, Adapter: fourByteAdapter{}, Verify: VerifyStrict, Timeout: time.Second, Dial: dial})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Completed || !res.Matched || res.Sent != 1 || res.Received != 1 {
		t.Fatalf("result=%+v", res)
	}
}

func TestRunTCPSemanticCloseFailureInvalidatesSuccess(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	dial := func(context.Context, string, string) (net.Conn, error) {
		return &closeErrorConn{Conn: client, err: errors.New("injected close failure")}, nil
	}
	go func() {
		buf := make([]byte, 4)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("pong"))
	}()
	s := &Session{ID: "tcp-0", Transport: TransportTCP, Events: []Event{
		{Direction: ClientToServer, Record: &pcapio.Record{}, Payload: []byte("ping")},
		{Direction: ServerToClient, Record: &pcapio.Record{}, Payload: []byte("pong")},
	}}
	res, err := RunTCPSemanticContext(context.Background(), TCPSemanticConfig{Session: s, Adapter: fourByteAdapter{}, Verify: VerifyStrict, Timeout: time.Second, Dial: dial})
	if err == nil || !strings.Contains(err.Error(), "injected close failure") {
		t.Fatalf("close error was not propagated: result=%+v err=%v", res, err)
	}
	if res.Completed || !strings.Contains(res.Error, "injected close failure") {
		t.Fatalf("close failure left a successful result: %+v", res)
	}
}

func TestRunTCPSemanticVerificationOffNeverClaimsMatch(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	dial := func(context.Context, string, string) (net.Conn, error) { return client, nil }
	go func() {
		buf := make([]byte, 4)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("pong"))
	}()
	session := &Session{ID: "tcp-0", Transport: TransportTCP, Events: []Event{
		{Direction: ClientToServer, Record: &pcapio.Record{}, Payload: []byte("ping")},
		{Direction: ServerToClient, Record: &pcapio.Record{}, Payload: []byte("pong")},
	}}
	result, err := RunTCPSemanticContext(context.Background(), TCPSemanticConfig{
		Session: session, Adapter: fourByteAdapter{}, Verify: VerifyOff, Timeout: time.Second, Dial: dial,
	})
	if err != nil || !result.Completed || result.Verified || result.Matched {
		t.Fatalf("unverified semantic result overclaimed fidelity: result=%+v err=%v", result, err)
	}
}

func TestRunTCPSemanticCancellation(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	dial := func(context.Context, string, string) (net.Conn, error) { return client, nil }
	s := &Session{ID: "tcp-0", Transport: TransportTCP, Events: []Event{
		{Direction: ClientToServer, Record: &pcapio.Record{}, Payload: []byte("ping")},
		{Direction: ServerToClient, Record: &pcapio.Record{}, Payload: []byte("pong")},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := RunTCPSemanticContext(ctx, TCPSemanticConfig{Session: s, Adapter: fourByteAdapter{}, Timeout: time.Second, Dial: dial}); err == nil {
		t.Fatal("expected cancellation")
	}
	if time.Since(start) > 300*time.Millisecond {
		t.Fatal("cancellation was not prompt")
	}
}

func TestRunTCPSemanticWaitsForEOFFramedResponse(t *testing.T) {
	client, server := net.Pipe()
	dial := func(context.Context, string, string) (net.Conn, error) { return client, nil }
	go func() {
		defer server.Close()
		buf := make([]byte, 4)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("pa"))
		time.Sleep(15 * time.Millisecond)
		_, _ = server.Write([]byte("rt"))
	}()
	s := &Session{ID: "tcp-0", Transport: TransportTCP, Events: []Event{
		{Direction: ClientToServer, Record: &pcapio.Record{}, Payload: []byte("ping")},
		{Direction: ServerToClient, Record: &pcapio.Record{}, Payload: []byte("part")},
	}}
	res, err := RunTCPSemanticContext(context.Background(), TCPSemanticConfig{Session: s, Adapter: eofAdapter{}, Verify: VerifyStrict, Timeout: time.Second, Dial: dial})
	if err != nil || !res.Completed || !res.Matched {
		t.Fatalf("EOF-framed result=%+v err=%v", res, err)
	}
}
