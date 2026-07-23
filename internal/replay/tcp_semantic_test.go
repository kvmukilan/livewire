package replay

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
)

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
