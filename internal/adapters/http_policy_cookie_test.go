package adapters

import (
	"strings"
	"testing"

	"github.com/kvmukilan/livewire/internal/replay"
)

func preparedHTTPRequest(t *testing.T, a HTTP, state *replay.RuntimeState, raw string) string {
	t.Helper()
	messages, err := a.Decode(replay.ClientToServer, []byte(raw))
	if err != nil || len(messages) != 1 {
		t.Fatalf("decode %q: %v", raw, err)
	}
	out, err := a.Prepare(replay.ClientToServer, messages[0], state)
	if err != nil {
		t.Fatal(err)
	}
	live, err := a.Decode(replay.ClientToServer, out)
	if err != nil || len(live) != 1 {
		t.Fatalf("decode prepared request: %v", err)
	}
	if err := replay.Observe(a, replay.ClientToServer, messages[0], live[0], state); err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestHTTPLiveCookiesMergeIntoCapturedCookies(t *testing.T) {
	a := HTTP{}
	state := replay.NewRuntimeState(nil)
	first := "GET /a HTTP/1.1\r\nHost: dev\r\nCookie: session=abc; csrftoken=x\r\n\r\n"
	if got := preparedHTTPRequest(t, a, state, first); got != first {
		t.Fatalf("request before any live cookie changed:\n%s", got)
	}
	requests, _ := a.Decode(replay.ClientToServer, []byte(first))
	responses, err := a.DecodeExchange(replay.ServerToClient, []byte("HTTP/1.1 200 OK\r\nSet-Cookie: lastvisit=LIVE; Path=/\r\nSet-Cookie: extra=1; Path=/\r\nContent-Length: 0\r\n\r\n"), requests)
	if err != nil || len(responses) != 1 {
		t.Fatalf("decode response: %v", err)
	}
	if err := replay.Observe(a, replay.ServerToClient, responses[0], responses[0], state); err != nil {
		t.Fatal(err)
	}
	got := preparedHTTPRequest(t, a, state, "GET /b HTTP/1.1\r\nHost: dev\r\nCookie: session=abc; csrftoken=x; lastvisit=CAPTURED\r\n\r\n")
	if !strings.Contains(got, "\r\nCookie: session=abc; csrftoken=x; lastvisit=LIVE; extra=1\r\n") {
		t.Fatalf("captured cookies were not merged with live ones:\n%s", got)
	}
	// Another origin has no live cookies: its header must be left as captured,
	// and a request captured without cookies must not gain an empty header.
	other := "GET /c HTTP/1.1\r\nHost: other\r\nCookie: keep=1\r\n\r\n"
	if got := preparedHTTPRequest(t, a, state, other); got != other {
		t.Fatalf("request to an origin without live cookies changed:\n%s", got)
	}
	bare := "GET /d HTTP/1.1\r\nHost: other\r\n\r\n"
	if got := preparedHTTPRequest(t, a, state, bare); got != bare {
		t.Fatalf("request without cookies gained a header:\n%s", got)
	}
}

func TestHTTPExpectContinueRequestIsRejectedBeforeReplay(t *testing.T) {
	_, err := HTTP{}.Decode(replay.ClientToServer, []byte("PUT /fw HTTP/1.1\r\nHost: dev\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nok"))
	if err == nil || !strings.Contains(err.Error(), "Expect: 100-continue") || !strings.Contains(err.Error(), "PUT /fw") {
		t.Fatalf("error = %v", err)
	}
}
