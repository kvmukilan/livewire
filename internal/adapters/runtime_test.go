package adapters

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/replay"
)

func TestRuntimeLearnsMQTTIDWithVerificationOff(t *testing.T) {
	for _, mode := range []replay.VerifyMode{replay.VerifyOff, replay.VerifyStrict} {
		t.Run(string(mode), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			captured := mqttQoS1Publish("alarms", 7, "trip")
			live := mqttQoS1Publish("alarms", 42, "trip")
			done := make(chan error, 1)
			go func() {
				defer server.Close()
				server.SetDeadline(time.Now().Add(time.Second))
				if _, e := server.Write(live); e != nil {
					done <- e
					return
				}
				b := make([]byte, 4)
				_, e := io.ReadFull(server, b)
				if e == nil && !bytes.Equal(b, []byte{0x40, 2, 0, 42}) {
					e = fmt.Errorf("wrong acknowledgement %x", b)
				}
				done <- e
			}()
			s := &replay.Session{ID: "mqtt", Transport: replay.TransportTCP, Events: []replay.Event{{Direction: replay.ServerToClient, Payload: captured}, {Direction: replay.ClientToServer, Payload: []byte{0x40, 2, 0, 7}}}}
			r, e := replay.RunTCPSemanticContext(context.Background(), replay.TCPSemanticConfig{Session: s, Adapter: MQTT{}, Verify: mode, Timeout: time.Second, Dial: func(context.Context, string, string) (net.Conn, error) { return client, nil }})
			if e != nil || !r.Completed {
				t.Fatalf("result=%+v err=%v", r, e)
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
			if mode == replay.VerifyOff && (r.Verified || r.Matched) {
				t.Fatal("verification off claimed a match")
			}
		})
	}
}

func TestHTTPCookiesLearnedAcrossLiveRequests(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	req := []byte("GET /login HTTP/1.1\r\nHost: device.test\r\n\r\n")
	reply := []byte("HTTP/1.1 200 OK\r\nSet-Cookie: session=captured; Path=/\r\nContent-Length: 2\r\n\r\nok")
	next := []byte("GET /data HTTP/1.1\r\nHost: device.test\r\nCookie: session=captured\r\n\r\n")
	final := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		server.SetDeadline(time.Now().Add(time.Second))
		r := bufio.NewReader(server)
		q, e := http.ReadRequest(r)
		if e != nil {
			done <- e
			return
		}
		q.Body.Close()
		_, e = server.Write(bytes.ReplaceAll(reply, []byte("captured"), []byte("fresh")))
		if e != nil {
			done <- e
			return
		}
		q, e = http.ReadRequest(r)
		if e == nil {
			q.Body.Close()
			if q.Header.Get("Cookie") != "session=fresh" {
				e = fmt.Errorf("stale cookie %q", q.Header.Get("Cookie"))
			}
		}
		if e == nil {
			_, e = server.Write(final)
		}
		done <- e
	}()
	s := &replay.Session{ID: "http", Transport: replay.TransportTCP, Events: []replay.Event{{Direction: replay.ClientToServer, Payload: req}, {Direction: replay.ServerToClient, Payload: reply}, {Direction: replay.ClientToServer, Payload: next}, {Direction: replay.ServerToClient, Payload: final}}}
	r, e := replay.RunTCPSemanticContext(context.Background(), replay.TCPSemanticConfig{Session: s, Adapter: HTTP{}, Verify: replay.VerifyLenient, Timeout: time.Second, Dial: func(context.Context, string, string) (net.Conn, error) { return client, nil }})
	if e != nil || !r.Matched {
		t.Fatalf("result=%+v err=%v", r, e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}

func TestReaderPreservesPartialFollowingFrame(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	expected, e := (HTTP{}).Decode(replay.ServerToClient, response)
	if e != nil {
		t.Fatal(e)
	}
	go func() {
		defer s.Close()
		s.Write(append(append([]byte{}, response...), response[:17]...))
		s.Write(response[17:])
	}()
	var reader replay.MessageReader
	for i := 0; i < 2; i++ {
		msgs, e := reader.Read(context.Background(), c, HTTP{}, replay.ServerToClient, expected, nil, time.Second)
		if e != nil || len(msgs) != 1 || !bytes.Equal(msgs[0].Raw, response) {
			t.Fatalf("read %d: %v %v", i, msgs, e)
		}
	}
}

func TestHTTPBodyDifferenceIsStructuralInLenientMode(t *testing.T) {
	a := HTTP{}
	w, _ := a.Decode(replay.ServerToClient, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	g, _ := a.Decode(replay.ServerToClient, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nno"))
	d := a.Compare(w[0], g[0], replay.VerifyLenient)
	if len(d) != 1 || d[0].Field != "body" || !d[0].Structural {
		t.Fatalf("differences=%+v", d)
	}
}

func TestCorrelationDoesNotMutateMQTTState(t *testing.T) {
	a := MQTT{}
	w, _ := a.Decode(replay.ServerToClient, mqttQoS1Publish("a", 1, "x"))
	g, _ := a.Decode(replay.ServerToClient, mqttQoS1Publish("a", 2, "x"))
	state := replay.NewRuntimeState(nil)
	a.Correlate(w[0], g[0], state)
	if len(state.Learned) != 0 {
		t.Fatal("correlation mutated state")
	}
}

func TestScenarioExtractsFreshTokenAndExplicitJSONPolicy(t *testing.T) {
	s, err := replay.ParseScenario([]byte(`{"version":1,"captureDigest":"x","steps":[{"id":"login","session":"tcp-0","request":1,"extract":[{"name":"token","jsonPointer":"/token"}]},{"id":"data","session":"tcp-0","request":2,"dependsOn":["login"],"set":{"http.header.Authorization":"Bearer ${token}"},"compare":{"normalizeJSON":true,"ignoreJSON":["/time"]}}]}`), "x")
	if err != nil {
		t.Fatal(err)
	}
	a := HTTP{}
	body := `{"token":"live-secret"}`
	messages, err := a.Decode(replay.ServerToClient, []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)))
	if err != nil {
		t.Fatal(err)
	}
	r := replay.NewScenarioRuntime(s)
	if err = r.After("tcp-0", 1, a, messages[0]); err != nil {
		t.Fatal(err)
	}
	state := replay.NewRuntimeState(nil)
	if err = r.Before(context.Background(), "tcp-0", 2, state); err != nil {
		t.Fatal(err)
	}
	if state.Variables["http.header.Authorization"] != "Bearer live-secret" {
		t.Fatal("fresh binding was not applied")
	}
	message := func(body string) replay.Message {
		m, e := a.Decode(replay.ServerToClient, []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)))
		if e != nil {
			t.Fatal(e)
		}
		return m[0]
	}
	w := message(`{"value":42,"time":1}`)
	g := message(`{"time":2,"value":42}`)
	if d := a.Compare(w, g, replay.VerifyLenient); len(d) == 0 {
		t.Fatal("undeclared normalization hid difference")
	}
	if d := r.Compare("tcp-0", 2, a, w, g, replay.VerifyLenient); len(d) != 0 {
		t.Fatalf("explicit policy failed: %+v", d)
	}
}

func TestModbusResponsesCanArriveOutOfOrder(t *testing.T) {
	a := Modbus{}
	one := []byte{0, 1, 0, 0, 0, 5, 1, 3, 2, 0, 42}
	two := append([]byte{}, one...)
	two[1] = 2
	w, _ := a.Decode(replay.ServerToClient, append(append([]byte{}, one...), two...))
	g, _ := a.Decode(replay.ServerToClient, append(append([]byte{}, two...), one...))
	aligned, err := replay.AlignResponses(a, w, g, replay.NewRuntimeState(nil))
	if err != nil {
		t.Fatal(err)
	}
	for i := range w {
		if !bytes.Equal(w[i].Raw, aligned[i].Raw) {
			t.Fatal("transaction response mispaired")
		}
	}
}
