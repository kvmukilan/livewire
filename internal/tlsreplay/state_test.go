package tlsreplay

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/replay"
)

func TestFreshTLSCookiesLearnedWithVerificationOnAndOff(t *testing.T) {
	for _, mode := range []replay.VerifyMode{replay.VerifyOff, replay.VerifyLenient} {
		t.Run(string(mode), func(t *testing.T) {
			cert := selfSigned(t)
			roots := x509.NewCertPool()
			roots.AddCert(cert.Leaf)
			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			reply := []byte("HTTP/1.1 200 OK\r\nSet-Cookie: session=old; Secure; Path=/\r\nContent-Length: 2\r\n\r\nok")
			go func() {
				c, e := listener.Accept()
				if e != nil {
					done <- e
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				r := bufio.NewReader(c)
				for i := 0; i < 2; i++ {
					q, e := http.ReadRequest(r)
					if e != nil {
						done <- e
						return
					}
					q.Body.Close()
					if i == 1 && q.Header.Get("Cookie") != "session=fresh" {
						done <- fmt.Errorf("stale cookie: %s", q.Header.Get("Cookie"))
						return
					}
					if _, e = c.Write(bytes.ReplaceAll(reply, []byte("old"), []byte("fresh"))); e != nil {
						done <- e
						return
					}
				}
				done <- nil
			}()
			a := adapters.HTTP{}
			var script []AppMessage
			for i := 0; i < 2; i++ {
				raw := []byte(fmt.Sprintf("GET /%d HTTP/1.1\r\nHost: localhost\r\nCookie: session=old\r\n\r\n", i))
				msgs, e := a.Decode(replay.ClientToServer, raw)
				if e != nil {
					t.Fatal(e)
				}
				script = append(script, AppMessage{Role: FromClient, Data: raw, Request: &msgs[0]}, AppMessage{Role: FromServer, Data: reply, Peers: msgs})
			}
			result, err := ReTerminate(ReTermConfig{Address: listener.Addr().String(), TLSConfig: &tls.Config{RootCAs: roots, ServerName: "localhost"}, Script: script, Adapter: a, VerifyMode: mode, Timeout: 3 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
			if !result.HandshakeState.HandshakeComplete || result.Observed != 2 || result.Mismatches != 0 {
				t.Fatalf("%+v", result)
			}
			if mode == replay.VerifyOff && result.Compared != 0 {
				t.Fatal("verification-off compared responses")
			}
		})
	}
}
