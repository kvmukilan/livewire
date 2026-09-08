package secureexec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/replayintent"
	"golang.org/x/crypto/ssh"
)

func TestSSHPreparedReplayVerifiesPinnedPeerAndOutcome(t *testing.T) {
	for _, expects := range [][]string{{"ready"}, {"different"}, {""}, {"ready", ""}} {
		t.Run(strings.Join(expects, "/"), func(t *testing.T) {
			_, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.NewSignerFromKey(private)
			if err != nil {
				t.Fatal(err)
			}
			cfg := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
				if meta.User() == "operator" && string(password) == "secret" {
					return nil, nil
				}
				return nil, ssh.ErrNoAuth
			}}
			cfg.AddHostKey(signer)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_, channels, requests, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					ch, reqs, err := channel.Accept()
					if err != nil {
						return
					}
					for r := range reqs {
						if r.Type == "exec" {
							if r.WantReply {
								_ = r.Reply(true, nil)
							}
							_, _ = ch.Write([]byte("ready"))
							_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
							_ = ch.Close()
							break
						}
					}
				}
			}()
			inspection := &replayintent.Inspection{Readiness: replayintent.Readiness{Supported: true}, Route: replayintent.Route{Kind: replayintent.SSH, Session: &replay.Session{ID: "tcp-0"}}}
			commands := make([]string, len(expects))
			for i := range commands {
				commands[i] = "status"
			}
			prepared, err := Prepare(Config{Inspection: inspection, Target: ln.Addr().String(), User: "operator", Password: "secret", HostKey: ssh.MarshalAuthorizedKey(signer.PublicKey()), Commands: commands, Expects: expects, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			result, err := prepared.Run(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !result.Completed || !result.PeerIdentityChecked || result.Verified != (len(expects) == 1 && expects[0] != "") || result.Matched != (len(expects) == 1 && expects[0] == "ready") {
				t.Fatalf("outcome: %+v", result)
			}
			if len(result.Commands) != len(commands) || result.Commands[0].OutputBytes != 5 {
				t.Fatalf("missing digest evidence: %+v", result)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("SSH server did not stop")
			}
		})
	}
}

func TestSecurePreparationRejectsMissingRequirementsOffline(t *testing.T) {
	inspection := &replayintent.Inspection{Readiness: replayintent.Readiness{Supported: true}, Route: replayintent.Route{Kind: replayintent.SSH, Session: &replay.Session{}}}
	for _, cfg := range []Config{
		{}, {Inspection: inspection, Target: "bad", Timeout: time.Second},
		{Inspection: inspection, Target: "127.0.0.1:0", Timeout: time.Second},
		{Inspection: inspection, Target: "127.0.0.1:22", Timeout: -time.Second},
		{Inspection: inspection, Target: "127.0.0.1:22", Timeout: time.Second, User: "u", Password: "p", Commands: []string{"status"}},
	} {
		if _, err := Prepare(cfg); err == nil {
			t.Fatalf("accepted invalid preparation: %+v", cfg)
		}
	}
}
