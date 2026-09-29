package replaylab

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

func init() { Register(Case{Name: "ssh", Setup: setupSSH}) }

func setupSSH(ctx context.Context, dir string) (_ *Fixture, retErr error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	host, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		return nil, err
	}
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	client, err := ssh.NewSignerFromKey(clientPrivate)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(clientPrivate, "ephemeral software lab identity")
	if err != nil {
		return nil, err
	}
	keyPath, hostPath := filepath.Join(dir, "client.key"), filepath.Join(dir, "server.pub")
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
		return nil, err
	}
	if err = os.WriteFile(hostPath, ssh.MarshalAuthorizedKey(host.PublicKey()), 0600); err != nil {
		return nil, err
	}
	config := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() != "lab" || !bytes.Equal(key.Marshal(), client.PublicKey().Marshal()) {
			return nil, ssh.ErrNoAuth
		}
		return nil, nil
	}}
	config.AddHostKey(host)
	server, err := ServeTCP(ctx, func(conn net.Conn, stats *Stats) error {
		secured, channels, requests, err := ssh.NewServerConn(conn, config)
		if err != nil {
			return err
		}
		defer secured.Close()
		requestsDone := make(chan struct{})
		go func() { ssh.DiscardRequests(requests); close(requestsDone) }()
		defer func() { _ = secured.Close(); <-requestsDone }()
		for offer := range channels {
			if offer.ChannelType() != "session" {
				_ = offer.Reject(ssh.UnknownChannelType, "only lab sessions allowed")
				return fmt.Errorf("unexpected SSH channel type")
			}
			channel, requests, err := offer.Accept()
			if err != nil {
				return err
			}
			if err = serveSSHCommand(channel, requests, stats); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			_ = server.Close()
		}
	}()
	capture := filepath.Join(dir, "fixture.pcap")
	if err = WriteTCPCapture(capture, 22, []Exchange{{Client: []byte("SSH-2.0-livewire_capture\r\n"), Server: []byte("SSH-2.0-livewire_peer\r\n")}}); err != nil {
		return nil, err
	}
	return &Fixture{Capture: capture, Args: []string{"-t", server.Address(), "-user", "lab", "-key", keyPath, "-host-key", hostPath, "-cmd", "status", "-expect", "ready", "-cmd", "version", "-expect", "lab1"}, Snapshot: server.Stats.Snapshot, Events: server.Stats.Events, Close: server.Close}, nil
}

func serveSSHCommand(channel ssh.Channel, requests <-chan *ssh.Request, stats *Stats) error {
	defer channel.Close()
	request, ok := <-requests
	if ok {
		var command struct{ Command string }
		if request.Type != "exec" || ssh.Unmarshal(request.Payload, &command) != nil {
			_ = request.Reply(false, nil)
			return fmt.Errorf("invalid SSH exec request")
		}
		response := ""
		switch command.Command {
		case "status":
			response = "ready"
		case "version":
			response = "lab1"
		default:
			return fmt.Errorf("SSH command was not the selected synthetic script")
		}
		stats.Request()
		if request.WantReply {
			if err := request.Reply(true, nil); err != nil {
				return err
			}
		}
		if _, err := channel.Write([]byte(response)); err != nil {
			return err
		}
		if _, err := channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0}); err != nil {
			return err
		}
		stats.Response()
		return nil
	}
	return fmt.Errorf("SSH channel closed without a command")
}
