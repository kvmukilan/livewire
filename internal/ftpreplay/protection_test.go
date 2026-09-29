package ftpreplay

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/replay"
)

func TestLiveProtectionRefusalStopsBeforeSensitiveTraffic(t *testing.T) {
	t.Run("data", func(t *testing.T) {
		testLiveProtectionRefusal(t, "PROT P", "200 protected", "STOR protected.bin", "refusing an unprotected", false)
	})
	t.Run("control", func(t *testing.T) {
		testLiveProtectionRefusal(t, "AUTH TLS", "234 proceed", "PASS synthetic-secret", "refusing an unencrypted", true)
	})
}

func testLiveProtectionRefusal(t *testing.T, requested, capturedReply, nextCommand, refusal string, explicit bool) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err = conn.Write([]byte("220 ready\r\n")); err != nil {
			done <- err
			return
		}
		reader := bufio.NewReader(conn)
		command, err := reader.ReadString('\n')
		if err != nil || command != requested+"\r\n" {
			done <- fmt.Errorf("unexpected protection request %q: %v", command, err)
			return
		}
		if _, err = conn.Write([]byte("534 protection denied\r\n")); err != nil {
			done <- err
			return
		}
		command, err = reader.ReadString('\n')
		if err != io.EOF || command != "" {
			done <- fmt.Errorf("replay continued after protection rejection: %q %v", command, err)
			return
		}
		done <- nil
	}()
	var turns []Turn
	for _, item := range []struct {
		direction replay.Direction
		raw       string
	}{
		{replay.ServerToClient, "220 ready\r\n"},
		{replay.ClientToServer, requested + "\r\n"},
		{replay.ServerToClient, capturedReply + "\r\n"},
		{replay.ClientToServer, nextCommand + "\r\n"},
		{replay.ServerToClient, "150 transfer\r\n"},
	} {
		messages, err := (adapters.FTP{}).Decode(item.direction, []byte(item.raw))
		if err != nil {
			t.Fatal(err)
		}
		turns = append(turns, Turn{Direction: item.direction, Message: messages[0]})
	}
	result, err := RunContext(context.Background(), Config{Control: &replay.Session{}, Address: listener.Addr().String(), Script: Script{Turns: turns, Explicit: explicit}, Timeout: time.Second, Verify: replay.VerifyOff})
	if err == nil || !strings.Contains(err.Error(), refusal) || result.Completed || result.Commands != 1 {
		t.Fatalf("protection rejection did not stop replay: %+v %v", result, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
