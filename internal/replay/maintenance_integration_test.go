package replay_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/replay"
)

var mqttConnect = []byte{0x10, 15, 0, 4, 'M', 'Q', 'T', 'T', 4, 2, 0, 1, 0, 3, 't', 'e', 's'}
var mqttConnack = []byte{0x20, 2, 0, 0}
var mqttPublish = []byte{0x32, 6, 0, 1, 't', 0, 1, 'x'}
var mqttPuback = []byte{0x40, 2, 0, 1}

func mqttRead(conn net.Conn) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[1] > 127 {
		return nil, fmt.Errorf("test broker received oversized frame")
	}
	body := make([]byte, int(header[1]))
	_, err := io.ReadFull(conn, body)
	return append(header, body...), err
}

func mqttTestSession(events ...replay.Event) *replay.Session {
	return &replay.Session{ID: "mqtt-maintenance", Transport: replay.TransportTCP, Events: events}
}

func TestMQTTIdleMaintenancePreservesCapturedResponses(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		_ = server.SetDeadline(time.Now().Add(6 * time.Second))
		connect, err := mqttRead(server)
		if err != nil || !bytes.Equal(connect, mqttConnect) {
			done <- fmt.Errorf("CONNECT: %x %v", connect, err)
			return
		}
		// A QoS1 publish appears while replay is waiting for its next captured
		// request. It must be acknowledged, without replacing a captured reply.
		if _, err := server.Write(append(append([]byte{}, mqttConnack...), []byte{0x32, 6, 0, 1, 't', 0, 7, 'y'}...)); err != nil {
			done <- err
			return
		}
		pings, extraACK := 0, false
		for {
			_ = server.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
			frame, err := mqttRead(server)
			if err != nil {
				done <- fmt.Errorf("broker keepalive expired: %w", err)
				return
			}
			switch frame[0] >> 4 {
			case 4:
				extraACK = bytes.Equal(frame, []byte{0x40, 2, 0, 7})
			case 12:
				pings++
				_, err = server.Write([]byte{0xd0, 0})
			case 3:
				if !bytes.Equal(frame, mqttPublish) {
					err = fmt.Errorf("captured publish changed: %x", frame)
				} else {
					_, err = server.Write(mqttPuback)
				}
			case 14:
				if pings < 3 || !extraACK {
					err = fmt.Errorf("maintenance missing: pings=%d extraACK=%v", pings, extraACK)
				}
				done <- err
				return
			default:
				err = fmt.Errorf("unexpected frame: %x", frame)
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()
	session := mqttTestSession(
		replay.Event{Direction: replay.ClientToServer, Payload: mqttConnect},
		replay.Event{Direction: replay.ServerToClient, Payload: mqttConnack},
		replay.Event{Direction: replay.ClientToServer, At: 2500 * time.Millisecond, Payload: []byte{0xc0, 0}},
		replay.Event{Direction: replay.ServerToClient, At: 2510 * time.Millisecond, Payload: []byte{0xd0, 0}},
		replay.Event{Direction: replay.ClientToServer, At: 2520 * time.Millisecond, Payload: mqttPublish},
		replay.Event{Direction: replay.ServerToClient, At: 2530 * time.Millisecond, Payload: mqttPuback},
		replay.Event{Direction: replay.ClientToServer, At: 2540 * time.Millisecond, Payload: []byte{0xe0, 0}},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	result, err := replay.RunTCPSemanticContext(ctx, replay.TCPSemanticConfig{
		Session: session, Adapter: adapters.MQTT{}, Profile: replay.ProfileTiming, Verify: replay.VerifyStrict, Timeout: time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) { return client, nil },
	})
	if err != nil {
		t.Fatalf("idle replay failed: %+v: %v", result, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !result.Completed || !result.Matched || result.Sent != 4 || result.Received != 3 || result.Compared != 3 {
		t.Fatalf("maintenance traffic changed captured correlation: %+v", result)
	}
}

func TestMQTTMaintenanceDuringResponseWait(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		_ = server.SetDeadline(time.Now().Add(6 * time.Second))
		if _, err := mqttRead(server); err != nil {
			done <- err
			return
		}
		if _, err := server.Write(mqttConnack); err != nil {
			done <- err
			return
		}
		if _, err := mqttRead(server); err != nil {
			done <- err
			return
		}
		for i := 0; i < 2; i++ {
			_ = server.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
			ping, err := mqttRead(server)
			if err != nil || !bytes.Equal(ping, []byte{0xc0, 0}) {
				done <- fmt.Errorf("waiting-response maintenance %x: %v", ping, err)
				return
			}
			if _, err := server.Write([]byte{0xd0, 0}); err != nil {
				done <- err
				return
			}
		}
		_, err := server.Write(mqttPuback)
		done <- err
	}()
	session := mqttTestSession(
		replay.Event{Direction: replay.ClientToServer, Payload: mqttConnect},
		replay.Event{Direction: replay.ServerToClient, Payload: mqttConnack},
		replay.Event{Direction: replay.ClientToServer, Payload: mqttPublish},
		replay.Event{Direction: replay.ServerToClient, Payload: mqttPuback},
	)
	result, err := replay.RunTCPSemanticContext(context.Background(), replay.TCPSemanticConfig{
		Session: session, Adapter: adapters.MQTT{}, Verify: replay.VerifyStrict, Timeout: 4 * time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) { return client, nil },
	})
	if err != nil || !result.Completed || !result.Matched || result.Received != 2 {
		t.Fatalf("response maintenance lost correlation: %+v %v", result, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestMQTTCancellationDuringIdleMaintenance(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		_ = server.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := mqttRead(server); err != nil {
			done <- err
			return
		}
		if _, err := server.Write(mqttConnack); err != nil {
			done <- err
			return
		}
		_, err := mqttRead(server)
		done <- err
	}()
	session := mqttTestSession(
		replay.Event{Direction: replay.ClientToServer, Payload: mqttConnect},
		replay.Event{Direction: replay.ServerToClient, Payload: mqttConnack},
		replay.Event{Direction: replay.ClientToServer, At: 10 * time.Second, Payload: []byte{0xe0, 0}},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := replay.RunTCPSemanticContext(ctx, replay.TCPSemanticConfig{
		Session: session, Adapter: adapters.MQTT{}, Profile: replay.ProfileTiming, Timeout: time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) { return client, nil },
	})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 700*time.Millisecond {
		t.Fatalf("idle cancellation was not prompt: %v", err)
	}
	if err := <-done; !errors.Is(err, io.EOF) {
		t.Fatalf("connection survived cancellation: %v", err)
	}
}

func TestScenarioPipelinedImplicitBindingRejectedBeforeDial(t *testing.T) {
	scenario, err := replay.ParseScenario([]byte(`{"version":1,"captureDigest":"x","steps":[{"id":"login","session":"tcp-0","request":1,"extract":[{"name":"token","header":"X-Token"}]},{"id":"use","session":"tcp-0","request":2,"set":{"http.header.Authorization":"${token}"}}]}`), "x")
	if err != nil {
		t.Fatal(err)
	}
	requests := []byte("GET /login HTTP/1.1\r\nHost: localhost\r\n\r\nGET /use HTTP/1.1\r\nHost: localhost\r\n\r\n")
	responses := []byte("HTTP/1.1 200 OK\r\nX-Token: fresh\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	session := &replay.Session{ID: "tcp-0", Transport: replay.TransportTCP, Events: []replay.Event{{Direction: replay.ClientToServer, Payload: requests}, {Direction: replay.ServerToClient, Payload: responses}}}
	dialed := false
	ctx := replay.WithExecution(context.Background(), replay.ExecutionConfig{Scenario: replay.NewScenarioRuntime(scenario)})
	_, err = replay.RunTCPSemanticContext(ctx, replay.TCPSemanticConfig{Session: session, Adapter: adapters.HTTP{}, Dial: func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("unexpected dial")
	}})
	if err == nil || !strings.Contains(err.Error(), "pipelined") || dialed {
		t.Fatalf("unsatisfiable binding reached target: dialed=%v err=%v", dialed, err)
	}
}
