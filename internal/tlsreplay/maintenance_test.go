package tlsreplay

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/replay"
)

func maintenanceReadMQTT(conn net.Conn) ([]byte, error) {
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

func maintenanceScript(t *testing.T, idle time.Duration) []AppMessage {
	t.Helper()
	a := adapters.MQTT{}
	connect := []byte{0x10, 15, 0, 4, 'M', 'Q', 'T', 'T', 4, 2, 0, 1, 0, 3, 't', 'e', 's'}
	request, err := a.Decode(replay.ClientToServer, connect)
	if err != nil {
		t.Fatal(err)
	}
	disconnect, err := a.Decode(replay.ClientToServer, []byte{0xe0, 0})
	if err != nil {
		t.Fatal(err)
	}
	return []AppMessage{
		{Role: FromClient, Data: connect, Request: &request[0], HasCaptureTime: true},
		{Role: FromServer, Data: []byte{0x20, 2, 0, 0}, Peers: request, HasCaptureTime: true},
		{Role: FromClient, Data: []byte{0xe0, 0}, Request: &disconnect[0], CapturedAt: idle, HasCaptureTime: true},
	}
}

func TestTLSMQTTMaintenanceDuringCapturedIdle(t *testing.T) {
	t.Parallel()
	cert := selfSigned(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := maintenanceReadMQTT(conn); err != nil {
			done <- err
			return
		}
		if _, err := conn.Write([]byte{0x20, 2, 0, 0, 0x32, 6, 0, 1, 't', 0, 7, 'x'}); err != nil {
			done <- err
			return
		}
		pings, acknowledged := 0, false
		for {
			_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
			frame, err := maintenanceReadMQTT(conn)
			if err != nil {
				done <- fmt.Errorf("TLS broker keepalive expired: %w", err)
				return
			}
			switch frame[0] >> 4 {
			case 4:
				acknowledged = bytes.Equal(frame, []byte{0x40, 2, 0, 7})
			case 12:
				pings++
				_, err = conn.Write([]byte{0xd0, 0})
			case 14:
				if pings < 2 || !acknowledged {
					err = fmt.Errorf("TLS maintenance missing: pings=%d publishACK=%v", pings, acknowledged)
				}
				done <- err
				return
			default:
				err = fmt.Errorf("unexpected frame %x", frame)
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()
	result, err := ReTerminate(ReTermConfig{
		Address: listener.Addr().String(), TLSConfig: &tls.Config{RootCAs: roots, ServerName: "localhost"},
		Script: maintenanceScript(t, 2500*time.Millisecond), Adapter: adapters.MQTT{}, VerifyMode: replay.VerifyStrict,
		Timeout: 5 * time.Second, ExchangeTimeout: 300 * time.Millisecond, Profile: replay.ProfileTiming,
	})
	if err != nil {
		t.Fatalf("TLS idle replay: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !result.HandshakeState.HandshakeComplete || result.Observed != 1 || result.Compared != 1 || result.Mismatches != 0 {
		t.Fatalf("TLS maintenance changed verification: %+v", result)
	}
}

func TestTLSIdleMaintenanceCancellation(t *testing.T) {
	t.Parallel()
	cert := selfSigned(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := maintenanceReadMQTT(conn); err != nil {
			done <- err
			return
		}
		if _, err := conn.Write([]byte{0x20, 2, 0, 0}); err != nil {
			done <- err
			return
		}
		_, err = maintenanceReadMQTT(conn)
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = ReTerminateContext(ctx, ReTermConfig{
		Address: listener.Addr().String(), TLSConfig: &tls.Config{RootCAs: roots, ServerName: "localhost"},
		Script: maintenanceScript(t, 10*time.Second), Adapter: adapters.MQTT{}, Profile: replay.ProfileTiming,
		Timeout: 5 * time.Second, ExchangeTimeout: time.Second,
	})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatalf("TLS idle cancellation was not prompt: %v", err)
	}
	if err := <-done; !errors.Is(err, io.EOF) {
		t.Fatalf("TLS connection survived cancellation: %v", err)
	}
}

func TestTLSExchangeTimeoutIsIndependentOfSessionBudget(t *testing.T) {
	t.Parallel()
	cert := selfSigned(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.Copy(io.Discard, conn)
	}()
	started := time.Now()
	_, err = ReTerminate(ReTermConfig{
		Address: listener.Addr().String(), TLSConfig: &tls.Config{RootCAs: roots, ServerName: "localhost"},
		Script:  []AppMessage{{Role: FromClient, Data: []byte("request")}, {Role: FromServer, Data: []byte("response")}},
		Timeout: 5 * time.Second, ExchangeTimeout: 100 * time.Millisecond,
	})
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("per-exchange budget was ignored: %v", err)
	}
	<-done
}
