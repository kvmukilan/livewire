package dissect

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// captureClientHello grabs the raw first flight crypto/tls puts on the wire when
// dialing a loopback listener, so the detector runs against real bytes.
func captureClientHello(t *testing.T, sni string, alpn []string) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		got <- append([]byte(nil), buf[:n]...)
	}()

	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: sni, NextProtos: alpn}
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tconn := tls.Client(conn, cfg)
	_ = tconn.SetDeadline(time.Now().Add(time.Second))
	go tconn.Handshake() // will fail on the dummy listener; we only need the ClientHello

	select {
	case b := <-got:
		if b == nil {
			t.Fatal("no ClientHello captured")
		}
		return b
	case <-time.After(3 * time.Second):
		t.Fatal("timed out capturing ClientHello")
		return nil
	}
}

func TestDetectTLSClientHello(t *testing.T) {
	hello := captureClientHello(t, "device.plant.local", []string{"h2", "http/1.1"})
	info := DetectTLS(hello)
	if !info.IsTLS || !info.IsClientHi {
		t.Fatalf("expected TLS ClientHello, got %+v", info)
	}
	if info.SNI != "device.plant.local" {
		t.Fatalf("SNI = %q, want device.plant.local", info.SNI)
	}
	foundH2 := false
	for _, a := range info.ALPN {
		if a == "h2" {
			foundH2 = true
		}
	}
	if !foundH2 {
		t.Fatalf("ALPN = %v, expected to contain h2", info.ALPN)
	}
}

func TestDetectTLSNegative(t *testing.T) {
	// Cleartext Modbus must not be misdetected as TLS.
	modbus := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01}
	if DetectTLS(modbus).IsTLS {
		t.Fatal("Modbus payload misdetected as TLS")
	}
	if DetectTLS(nil).IsTLS {
		t.Fatal("empty payload detected as TLS")
	}
}
