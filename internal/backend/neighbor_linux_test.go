//go:build linux

package backend

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

func TestNeighborRetriesLostDiscoveryWithinFixedBudget(t *testing.T) {
	now := time.Unix(0, 0)
	sends, reads := 0, 0
	want := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	mac, err := resolveNeighborExchange(time.Second, func() error { sends++; return nil }, func(wait time.Duration) ([]byte, error) {
		reads++
		if reads == 1 {
			now = now.Add(wait)
			return nil, syscall.EAGAIN
		}
		if reads == 2 {
			now = now.Add(time.Millisecond)
			return nil, syscall.EINTR
		}
		return []byte{1}, nil
	}, func(frame []byte) (net.HardwareAddr, bool) { return want, len(frame) == 1 }, func() time.Time { return now })
	if err != nil || mac.String() != want.String() || sends != 2 {
		t.Fatalf("mac=%v sends=%d err=%v", mac, sends, err)
	}
	start := now
	sends = 0
	_, err = resolveNeighborExchange(time.Second, func() error { sends++; return nil }, func(wait time.Duration) ([]byte, error) { now = now.Add(wait); return []byte{0}, nil }, func([]byte) (net.HardwareAddr, bool) { return nil, false }, func() time.Time { return now })
	if err == nil || now.Sub(start) != time.Second || sends != 4 {
		t.Fatalf("unrelated traffic escaped budget: elapsed=%s sends=%d err=%v", now.Sub(start), sends, err)
	}
}

func TestNeighborPreservesFatalErrors(t *testing.T) {
	for _, sendFailure := range []bool{false, true} {
		_, err := resolveNeighborExchange(time.Second, func() error {
			if sendFailure {
				return syscall.ENODEV
			}
			return nil
		}, func(time.Duration) ([]byte, error) { return nil, syscall.ENODEV }, func([]byte) (net.HardwareAddr, bool) { return nil, false }, time.Now)
		if !errors.Is(err, syscall.ENODEV) {
			t.Fatalf("lost interface-removal error: %v", err)
		}
	}
}

func TestNeighborCacheUsesInterfaceAndCompleteEntry(t *testing.T) {
	table := []byte("IP address HW type Flags HW address Mask Device\n192.0.2.1 0x1 0x2 02:00:00:00:00:01 * other\n192.0.2.1 0x1 0x0 02:00:00:00:00:02 * lab\n192.0.2.1 0x1 0x2 02:00:00:00:00:03 * lab\n")
	mac, ok := parseNeighborTable(table, "lab", netip.MustParseAddr("192.0.2.1"))
	if !ok || mac.String() != "02:00:00:00:00:03" {
		t.Fatalf("used wrong interface or incomplete entry: %v %v", mac, ok)
	}
	if _, ok = parseNeighborTable(table, "missing", netip.MustParseAddr("192.0.2.1")); ok {
		t.Fatal("cache escaped selected interface")
	}
}
