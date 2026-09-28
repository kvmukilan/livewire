//go:build linux

package backend

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// resolveNeighborExchange retries lost discovery frames within one fixed
// deadline. Unrelated frames and interrupted syscalls cannot reset that budget.
func resolveNeighborExchange(timeout time.Duration, send func() error, receive func(time.Duration) ([]byte, error), parse func([]byte) (net.HardwareAddr, bool), now func() time.Time) (net.HardwareAddr, error) {
	deadline := now().Add(timeout)
	var nextSend time.Time
	for now().Before(deadline) {
		if !now().Before(nextSend) {
			if err := send(); err != nil && !errors.Is(err, syscall.EINTR) {
				return nil, fmt.Errorf("neighbor request: %w", err)
			}
			nextSend = now().Add(250 * time.Millisecond)
		}
		wait := min(deadline.Sub(now()), nextSend.Sub(now()))
		if wait <= 0 {
			continue
		}
		frame, err := receive(wait)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
				continue
			}
			return nil, fmt.Errorf("neighbor receive: %w", err)
		}
		if mac, ok := parse(frame); ok {
			return mac, nil
		}
	}
	return nil, fmt.Errorf("neighbor discovery timed out after %s", timeout)
}

func resolveNeighborSocket(fd int, address *syscall.SockaddrLinklayer, frame []byte, timeout time.Duration, parse func([]byte) (net.HardwareAddr, bool)) (net.HardwareAddr, error) {
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: address.Protocol, Ifindex: address.Ifindex}); err != nil {
		return nil, fmt.Errorf("bind neighbor socket: %w", err)
	}
	buf := make([]byte, 256)
	return resolveNeighborExchange(timeout, func() error { return syscall.Sendto(fd, frame, 0, address) }, func(wait time.Duration) ([]byte, error) {
		tv := syscall.NsecToTimeval(max(wait, time.Microsecond).Nanoseconds())
		if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
			return nil, err
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}, parse, time.Now)
}
