//go:build linux

package backend

import (
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"

	"github.com/kvmukilan/livewire/internal/wire"
)

// ethPAll is ETH_P_ALL: capture/inject every ethertype at layer 2.
const ethPAll = 0x0003

// htons converts a uint16 to network byte order for the AF_PACKET protocol field.
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// AFPacket is a pure-Go Linux backend that sends and receives full Ethernet
// frames over an AF_PACKET/SOCK_RAW socket. Raw L2 access lets us craft the
// client's packets byte-for-byte and receive the server's replies. Sending
// crafted TCP still needs the host kernel's RST suppressed (see
// internal/hoststack), or the kernel tears the flow down first.
type AFPacket struct {
	fd    int
	ifi   *net.Interface
	sll   syscall.SockaddrLinklayer
	now   func() time.Time
	promc bool

	// Filter, if set, gates received frames: Recv only returns ones it accepts.
	// Drops traffic outside the replayed 4-tuple.
	Filter func(frame []byte) bool
}

// OpenAFPacket binds a raw L2 socket to the named interface. If promisc is set,
// the interface is put into promiscuous mode for the socket's lifetime.
func OpenAFPacket(ifname string, promisc bool) (*AFPacket, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("afpacket: interface %q: %w", ifname, err)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return nil, fmt.Errorf("afpacket: socket: %w", err)
	}
	sll := syscall.SockaddrLinklayer{
		Protocol: htons(ethPAll),
		Ifindex:  ifi.Index,
	}
	if err := syscall.Bind(fd, &sll); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("afpacket: bind %s: %w", ifname, err)
	}
	b := &AFPacket{fd: fd, ifi: ifi, sll: sll, now: time.Now, promc: promisc}
	if promisc {
		if err := setPromisc(ifname, true); err != nil {
			syscall.Close(fd)
			return nil, err
		}
	}
	return b, nil
}

// iffPromisc is IFF_PROMISC from <linux/if.h>.
const iffPromisc = 0x100

// setPromisc toggles IFF_PROMISC via SIOCGIFFLAGS/SIOCSIFFLAGS. Needed because
// server replies are unicast to the spoofed client MAC, which the interface
// doesn't own.
func setPromisc(ifname string, on bool) error {
	ctl, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("afpacket: promisc ctl socket: %w", err)
	}
	defer syscall.Close(ctl)

	// struct ifreq: 16-byte name followed by a union; the flags are a c_short.
	var ifr [40]byte
	copy(ifr[:15], ifname)
	if err := ioctl(ctl, syscall.SIOCGIFFLAGS, unsafe.Pointer(&ifr[0])); err != nil {
		return fmt.Errorf("afpacket: SIOCGIFFLAGS: %w", err)
	}
	flags := *(*uint16)(unsafe.Pointer(&ifr[syscall.IFNAMSIZ]))
	if on {
		flags |= iffPromisc
	} else {
		flags &^= iffPromisc
	}
	*(*uint16)(unsafe.Pointer(&ifr[syscall.IFNAMSIZ])) = flags
	if err := ioctl(ctl, syscall.SIOCSIFFLAGS, unsafe.Pointer(&ifr[0])); err != nil {
		return fmt.Errorf("afpacket: SIOCSIFFLAGS: %w", err)
	}
	return nil
}

func ioctl(fd int, req uint, arg unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

// Send transmits one Ethernet frame on the bound interface.
func (b *AFPacket) Send(frame []byte) error {
	if err := syscall.Sendto(b.fd, frame, 0, &b.sll); err != nil {
		return fmt.Errorf("afpacket: sendto: %w", err)
	}
	return nil
}

// Recv reads the next frame passing the filter, waiting up to timeout. A timeout
// is reported as ok=false with err=nil.
func (b *AFPacket) Recv(buf []byte, timeout time.Duration) (int, bool, error) {
	deadline := b.now().Add(timeout)
	for {
		remaining := timeout
		if timeout > 0 {
			remaining = deadline.Sub(b.now())
			if remaining <= 0 {
				return 0, false, nil
			}
		}
		if err := b.setRecvTimeout(remaining); err != nil {
			return 0, false, err
		}
		n, _, err := syscall.Recvfrom(b.fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
				if timeout <= 0 {
					return 0, false, nil
				}
				continue // timed out or interrupted; re-check the deadline
			}
			return 0, false, fmt.Errorf("afpacket: recvfrom: %w", err)
		}
		if b.Filter != nil && !b.Filter(buf[:n]) {
			continue // not our flow; keep waiting within the deadline
		}
		return n, true, nil
	}
}

// setRecvTimeout arms SO_RCVTIMEO so Recvfrom returns EAGAIN after d. A
// non-positive d clears the timeout (blocking recv).
func (b *AFPacket) setRecvTimeout(d time.Duration) error {
	var tv syscall.Timeval
	if d > 0 {
		tv = syscall.NsecToTimeval(d.Nanoseconds())
	}
	if err := syscall.SetsockoptTimeval(b.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("afpacket: set SO_RCVTIMEO: %w", err)
	}
	return nil
}

// Now returns wall-clock time.
func (b *AFPacket) Now() time.Time { return b.now() }

// LinkType reports Ethernet — AF_PACKET SOCK_RAW delivers full L2 frames.
func (b *AFPacket) LinkType() wire.LinkType { return wire.LinkEthernet }

// Caps reports raw L2 send/receive suitable for stateful replay.
func (b *AFPacket) Caps() Capabilities { return Layer2 | CanReceive | StatefulSafe }

// Close releases the socket (promiscuous membership is dropped with it).
func (b *AFPacket) Close() error { return syscall.Close(b.fd) }
