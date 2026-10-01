package backend

import (
	"encoding/binary"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestAFPacketPromiscOwnership(t *testing.T) {
	if os.Getenv("LIVEWIRE_NATIVE_CAPTURE_TEST") != "1" {
		t.Skip("requires approved isolated raw loopback capture")
	}
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	// SIOCGIFFLAGS intentionally hides other sockets' memberships. Netlink
	// exposes the reference count, including concurrently owned captures.
	count := func() uint32 {
		rib, err := syscall.NetlinkRIB(syscall.RTM_GETLINK, syscall.AF_UNSPEC)
		if err != nil {
			t.Fatal(err)
		}
		messages, err := syscall.ParseNetlinkMessage(rib)
		if err != nil {
			t.Fatal(err)
		}
		for _, message := range messages {
			if message.Header.Type != syscall.RTM_NEWLINK || len(message.Data) < 16 || int(binary.NativeEndian.Uint32(message.Data[4:8])) != iface.Index {
				continue
			}
			attrs, err := syscall.ParseNetlinkRouteAttr(&message)
			if err != nil {
				t.Fatal(err)
			}
			for _, attr := range attrs {
				if attr.Attr.Type == unix.IFLA_PROMISCUITY && len(attr.Value) == 4 {
					return binary.NativeEndian.Uint32(attr.Value)
				}
			}
		}
		t.Fatal("missing interface promiscuity counter")
		return 0
	}
	before := count()
	first, err := OpenAFPacket("lo", true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenAFPacket("lo", true)
	if err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	if count() != before+2 {
		t.Error("promiscuous membership not active")
	}
	if err := first.Close(); err != nil {
		t.Error(err)
	}
	if count() != before+1 {
		t.Error("closing one socket removed another's membership")
	}
	if err := second.Close(); err != nil {
		t.Error(err)
	}
	if count() != before {
		t.Fatal("promiscuous mode leaked after last socket close")
	}
}
