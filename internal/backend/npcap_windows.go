//go:build windows

package backend

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"github.com/kvmukilan/livewire/internal/wire"
)

// The Windows live backend drives Npcap through its libpcap-compatible
// wpcap.dll, loaded lazily so the build stays cgo-free and needs no Npcap SDK —
// only the runtime DLL. Windows counterpart of the Linux AF_PACKET backend.

var (
	wpcap           = syscall.NewLazyDLL("wpcap.dll")
	procOpenLive    = wpcap.NewProc("pcap_open_live")
	procSendpacket  = wpcap.NewProc("pcap_sendpacket")
	procNextEx      = wpcap.NewProc("pcap_next_ex")
	procClose       = wpcap.NewProc("pcap_close")
	procFindAllDevs = wpcap.NewProc("pcap_findalldevs")
	procFreeAllDevs = wpcap.NewProc("pcap_freealldevs")
	procDatalink    = wpcap.NewProc("pcap_datalink")

	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procSetDllDirectory = kernel32.NewProc("SetDllDirectoryW")
)

// ensureNpcapSearchPath makes wpcap.dll loadable when Npcap was installed
// without "WinPcap API-compatible mode", which puts the DLLs in
// %WINDIR%\System32\Npcap instead of on the search path. Also lets wpcap.dll
// find its Packet.dll. No-op if the directory is absent.
func ensureNpcapSearchPath() {
	dir := filepath.Join(os.Getenv("WINDIR"), "System32", "Npcap")
	if _, err := os.Stat(dir); err != nil {
		return
	}
	if p, err := syscall.UTF16PtrFromString(dir); err == nil {
		procSetDllDirectory.Call(uintptr(unsafe.Pointer(p)))
	}
}

// Npcap is a PacketBackend over an Npcap/libpcap capture handle.
type Npcap struct {
	handle uintptr
	link   wire.LinkType

	// Filter drops frames outside the replayed flow, mirroring AF_PACKET.
	Filter func(frame []byte) bool
}

// OpenNpcap opens a live capture/injection handle on an Npcap device name (the
// "\Device\NPF_{GUID}" form that `livewire ifaces` prints), with a short read
// timeout so Recv can honour deadlines.
func OpenNpcap(device string, promisc bool) (*Npcap, error) {
	ensureNpcapSearchPath()
	if err := wpcap.Load(); err != nil {
		return nil, fmt.Errorf("backend: wpcap.dll not loadable — install Npcap (https://npcap.com) "+
			"in WinPcap API-compatible mode: %w", err)
	}
	dev, err := syscall.BytePtrFromString(device)
	if err != nil {
		return nil, err
	}
	var errbuf [256]byte
	promiscFlag := 0
	if promisc {
		promiscFlag = 1
	}
	h, _, _ := procOpenLive.Call(
		uintptr(unsafe.Pointer(dev)),
		uintptr(65536), // snaplen: whole frames
		uintptr(promiscFlag),
		uintptr(1), // read timeout 1ms; Recv loops to the deadline
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if h == 0 {
		return nil, fmt.Errorf("backend: pcap_open_live(%s) failed: %s", device, cbytes(errbuf[:]))
	}
	link := wire.LinkEthernet
	if dl, _, _ := procDatalink.Call(h); dl != 1 {
		// Rare on Windows adapters, but record the actual DLT if it isn't Ethernet.
		link = wire.LinkType(dl)
	}
	return &Npcap{handle: h, link: link}, nil
}

// Send injects one frame via pcap_sendpacket (0 = success).
func (n *Npcap) Send(frame []byte) error {
	if len(frame) == 0 {
		return nil
	}
	r, _, _ := procSendpacket.Call(n.handle, uintptr(unsafe.Pointer(&frame[0])), uintptr(len(frame)))
	if int32(r) != 0 {
		return fmt.Errorf("backend: pcap_sendpacket failed (rc=%d)", int32(r))
	}
	return nil
}

// Recv returns the next frame passing the filter, waiting up to timeout by
// looping over pcap_next_ex's short per-call timeout.
func (n *Npcap) Recv(buf []byte, timeout time.Duration) (int, bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		var hdr unsafe.Pointer  // *pcap_pkthdr
		var data unsafe.Pointer // *u_char
		r, _, _ := procNextEx.Call(n.handle,
			uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data)))
		switch int32(r) {
		case 1:
			// pcap_pkthdr on 64-bit Windows: timeval(8) + caplen(4) + len(4);
			// caplen is at offset 8.
			caplen := *(*uint32)(unsafe.Add(hdr, 8))
			if caplen == 0 || data == nil {
				break
			}
			src := unsafe.Slice((*byte)(data), int(caplen))
			nn := copy(buf, src)
			if n.Filter != nil && !n.Filter(buf[:nn]) {
				break // not our flow; keep waiting within the deadline
			}
			return nn, true, nil
		case 0:
			// per-call timeout: fall through to the deadline check
		case -1:
			return 0, false, fmt.Errorf("backend: pcap_next_ex failed")
		case -2:
			return 0, false, nil // no more packets (offline; not expected live)
		}
		if timeout > 0 && !time.Now().Before(deadline) {
			return 0, false, nil
		}
		if timeout <= 0 {
			return 0, false, nil
		}
	}
}

func (n *Npcap) Now() time.Time          { return time.Now() }
func (n *Npcap) LinkType() wire.LinkType { return n.link }
func (n *Npcap) Caps() Capabilities      { return Layer2 | CanReceive | StatefulSafe | BatchSend }
func (n *Npcap) Close() error {
	if n.handle != 0 {
		procClose.Call(n.handle)
		n.handle = 0
	}
	return nil
}

// PcapDevice is one interface Npcap can open.
type PcapDevice struct {
	Name        string // \Device\NPF_{GUID} — pass this to -iface
	Description string
}

// ListPcapDevices enumerates Npcap devices via pcap_findalldevs. The friendly
// net.Interfaces names can't be opened directly on Windows, so the ifaces
// command uses these device names.
func ListPcapDevices() ([]PcapDevice, error) {
	ensureNpcapSearchPath()
	if err := wpcap.Load(); err != nil {
		return nil, fmt.Errorf("backend: wpcap.dll not loadable — install Npcap: %w", err)
	}
	var alldevs unsafe.Pointer
	var errbuf [256]byte
	r, _, _ := procFindAllDevs.Call(uintptr(unsafe.Pointer(&alldevs)), uintptr(unsafe.Pointer(&errbuf[0])))
	if int32(r) != 0 {
		return nil, fmt.Errorf("backend: pcap_findalldevs: %s", cbytes(errbuf[:]))
	}
	defer procFreeAllDevs.Call(uintptr(alldevs))

	var out []PcapDevice
	// pcap_if_t on 64-bit: next(8) @0, name(8) @8, description(8) @16.
	for d := alldevs; d != nil; {
		namePtr := *(*unsafe.Pointer)(unsafe.Add(d, 8))
		descPtr := *(*unsafe.Pointer)(unsafe.Add(d, 16))
		out = append(out, PcapDevice{Name: cstr(namePtr), Description: cstr(descPtr)})
		d = *(*unsafe.Pointer)(d) // next
	}
	return out, nil
}

// cstr reads a NUL-terminated C string at ptr.
func cstr(ptr unsafe.Pointer) string {
	if ptr == nil {
		return ""
	}
	var b []byte
	for i := 0; ; i++ {
		c := *(*byte)(unsafe.Add(ptr, i))
		if c == 0 {
			break
		}
		b = append(b, c)
	}
	return string(b)
}

// cbytes trims a fixed C error buffer to its NUL-terminated content.
func cbytes(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
