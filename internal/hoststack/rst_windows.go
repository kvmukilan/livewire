//go:build windows

package hoststack

import (
	"fmt"
	"syscall"
	"unsafe"
)

// WinDivert layer/flag constants (2.x). DROP mode discards matching packets in
// the driver, with no user-space recv/send loop.
const (
	winDivertLayerNetwork = 0
	winDivertFlagDrop     = 0x0002
)

// invalidHandle is INVALID_HANDLE_VALUE, WinDivertOpen's error return.
var invalidHandle = ^uintptr(0)

// winDivertSuppressor drops host RSTs to the target via the WinDivert driver,
// loaded lazily from a DLL so livewire stays cgo-free and builds without
// WinDivert present. Windows analogue of the Linux iptables rule.
type winDivertSuppressor struct {
	rule   Rule
	filter string
	dll    *syscall.LazyDLL
	open   *syscall.LazyProc
	closeP *syscall.LazyProc
	handle uintptr
}

func newSuppressor(r Rule) (Suppressor, error) {
	dll := syscall.NewLazyDLL("WinDivert.dll")
	return &winDivertSuppressor{
		rule:   r,
		filter: winDivertFilter(r),
		dll:    dll,
		open:   dll.NewProc("WinDivertOpen"),
		closeP: dll.NewProc("WinDivertClose"),
		handle: invalidHandle,
	}, nil
}

func (s *winDivertSuppressor) Arm() error {
	if err := s.dll.Load(); err != nil {
		return fmt.Errorf("hoststack: WinDivert.dll could not be loaded — place WinDivert.dll and WinDivert64.sys beside livewire.exe (from the WinDivert distribution) and run as Administrator: %w", err)
	}
	filterPtr, err := syscall.BytePtrFromString(s.filter)
	if err != nil {
		return err
	}
	h, _, callErr := s.open.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(winDivertLayerNetwork),
		uintptr(0), // priority
		uintptr(winDivertFlagDrop),
	)
	if h == invalidHandle {
		return fmt.Errorf("hoststack: WinDivertOpen failed (need Administrator; driver must be installable): %v", callErr)
	}
	s.handle = h
	return nil
}

func (s *winDivertSuppressor) Disarm() error {
	if s.handle == invalidHandle {
		return nil
	}
	r, _, callErr := s.closeP.Call(s.handle)
	s.handle = invalidHandle
	if r == 0 {
		return fmt.Errorf("hoststack: WinDivertClose failed: %v", callErr)
	}
	return nil
}

func (s *winDivertSuppressor) Describe() string {
	return fmt.Sprintf("WinDivert DROP-mode handle, filter: %q", s.filter)
}
