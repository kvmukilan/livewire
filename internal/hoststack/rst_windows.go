//go:build windows

package hoststack

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
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
// loaded only by absolute executable-directory path with restricted dependency
// search flags. Livewire stays cgo-free and builds without WinDivert present.
type winDivertSuppressor struct {
	rule   Rule
	filter string
	dll    *windows.DLL
	open   *windows.Proc
	closeP *windows.Proc
	handle uintptr
}

func newSuppressor(r Rule) (Suppressor, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("hoststack: resolve executable path: %w", err)
	}
	dllPath := filepath.Join(filepath.Dir(exe), "WinDivert.dll")
	info, err := os.Lstat(dllPath)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("hoststack: trusted WinDivert.dll not found beside executable: %s", dllPath)
	}
	handle, err := windows.LoadLibraryEx(dllPath, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, fmt.Errorf("hoststack: load trusted WinDivert DLL: %w", err)
	}
	dll := &windows.DLL{Name: dllPath, Handle: handle}
	open, openErr := dll.FindProc("WinDivertOpen")
	closeP, closeErr := dll.FindProc("WinDivertClose")
	if err := errors.Join(openErr, closeErr); err != nil {
		return nil, errors.Join(err, dll.Release())
	}
	return &winDivertSuppressor{
		rule:   r,
		filter: winDivertFilter(r),
		dll:    dll,
		open:   open,
		closeP: closeP,
		handle: invalidHandle,
	}, nil
}

func (s *winDivertSuppressor) Arm() error {
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
	var errs []error
	if s.handle != invalidHandle {
		r, _, callErr := s.closeP.Call(s.handle)
		s.handle = invalidHandle
		if r == 0 {
			errs = append(errs, fmt.Errorf("hoststack: WinDivertClose failed: %v", callErr))
		}
	}
	if s.dll != nil {
		if err := s.dll.Release(); err != nil {
			errs = append(errs, err)
		}
		s.dll = nil
	}
	return errors.Join(errs...)
}

func (s *winDivertSuppressor) Describe() string {
	return fmt.Sprintf("WinDivert DROP-mode handle, filter: %q", s.filter)
}
