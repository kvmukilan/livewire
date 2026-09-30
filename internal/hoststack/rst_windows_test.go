//go:build windows

package hoststack

import (
	"errors"
	"testing"
)

type fakeWinDivertClose struct {
	calls   int
	failure error
	handles []uintptr
}

func (p *fakeWinDivertClose) Call(args ...uintptr) (uintptr, uintptr, error) {
	p.calls++
	p.handles = append(p.handles, args[0])
	if p.calls == 1 && p.failure != nil {
		return 0, 0, p.failure
	}
	return 1, 0, nil
}

type fakeWinDivertLibrary struct {
	calls   int
	failure error
}

func (d *fakeWinDivertLibrary) Release() error {
	d.calls++
	if d.calls == 1 {
		return d.failure
	}
	return nil
}

// Native Windows control-flow coverage with fake OS calls, not driver/NIC
// qualification. A failed close must retain both resources needed to retry.
func TestWinDivertCleanupRetainsFailedHandleAndLibrary(t *testing.T) {
	closeFailure, libraryFailure := errors.New("close failed"), errors.New("FreeLibrary failed")
	closeCall := &fakeWinDivertClose{failure: closeFailure}
	library := &fakeWinDivertLibrary{failure: libraryFailure}
	s := &winDivertSuppressor{handle: 123, closeP: closeCall, dll: library}
	g := &Guard{s: s, armed: true}
	if err := g.Release(); !errors.Is(err, closeFailure) {
		t.Fatalf("close failure: %v", err)
	}
	if s.handle != 123 || s.dll != library || library.calls != 0 || !g.armed {
		t.Fatal("live handle or DLL discarded after close failure")
	}
	if err := g.Release(); !errors.Is(err, libraryFailure) {
		t.Fatalf("library failure: %v", err)
	}
	if s.handle != invalidHandle || s.dll != library || !g.armed {
		t.Fatal("DLL ownership discarded after release failure")
	}
	if err := g.Release(); err != nil {
		t.Fatal(err)
	}
	if s.handle != invalidHandle || s.dll != nil || g.armed || closeCall.calls != 2 || library.calls != 2 {
		t.Fatalf("cleanup calls: close=%d library=%d armed=%v", closeCall.calls, library.calls, g.armed)
	}
	for _, handle := range closeCall.handles {
		if handle != 123 {
			t.Fatalf("retried wrong handle: %d", handle)
		}
	}
	if err := g.Release(); err != nil || closeCall.calls != 2 || library.calls != 2 {
		t.Fatal("successful cleanup is not idempotent")
	}
}
