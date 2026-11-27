//go:build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// launchedWithoutTerminal reports whether this process owns its console alone,
// which is how Explorer starts a console program on a double-click. A shell
// that ran the command is a second process attached to the same console.
func launchedWithoutTerminal() bool {
	var pids [2]uint32
	n, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleProcessList").Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}

// holdWindowOpen keeps a double-clicked console visible long enough to read
// why the dashboard did not start.
func holdWindowOpen() {
	fmt.Print("\nPress Enter to close this window.")
	_, _ = fmt.Scanln()
}
