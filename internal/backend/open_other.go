//go:build !linux && !windows

package backend

import (
	"fmt"
	"net/netip"
	"runtime"
)

// openLive: no live backend on this OS. Use Linux (AF_PACKET) or a Windows
// Npcap build; offline commands work everywhere.
func openLive(cfg LiveConfig) (*LiveBackend, error) {
	return nil, fmt.Errorf("backend: no live packet backend on %s; "+
		"use Linux (AF_PACKET, built in) or a Windows build with the Npcap backend, "+
		"or run offline commands / live -dry-run", runtime.GOOS)
}

// openSender: no send backend on this OS.
func openSender(iface string) (PacketBackend, error) {
	return nil, fmt.Errorf("backend: no packet send backend on %s; "+
		"use Linux (AF_PACKET) or a Windows build with the Npcap backend", runtime.GOOS)
}

// openCapture: no capture backend on this OS.
func openCapture(iface string, promisc bool) (PacketBackend, error) {
	return nil, fmt.Errorf("backend: no capture backend on %s; use Linux or a Windows Npcap build", runtime.GOOS)
}

func resolveLink(_ string, _ netip.Addr, _ PacketBackend) ([6]byte, [6]byte, error) {
	return [6]byte{}, [6]byte{}, fmt.Errorf("backend: no link resolver on %s", runtime.GOOS)
}
