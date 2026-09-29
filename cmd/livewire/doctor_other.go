//go:build !linux && !windows

package main

func doctorPlatform(iface string) []doctorFinding {
	return []doctorFinding{{"packet-platform", packetSeverity(iface), "This build has no packet backend", "Use Windows or Linux for packet replay; offline inspection and socket application replay remain available."}}
}
