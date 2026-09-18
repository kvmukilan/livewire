//go:build windows

package main

import (
	"github.com/kvmukilan/livewire/internal/backend"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
)

func doctorPlatform(iface string) []doctorFinding {
	out := []doctorFinding{{"platform", "info", "Windows Npcap backend is compiled in", "Socket application replay needs neither Npcap nor elevation."}}
	devs, err := backend.ListPcapDevices()
	if err != nil {
		out = append(out, doctorFinding{"npcap-unavailable", packetSeverity(iface), err.Error(), "Install Npcap using SETUP.md, then run livewire ifaces and livewire doctor."})
	} else {
		out = append(out, doctorFinding{"npcap-available", "info", "Npcap loaded and device enumeration succeeded", "Use a Npcap device name from livewire ifaces for -i."})
		if iface != "" {
			found := false
			for _, d := range devs {
				if d.Name == iface {
					found = true
					if d.Flags&2 == 0 {
						out = append(out, doctorFinding{"interface-down", "blocker", "Selected Npcap interface is not up", "Enable the adapter and connect the lab cable, then rerun livewire doctor -i <interface>."})
					} else {
						out = append(out, doctorFinding{"interface-up", "info", "Selected Npcap interface is up", "Driver opening is deferred until an explicit replay or capture."})
					}
				}
			}
			if !found {
				out = append(out, doctorFinding{"interface-missing", "blocker", "Selected Npcap device does not exist", "Run livewire ifaces and pass the complete Npcap device name to -i."})
			}
		}
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		out = append(out, doctorFinding{"packet-privilege", "info", "Process is elevated", "Elevate only packet operations; inspect captures without elevation."})
	} else {
		out = append(out, doctorFinding{"packet-privilege", "warning", "Process is not elevated; Npcap access depends on installation policy", "If packet access is denied, open an Administrator terminal and rerun livewire doctor -i <interface>."})
	}
	exe, err := os.Executable()
	if err == nil {
		if _, err := os.Stat(filepath.Join(filepath.Dir(exe), "WinDivert.dll")); err != nil {
			out = append(out, doctorFinding{"rst-driver", "warning", "WinDivert.dll is missing beside the executable", "Follow SETUP.md for stateful packet TCP RST suppression; wire and socket application replay do not need it."})
		}
	}
	return out
}
