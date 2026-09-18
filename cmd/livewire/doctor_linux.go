//go:build linux

package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func doctorPlatform(iface string) []doctorFinding {
	out := []doctorFinding{{"platform", "info", "Linux AF_PACKET backend is compiled in", "Socket application replay needs no packet privileges."}}
	data, err := os.ReadFile("/proc/self/status")
	var caps uint64
	known := false
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "CapEff:") {
				caps, err = strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
				known = err == nil
			}
		}
	}
	if known && caps&(1<<13) != 0 {
		out = append(out, doctorFinding{"packet-privilege", "info", "CAP_NET_RAW is effective", "Use the selected isolated lab interface."})
	} else {
		out = append(out, doctorFinding{"packet-privilege", packetSeverity(iface), "CAP_NET_RAW is absent or could not be verified", "Run only packet operations with sudo or an administrator-provided capability configuration; rerun livewire doctor -i <interface>."})
	}
	if !known || caps&(1<<12) == 0 {
		out = append(out, doctorFinding{"rst-privilege", "warning", "CAP_NET_ADMIN for stateful TCP RST suppression is absent or unverified", "Stateful packet TCP requires an administrator-provided RST guard; application socket replay does not."})
	}
	for _, bin := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(bin); err != nil {
			out = append(out, doctorFinding{"rst-tool-" + bin, "warning", bin + " is unavailable for stateful TCP RST suppression", "Install the firewall tooling for the address family used by the lab; rerun livewire doctor."})
		}
	}
	return out
}
