//go:build windows

package webui

import (
	"strings"

	"github.com/kvmukilan/livewire/internal/backend"
)

// listInterfaces returns the selectable Npcap devices plus the host's interface/IP
// table for reference; Windows can't open a friendly adapter name directly.
func listInterfaces() ([]ifaceInfo, []addrRow) {
	addrs := netInterfaceAddrs()
	var out []ifaceInfo
	devs, err := backend.ListPcapDevices()
	if err != nil {
		return out, addrs
	}
	for _, d := range devs {
		kind := "npcap"
		if strings.Contains(strings.ToLower(d.Name), "loopback") {
			kind = "loopback"
		}
		out = append(out, ifaceInfo{Value: d.Name, Label: d.Description, Kind: kind})
	}
	return out, addrs
}
