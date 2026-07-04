//go:build !windows

package webui

// listInterfaces returns the host's interfaces as both the selectable list and
// the reference table; the AF_PACKET backend opens them by plain name.
func listInterfaces() ([]ifaceInfo, []addrRow) {
	addrs := netInterfaceAddrs()
	out := make([]ifaceInfo, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, ifaceInfo{Value: a.Name, Label: a.Name, IPs: a.IPs, Kind: "afpacket"})
	}
	return out, addrs
}
