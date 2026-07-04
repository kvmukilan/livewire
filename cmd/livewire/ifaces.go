package main

import (
	"flag"
	"fmt"
	"net"
	"runtime"
	"strings"
)

// cmdIfaces lists interfaces with addresses and live-replay capability.
func cmdIfaces(args []string) error {
	fs := flag.NewFlagSet("ifaces", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Println("usage: livewire ifaces")
		fmt.Println("\nList interfaces with addresses and live-replay capability on this OS.")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	ifis, err := net.Interfaces()
	if err != nil {
		return err
	}
	live := liveSupported()
	fmt.Printf("live backend on %s/%s: %s\n\n", runtime.GOOS, runtime.GOARCH, live)

	// Windows live replay uses Npcap device names, not friendly names.
	if runtime.GOOS == "windows" {
		if devs, err := listPcapDevices(); err == nil && len(devs) > 0 {
			fmt.Println("Npcap devices (pass one to -iface for live/replay):")
			for _, d := range devs {
				fmt.Printf("  %s\n      %s\n", d.name, d.desc)
			}
			fmt.Println()
		}
	}

	for _, ifi := range ifis {
		flags := []string{}
		if ifi.Flags&net.FlagUp != 0 {
			flags = append(flags, "up")
		}
		if ifi.Flags&net.FlagLoopback != 0 {
			flags = append(flags, "loopback")
		}
		if ifi.Flags&net.FlagPointToPoint != 0 {
			flags = append(flags, "p2p")
		}
		fmt.Printf("%s  [%s]  mtu=%d  mac=%s\n", ifi.Name, strings.Join(flags, ","), ifi.MTU, macOrDash(ifi.HardwareAddr))
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			fmt.Printf("    %s\n", a.String())
		}
		var cap string
		switch {
		case ifi.Flags&net.FlagLoopback != 0:
			cap = "offline/dry-run only (loopback)"
		case runtime.GOOS == "linux":
			cap = "stateless + stateful (AF_PACKET)"
		case runtime.GOOS == "windows":
			cap = "stateless + stateful (Npcap; use the \\Device\\NPF name below)"
		default:
			cap = "dry-run only (no live backend on this OS)"
		}
		fmt.Printf("    capability: %s\n\n", cap)
	}
	return nil
}

func macOrDash(h net.HardwareAddr) string {
	if len(h) == 0 {
		return "-"
	}
	return h.String()
}

// liveSupported reports this build's live-replay mechanism.
func liveSupported() string {
	switch runtime.GOOS {
	case "linux":
		return "AF_PACKET (pure Go)"
	case "windows":
		return "Npcap (install wpcap.dll via npcap.com); host-RST suppression via WinDivert"
	default:
		return "none"
	}
}
