package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/kvmukilan/livewire/internal/hoststack"
)

// cmdRstdrop drops the host kernel's outbound RSTs to a target and holds the rule
// until Ctrl-C. Same guard `live` arms automatically, exposed for use with an
// external injector (scapy). Needs root (iptables) / Administrator (WinDivert).
func cmdRstdrop(args []string) error {
	fs := flag.NewFlagSet("rstdrop", flag.ContinueOnError)
	var ip string
	fs.StringVar(&ip, flagTarget, "", "target IP")
	fs.StringVar(&ip, "ip", "", "alias for -t")
	port := fs.Int("port", 0, "target TCP port (required)")
	sport := fs.Int("sport", 0, "match only this source port (0 = any)")
	allFlags := registerAllFlags(fs)
	fs.Usage = func() {
		fmt.Println("usage: livewire rstdrop -t <target-ip> -port <port> [-sport <n>]")
		fmt.Println("\nDrop the host's outbound RSTs to a target until Ctrl-C.")
		fmt.Println("\nYou usually do not need this: 'reproduce' and 'live' arm the same guard")
		fmt.Println("automatically for the duration of a replay. Use it only when an external")
		fmt.Println("injector (Scapy, a hand-rolled script) is sending the packets instead.")
		printFlags(fs, flagTarget, "port", "sport")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if handleAllFlags(fs, *allFlags, aliasSet{"ip": true}) {
		return errAllFlags
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		fs.Usage()
		return fmt.Errorf("invalid -t %q", ip)
	}
	if *port <= 0 || *port > 65535 {
		fs.Usage()
		return fmt.Errorf("invalid -port %d", *port)
	}

	guard, err := hoststack.Arm(hoststack.Rule{TargetIP: addr, TargetPort: uint16(*port), LocalPort: uint16(*sport)})
	if err != nil {
		return err
	}
	defer guard.Release()

	fmt.Printf("armed: %s\n", guard.Describe())
	fmt.Println("dropping host RSTs — press Ctrl-C to remove the rule")

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	fmt.Println("\nremoving rule")
	return nil
}
