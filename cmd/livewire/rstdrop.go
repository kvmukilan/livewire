package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/kvmukilan/livewire/internal/hoststack"
)

// cmdRstdrop drops the host kernel's outbound RSTs to a target and holds the rule
// until Ctrl-C. Same guard packet TCP replay arms, exposed for use with an
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
		fmt.Println("\nAdvanced live packet-TCP replay arms this guard automatically.")
		fmt.Println("Fresh OS-managed live sessions do not need it. Stateless reproduce/replay")
		fmt.Println("does not install a guard. This command is an explicit low-level lab control.")
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
	if *sport < 0 || *sport > 65535 {
		fs.Usage()
		return fmt.Errorf("invalid -sport %d", *sport)
	}

	ctx, stop := commandSignalContext(context.Background())
	defer stop()
	return holdRSTDrop(ctx, os.Stdout, hoststack.Rule{TargetIP: addr, TargetPort: uint16(*port), LocalPort: uint16(*sport)}, func(rule hoststack.Rule) (rstDropGuard, error) {
		return hoststack.Arm(rule)
	})
}

type rstDropGuard interface {
	Release() error
	Describe() string
}

func holdRSTDrop(ctx context.Context, out io.Writer, rule hoststack.Rule, arm func(hoststack.Rule) (rstDropGuard, error)) (retErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	guard, err := arm(rule)
	if err != nil {
		return err
	}
	released := false
	release := func() error {
		if released {
			return nil
		}
		if err := guard.Release(); err != nil {
			return err
		}
		released = true
		return nil
	}
	defer func() { retErr = errors.Join(retErr, release()) }()
	if _, err := fmt.Fprintf(out, "armed: %s\ndropping host RSTs — press Ctrl-C to remove the rule\n", guard.Describe()); err != nil {
		return err
	}
	<-ctx.Done()
	if err := release(); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, "\nRST-drop rule removed")
	return err
}
