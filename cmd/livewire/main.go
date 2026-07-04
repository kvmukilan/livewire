// Command livewire is a cross-platform pcap replay and rewriting tool.
package main

import (
	"fmt"
	"os"
)

const version = "0.1.0-s0"

type command struct {
	name    string
	summary string
	run     func(args []string) error
}

var commands = []command{
	{"info", "inspect a pcap/pcapng file and print a summary", cmdInfo},
	{"ifaces", "list interfaces with addresses and live-replay capability", cmdIfaces},
	{"capture", "record live frames from an interface into a pcap", cmdCapture},
	{"rewrite", "apply static edits (MAC/IP/port/TTL/VLAN/seq) to a capture", cmdRewrite},
	{"prep", "classify packets client/server and write a cache file", cmdPrep},
	{"replay", "stateless send: blast a capture onto an interface at a set rate", cmdReplay},
	{"live", "stateful TCP replay: realign seq/ack to a live peer (dry-run or on-wire)", cmdLive},
	{"web", "serve the browser dashboard (capture/load/replay/RST rules/SSH)", cmdWeb},
	{"convert", "convert a pcapng file to classic pcap", cmdConvert},
	{"version", "print the version", cmdVersion},
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	name := os.Args[1]
	if name == "-h" || name == "--help" || name == "help" {
		usage()
		return
	}
	for _, c := range commands {
		if c.name == name {
			if err := c.run(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "livewire %s: %v\n", name, err)
				os.Exit(1)
			}
			return
		}
	}
	fmt.Fprintf(os.Stderr, "livewire: unknown command %q\n\n", name)
	usage()
	os.Exit(2)
}

func usage() {
	fmt.Fprintf(os.Stderr, "livewire %s — cross-platform stateful TCP replay\n\n", version)
	fmt.Fprintln(os.Stderr, "usage: livewire <command> [flags]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "commands:")
	for _, c := range commands {
		fmt.Fprintf(os.Stderr, "  %-9s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(os.Stderr, "\nrun 'livewire <command> -h' for command flags")
}

func cmdVersion(_ []string) error {
	fmt.Println("livewire", version)
	return nil
}
