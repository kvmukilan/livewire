// Command livewire is a cross-platform pcap replay and rewriting tool.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

const version = "0.6.0"

// cmdGroup decides whether a command appears at the front door. The tool has
// sixteen commands but a field engineer only ever needs five of them, and a flat
// list of sixteen buries the one they were told to run.
type cmdGroup int

const (
	// groupEveryday is what 'livewire' with no arguments shows.
	groupEveryday cmdGroup = iota
	// groupAdvanced still runs and is still documented; it is listed only by
	// 'livewire help --all'.
	groupAdvanced
	// groupCompat is an older name kept working after a merge or rename. It
	// dispatches and it is named in 'livewire help --all', but it stays out of
	// the everyday list so the surface a newcomer reads does not grow every
	// time something is tidied up.
	groupCompat
)

type command struct {
	name    string
	summary string
	group   cmdGroup
	run     func(args []string) error
}

// matches reports whether name selects this command.
func (c command) matches(name string) bool { return c.name == name }

// commands is the whole command surface, everyday commands first so the order
// here is the order a reader sees.
var commands = []command{
	{name: "reproduce", group: groupEveryday, run: cmdReproduce,
		summary: "replay a capture against your device and say what happened"},
	{name: "check", group: groupEveryday, run: cmdCheck,
		summary: "look at a capture: what's in it, and whether it can be replayed"},
	{name: "capture", group: groupEveryday, run: cmdCapture,
		summary: "record traffic from a network connection into a file"},
	{name: "ifaces", group: groupEveryday, run: cmdIfaces,
		summary: "list your network connections"},
	{name: "web", group: groupEveryday, run: cmdWeb,
		summary: "open the browser dashboard"},

	{name: "live", group: groupAdvanced, run: cmdLive,
		summary: "stateful TCP replay: realign seq/ack to a live peer (dry-run or on-wire)"},
	{name: "lab", group: groupAdvanced, run: cmdLab,
		summary: "two-sided replay through a DUT with topology, faults, and PCAPNG evidence"},
	{name: "replay", group: groupAdvanced, run: cmdReplay,
		summary: "stateless send: blast a capture onto an interface at a set rate"},
	{name: "rewrite", group: groupAdvanced, run: cmdRewrite,
		summary: "apply static edits (MAC/IP/port/TTL/VLAN/seq) to a capture"},
	{name: "convert", group: groupAdvanced, run: cmdConvert,
		summary: "convert a pcapng file to classic pcap"},
	{name: "tls-replay", group: groupAdvanced, run: cmdTLSReplay,
		summary: "decrypt with a key log and re-terminate a fresh verified TLS session"},
	{name: "ssh-replay", group: groupAdvanced, run: cmdSSHReplay,
		summary: "re-terminate an SSH session against a live device"},
	{name: "bundle", group: groupAdvanced, run: cmdBundle,
		summary: "create a redacted metadata-only support archive"},
	{name: "rstdrop", group: groupAdvanced, run: cmdRstdrop,
		summary: "drop the host's outbound RSTs to a target until Ctrl-C (only needed with an external injector)"},
	{name: "version", group: groupAdvanced, run: cmdVersion,
		summary: "print the version"},

	// 'check' merged these two. Both keep their exact previous behaviour so
	// existing scripts and older copies of the docs still work.
	{name: "info", group: groupCompat, run: cmdInfo,
		summary: "capture summary only (now part of 'check')"},
	{name: "analyze", group: groupCompat, run: cmdAnalyze,
		summary: "replayability assessment only (now part of 'check')"},
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	name := os.Args[1]
	if name == "-h" || name == "--help" || name == "help" {
		if err := help(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "livewire help: %v\n", err)
			os.Exit(2)
		}
		return
	}
	for _, c := range commands {
		if !c.matches(name) {
			continue
		}
		err := c.run(os.Args[2:])
		switch {
		case err == nil:
			return
		// Asking for help is not a failure, even though the flag package
		// reports it as one.
		case errors.Is(err, flag.ErrHelp), errors.Is(err, errAllFlags):
			return
		default:
			fmt.Fprintf(os.Stderr, "livewire %s: %v\n", name, err)
			os.Exit(1)
		}
	}
	fmt.Fprintf(os.Stderr, "livewire: unknown command %q\n\n", name)
	usage()
	os.Exit(2)
}

// help implements 'livewire help [--all | <command>]'.
func help(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	switch args[0] {
	case "--all", "-all", "all":
		usageAll()
		return nil
	}
	for _, c := range commands {
		if c.matches(args[0]) {
			// Every command prints its own help when asked, so route through it
			// rather than keeping a second description of its flags here.
			err := c.run([]string{"-h"})
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
	}
	return fmt.Errorf("unknown command %q; run 'livewire help --all' for the full list", args[0])
}

func usage() {
	fmt.Fprintf(os.Stderr, "livewire %s - protocol-adaptive traffic replay\n\n", version)
	fmt.Fprintln(os.Stderr, "usage: livewire <command> [options]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "New here? To reproduce an issue we sent you, run:")
	fmt.Fprintln(os.Stderr, "  livewire reproduce <capture.pcap>")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "everyday commands:")
	printGroup(groupEveryday)
	fmt.Fprintln(os.Stderr, "\nrun 'livewire help <command>' for one command's options,")
	fmt.Fprintln(os.Stderr, "or 'livewire help --all' for the advanced commands.")
}

func usageAll() {
	fmt.Fprintf(os.Stderr, "livewire %s - protocol-adaptive traffic replay\n\n", version)
	fmt.Fprintln(os.Stderr, "usage: livewire <command> [options]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "everyday commands:")
	printGroup(groupEveryday)
	fmt.Fprintln(os.Stderr, "\nadvanced commands:")
	printGroup(groupAdvanced)
	fmt.Fprintln(os.Stderr, "\nolder names, still supported:")
	printGroup(groupCompat)
	fmt.Fprintln(os.Stderr, "\ncommon options, the same on every command that has them:")
	fmt.Fprintln(os.Stderr, "  -in    the capture file        -o  where to write")
	fmt.Fprintln(os.Stderr, "  -i     network connection      -n  how many")
	fmt.Fprintln(os.Stderr, "  -t     the device to talk to")
	fmt.Fprintln(os.Stderr, "\nrun 'livewire help <command>' for one command's options.")
}

func printGroup(g cmdGroup) {
	for _, c := range commands {
		if c.group == g {
			fmt.Fprintf(os.Stderr, "  %-11s %s\n", c.name, c.summary)
		}
	}
}

func cmdVersion(_ []string) error {
	fmt.Println("livewire", version)
	return nil
}
