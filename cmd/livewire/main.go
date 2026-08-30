// Command livewire is a cross-platform pcap replay and rewriting tool.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/kvmukilan/livewire/internal/buildinfo"
)

var version = buildinfo.Version

// cmdGroup decides whether a command appears at the front door. The product has
// two primary actions; narrower tools remain available through the full catalog.
type cmdGroup int

const (
	// groupEveryday is what 'livewire' with no arguments shows.
	groupEveryday cmdGroup = iota
	// groupAdvanced still runs and is still documented; it is listed only by
	// 'livewire help --all'.
	groupAdvanced
	// groupCompat is an older or protocol-specific entry point kept working. It
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
		summary: "guided, safe reproduction with automatic protocol handling"},
	{name: "live", group: groupEveryday, run: cmdLive,
		summary: "protocol-aware live replay plus advanced compatibility controls"},

	{name: "check", group: groupAdvanced, run: cmdCheck,
		summary: "look at a capture: what's in it, and whether it can be replayed"},
	{name: "capture", group: groupAdvanced, run: cmdCapture,
		summary: "record traffic from a network connection into a file"},
	{name: "ifaces", group: groupAdvanced, run: cmdIfaces,
		summary: "list your network connections"},
	{name: "web", group: groupAdvanced, run: cmdWeb,
		summary: "open the browser dashboard"},
	{name: "lab", group: groupAdvanced, run: cmdLab,
		summary: "two-sided replay through a DUT with topology, faults, and PCAPNG evidence"},
	{name: "replay", group: groupAdvanced, run: cmdReplay,
		summary: "stateless send: blast a capture onto an interface at a set rate"},
	{name: "rewrite", group: groupAdvanced, run: cmdRewrite,
		summary: "apply static edits (MAC/IP/port/TTL/VLAN/seq) to a capture"},
	{name: "convert", group: groupAdvanced, run: cmdConvert,
		summary: "convert a pcapng file to classic pcap"},
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
	{name: "tls-replay", group: groupCompat, run: cmdTLSReplay,
		summary: "TLS-specific compatibility entry point (automatic in reproduce/live)"},
	{name: "ftp-replay", group: groupCompat, run: cmdFTPReplay,
		summary: "FTP/FTPS compatibility entry point (automatic in reproduce/live)"},
	{name: "ssh-replay", group: groupCompat, run: cmdSSHReplay,
		summary: "SSH-specific compatibility entry point (automatic in reproduce/live)"},
}

func main() {
	if len(os.Args) < 2 {
		printHelpHub(os.Stdout)
		return
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
	fmt.Fprintf(os.Stderr, "livewire: unknown command %q\n", name)
	if suggestion := closestCommand(name); suggestion != "" {
		fmt.Fprintf(os.Stderr, "Did you mean 'livewire %s'?\n", suggestion)
	}
	fmt.Fprintln(os.Stderr, "Run 'livewire help' to choose a task or see the available help topics.")
	os.Exit(2)
}

func cmdVersion(_ []string) error {
	fmt.Println("livewire", version)
	return nil
}
