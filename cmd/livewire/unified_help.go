package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// help is the single help router. Its default is task-oriented; reference
// material stays one level deeper so a first-time user is not handed the full
// command and flag surface before they know what they want to accomplish.
func help(args []string) error {
	if len(args) == 0 {
		printHelpHub(os.Stdout)
		return nil
	}

	topic := strings.ToLower(args[0])
	switch topic {
	case "--all", "-all", "all", "commands":
		printCommandCatalog(os.Stdout)
		return nil
	case "examples":
		printExamples(os.Stdout)
		return nil
	case "troubleshoot", "troubleshooting":
		printTroubleshooting(os.Stdout)
		return nil
	case "protocols", "protocol":
		printProtocols(os.Stdout)
		return nil
	case "diagnose", "diagnostics", "support":
		printDiagnostics(os.Stdout)
		return nil
	}

	for _, c := range commands {
		if c.matches(topic) {
			// Commands remain the source of truth for their own flags. The hub
			// routes to that help instead of maintaining a second flag reference.
			err := c.run([]string{"-h"})
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
	}

	message := fmt.Sprintf("unknown command or topic %q", args[0])
	if suggestion := closestHelpTarget(topic); suggestion != "" {
		message += fmt.Sprintf("; did you mean 'livewire help %s'?", suggestion)
	} else {
		message += "; run 'livewire help' to see the available topics"
	}
	return errors.New(message)
}

func printHelpHub(w io.Writer) {
	fmt.Fprintf(w, "livewire %s - reproduce a network problem from a capture\n\n", version)
	fmt.Fprintln(w, "Two commands cover the normal workflow:")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Guided and safe - detect the protocol, ask only for missing inputs,")
	fmt.Fprintln(w, "  open fresh secure sessions, verify replies, and write evidence:")
	fmt.Fprintln(w, "    livewire reproduce issue.pcap")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Live and advanced - the same automatic protocol handling, with expert")
	fmt.Fprintln(w, "  controls and the historical 'live -in ...' mode still available:")
	fmt.Fprintln(w, "    livewire live issue.pcap")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Help topics:")
	fmt.Fprintln(w, "  livewire help examples       copy-paste common workflows")
	fmt.Fprintln(w, "  livewire help troubleshoot   recover from common problems")
	fmt.Fprintln(w, "  livewire help protocols      see automatic drivers and safe fallbacks")
	fmt.Fprintln(w, "  livewire help diagnose       collect reproducible support evidence")
	fmt.Fprintln(w, "  livewire help commands       list every command")
	fmt.Fprintln(w, "  livewire help <command>      explain one command and its options")
}

func printExamples(w io.Writer) {
	fmt.Fprintln(w, "Common Livewire examples")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Reproduce the recorded exchange on a device:")
	fmt.Fprintln(w, "  livewire reproduce issue.pcap -t 192.168.1.50")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Try five times when the problem is intermittent:")
	fmt.Fprintln(w, "  livewire reproduce issue.pcap -t 192.168.1.50 -n 5")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Automatically decrypt and re-terminate captured TLS:")
	fmt.Fprintln(w, "  livewire reproduce tls.pcap -keylog sslkeys.log -t device.example:443")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Reproduce SSH with fresh credentials and a pinned host key:")
	fmt.Fprintln(w, "  livewire reproduce ssh.pcap -t device:22 -user admin -key id_ed25519 -host-key device.pub -cmd 'show status'")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Use the advanced live entry point (same automatic routing):")
	fmt.Fprintln(w, "  livewire live issue.pcap -t 192.168.1.50")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Explicit raw packet injection (never selected automatically):")
	fmt.Fprintln(w, "  livewire live issue.pcap --wire -i <connection>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'livewire help <command>' for that command's usage and options.")
}

func printTroubleshooting(w io.Writer) {
	fmt.Fprintln(w, "Livewire troubleshooting")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Capture not found")
	fmt.Fprintln(w, "  Check the path, then run: livewire check <capture.pcap>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Connection or interface is unclear")
	fmt.Fprintln(w, "  Run: livewire ifaces")
	fmt.Fprintln(w, "  Copy the exact connection name shown and pass it with -i.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Permission denied or live capture/replay cannot start")
	fmt.Fprintln(w, "  Windows: open PowerShell as Administrator.")
	fmt.Fprintln(w, "  Linux: run the live command with sudo or configured capabilities.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "wpcap.dll or Npcap is missing on Windows")
	fmt.Fprintln(w, "  Install Npcap, then run 'livewire ifaces' to verify packet access.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The device does not answer")
	fmt.Fprintln(w, "  Confirm the target IP and connection, then inspect the capture:")
	fmt.Fprintln(w, "    livewire check issue.pcap -details")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "TLS or SSH traffic is blocked")
	fmt.Fprintln(w, "  Use reproduce/live and supply the requirement named in the error, such as")
	fmt.Fprintln(w, "  -keylog for TLS or -user, -key/-pass, -host-key, and -cmd for SSH.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "More setup and operator detail: SETUP.md and DOCUMENTATION.md")
}

func printProtocols(w io.Writer) {
	fmt.Fprintln(w, "Livewire automatic protocol handling")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  HTTP, DNS, MQTT, Modbus, DNP3, FTP and rule packs")
	fmt.Fprintln(w, "    Decode messages, update dynamic fields, and compare live replies.")
	fmt.Fprintln(w, "  Ordinary TCP, UDP and ICMP")
	fmt.Fprintln(w, "    Use a stateful transport driver when safe; no silent raw fallback.")
	fmt.Fprintln(w, "  TLS and FTPS")
	fmt.Fprintln(w, "    Require a matching NSS key log, then open a fresh verified TLS session.")
	fmt.Fprintln(w, "  SSH")
	fmt.Fprintln(w, "    Requires fresh credentials, a pinned host key, and explicit commands.")
	fmt.Fprintln(w, "  Unknown encryption, DNP3 Secure Authentication, mixed secure lanes")
	fmt.Fprintln(w, "    Block before sending and explain what must be isolated or supplied.")
	fmt.Fprintln(w, "  Explicit --wire")
	fmt.Fprintln(w, "    Inject captured frames only when the operator asks; no reply-equivalence claim.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Inspect one capture without sending: livewire check issue.pcap -details")
}

func printDiagnostics(w io.Writer) {
	fmt.Fprintln(w, "Collect reproducible Livewire evidence")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "1. Inspect without sending:")
	fmt.Fprintln(w, "   livewire check issue.pcap -details -json assessment.json")
	fmt.Fprintln(w, "2. Reproduce more than once when the fault is intermittent:")
	fmt.Fprintln(w, "   livewire reproduce issue.pcap -t 192.168.1.50 -n 5")
	fmt.Fprintln(w, "3. Keep the printed report and actual-traffic capture paths. Defaults never")
	fmt.Fprintln(w, "   overwrite a prior run; numbered filenames are chosen automatically.")
	fmt.Fprintln(w, "4. Create a redacted metadata-only support archive:")
	fmt.Fprintln(w, "   livewire bundle -report issue.report.json -evidence issue.actual.pcap -o support.zip")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Packet bytes are referenced by digest, not embedded in support.zip.")
}

func printCommandCatalog(w io.Writer) {
	fmt.Fprintf(w, "livewire %s command catalog\n\n", version)
	fmt.Fprintln(w, "Primary commands:")
	printGroup(w, groupEveryday)
	fmt.Fprintln(w, "\nAdvanced commands:")
	printGroup(w, groupAdvanced)
	fmt.Fprintln(w, "\nCompatibility entry points, still supported:")
	printGroup(w, groupCompat)
	fmt.Fprintln(w, "\nCommon options:")
	fmt.Fprintln(w, "  -in    capture file             -o  where to write")
	fmt.Fprintln(w, "  -i     network connection       -n  how many")
	fmt.Fprintln(w, "  -t     device to talk to")
	fmt.Fprintln(w, "\nRun 'livewire help <command>' for one command's usage and options.")
}

func printGroup(w io.Writer, group cmdGroup) {
	for _, c := range commands {
		if c.group == group {
			fmt.Fprintf(w, "  %-11s %s\n", c.name, c.summary)
		}
	}
}

func closestCommand(input string) string {
	var names []string
	for _, c := range commands {
		names = append(names, c.name)
	}
	return closestName(strings.ToLower(input), names)
}

func closestHelpTarget(input string) string {
	names := []string{"examples", "troubleshoot", "protocols", "diagnose", "commands"}
	for _, c := range commands {
		names = append(names, c.name)
	}
	return closestName(strings.ToLower(input), names)
}

func closestName(input string, names []string) string {
	best, bestDistance := "", -1
	for _, name := range names {
		distance := editDistance(input, name)
		if bestDistance < 0 || distance < bestDistance {
			best, bestDistance = name, distance
		}
	}
	limit := 2
	if len(input) >= 8 {
		limit = 3
	}
	if bestDistance > limit {
		return ""
	}
	return best
}

func editDistance(a, b string) int {
	previous := make([]int, len(b)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(a); i++ {
		current := make([]int, len(b)+1)
		current[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			current[j] = min(
				current[j-1]+1,
				previous[j]+1,
				previous[j-1]+cost,
			)
		}
		previous = current
	}
	return previous[len(b)]
}
