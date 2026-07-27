package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// The canonical flag vocabulary. The same idea keeps the same name on every
// command, so a peer who learns one command can drive the next one, and these
// short names are what the help text shows. Every command that used a different
// name for one of these keeps it working as an alias — see alias().
const (
	flagIn      = "in"      // the capture file to read
	flagIface   = "i"       // which network connection to use
	flagTarget  = "t"       // the device to talk to
	flagCount   = "n"       // how many
	flagOut     = "o"       // where to write
	flagLive    = "live"    // actually send on the wire
	flagDetails = "details" // show the expert tables
)

// allFlagsName is the escape hatch that lists everything a command accepts,
// including the aliases and the expert flags kept out of the default help.
const allFlagsName = "all-flags"

// aliasSet is the set of flag names that exist only for backward compatibility.
// They work exactly like the canonical flag they shadow but are never listed,
// so old scripts and older docs keep running without widening the surface a
// first-time user has to read.
type aliasSet map[string]bool

// usageWriter is where command help goes. Commands print their own help to
// stdout (it is requested output, not an error), while the top-level usage goes
// to stderr because it doubles as the message for a bad invocation.
var usageWriter = os.Stdout

// printFlags lists only the named flags, in the order given, and then points at
// -all-flags for the rest. Go's flag package has no notion of a hidden flag, so
// selecting what to show is the only way to keep a 12-flag command approachable.
//
// Names that do not exist on fs are skipped rather than reported: it keeps the
// call sites declarative, and the flag-vocabulary test asserts that every name
// listed here resolves.
func printFlags(fs *flag.FlagSet, visible ...string) {
	shown := map[string]bool{}
	var lines []string
	for _, name := range visible {
		f := fs.Lookup(name)
		if f == nil || shown[name] {
			continue
		}
		shown[name] = true
		lines = append(lines, flagLine(f))
	}
	if len(lines) > 0 {
		fmt.Fprintln(usageWriter, "\noptions:")
		for _, l := range lines {
			fmt.Fprint(usageWriter, l)
		}
	}
	hidden := 0
	fs.VisitAll(func(f *flag.Flag) {
		if !shown[f.Name] && f.Name != allFlagsName {
			hidden++
		}
	})
	if hidden > 0 {
		fmt.Fprintf(usageWriter, "\n%d more option(s) for advanced use: livewire %s -%s\n", hidden, fs.Name(), allFlagsName)
	}
}

// printAllFlags lists every flag, marking the aliases so a reader can tell the
// canonical name from the compatibility spelling.
func printAllFlags(fs *flag.FlagSet, aliases aliasSet) {
	var names []string
	fs.VisitAll(func(f *flag.Flag) {
		if f.Name != allFlagsName {
			names = append(names, f.Name)
		}
	})
	sort.Strings(names)
	fmt.Fprintf(usageWriter, "\nall options for '%s':\n", fs.Name())
	if len(names) == 0 {
		fmt.Fprintln(usageWriter, "  (this command takes no options)")
		return
	}
	for _, n := range names {
		f := fs.Lookup(n)
		line := flagLine(f)
		if aliases[n] {
			line = strings.TrimRight(line, "\n") + "  (alias)\n"
		}
		fmt.Fprint(usageWriter, line)
	}
}

// flagLine renders one flag the way the flag package would, but on two lines
// with the default appended, so long help strings stay readable.
func flagLine(f *flag.Flag) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  -%s", f.Name)
	if name, _ := flag.UnquoteUsage(f); name != "" {
		fmt.Fprintf(&b, " %s", name)
	}
	b.WriteString("\n")
	usage := strings.ReplaceAll(f.Usage, "\n", "\n        ")
	fmt.Fprintf(&b, "        %s", usage)
	if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" && f.DefValue != "[]" {
		fmt.Fprintf(&b, " (default %s)", f.DefValue)
	}
	b.WriteString("\n")
	return b.String()
}

// registerAllFlags adds the -all-flags escape hatch to fs and returns the bool
// it sets. Commands check it after parsing and print the full list.
func registerAllFlags(fs *flag.FlagSet) *bool {
	return fs.Bool(allFlagsName, false, "list every option, including advanced ones and compatibility aliases")
}

// errAllFlags is returned by a command whose only job this run was to print the
// full flag list. main treats it as success with no message.
var errAllFlags = fmt.Errorf("all-flags listed")

// handleAllFlags prints the complete flag list when -all-flags was passed,
// reporting whether the command should stop.
func handleAllFlags(fs *flag.FlagSet, on bool, aliases aliasSet) bool {
	if !on {
		return false
	}
	printAllFlags(fs, aliases)
	return true
}
