package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/livereplay"
)

const maxShownDivergences = 6

// printVerdict writes the plain-language verdict to stdout.
func printVerdict(label string, res livereplay.Result) { fprintVerdict(os.Stdout, label, res) }

// fprintVerdict writes a plain-language pass/fail summary of one flow's replay,
// framed around the question a peer actually has: did my device behave the same
// as the recording? label prefixes the block (e.g. "Connection 2") or is empty.
func fprintVerdict(w io.Writer, label string, res livereplay.Result) {
	out := res.Outcome
	fmt.Fprintln(w)
	if label != "" {
		fmt.Fprintf(w, "---- %s ----\n", label)
	} else {
		fmt.Fprintln(w, "--------------------------------")
	}
	switch {
	case out.Succeeded() && out.RepliesMatched():
		fmt.Fprintln(w, "RESULT: SAME AS THE RECORDING.")
		fmt.Fprintln(w, "The device behaved exactly as it did when the capture was taken.")
		fmt.Fprintln(w, "If the recording shows the problem, the problem reproduces on this device.")
	case out.Succeeded() && !out.RepliesMatched():
		fmt.Fprintln(w, "RESULT: DIFFERENT FROM THE RECORDING.")
		fmt.Fprintln(w, "The exchange completed, but the device answered differently:")
		fprintDivergences(w, out)
		fmt.Fprintln(w, "The recorded behavior did NOT reproduce here — likely a different device")
		fmt.Fprintln(w, "state, firmware, or register contents (or it has already been fixed).")
	default:
		fmt.Fprintln(w, "RESULT: THE EXCHANGE DID NOT COMPLETE.")
		fmt.Fprintf(w, "What happened: %s\n", plainReason(out))
		fprintDivergences(w, out)
	}
	fmt.Fprintln(w, "--------------------------------")
}

// fprintDivergences lists up to a few reply differences in the device's own terms.
func fprintDivergences(w io.Writer, out engine.Outcome) {
	shown := 0
	for _, m := range out.Mismatches {
		if shown >= maxShownDivergences {
			fmt.Fprintf(w, "  ...and %d more\n", len(out.Mismatches)-shown)
			break
		}
		fmt.Fprintf(w, "  - %s\n", m.Detail)
		shown++
	}
}

// plainReason turns an internal abort reason into a non-technical sentence.
func plainReason(out engine.Outcome) string {
	r := out.Reason
	switch {
	case strings.Contains(r, "RST"):
		return "the device reset (refused) the connection"
	case strings.Contains(r, "stalled"), strings.Contains(r, "retransmit"):
		return "the device stopped responding partway through the exchange"
	case strings.Contains(r, "exceeded"):
		return "the exchange ran longer than expected and was stopped"
	case r == "":
		return "the connection ended in state " + out.Phase.String()
	default:
		return r
	}
}
