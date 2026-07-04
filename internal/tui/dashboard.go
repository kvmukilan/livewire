// Package tui renders a live replay dashboard to a terminal using only ANSI
// escapes and the standard library. It is render-only: no input handling, which
// keeps it testable against any io.Writer.
package tui

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// FlowState is one flow's live status line.
type FlowState struct {
	Index       int
	Label       string // e.g. "10.0.0.9:5000 -> 10.0.0.1:502 (Modbus)"
	Phase       string // init/syn-sent/established/closing/closed/aborted
	Sent        int
	Retransmits int
	ServerISN   uint32 // learned live server ISN (0 until known)
	Note        string // last log line / abort reason
}

// Model is the full dashboard state for one render.
type Model struct {
	Title   string
	Iface   string
	Target  string
	Elapsed time.Duration
	Flows   []FlowState
}

// Renderer draws frames to W. Colour is off for tests so output stays plain.
type Renderer struct {
	W     io.Writer
	Color bool
	// lines drawn by the previous frame, so the next can repaint in place.
	lastLines int
}

const (
	ansiClearLine = "\x1b[2K"
	ansiHome      = "\x1b[G"
)

func (r *Renderer) c(code, s string) string {
	if !r.Color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// phaseColor maps a phase to an ANSI colour code.
func phaseColor(phase string) string {
	switch phase {
	case "closed":
		return "32" // green
	case "aborted":
		return "31" // red
	case "established":
		return "36" // cyan
	default:
		return "33" // yellow (in progress)
	}
}

// Render draws the dashboard, repainting in place when colour is on.
func (r *Renderer) Render(m Model) {
	var b strings.Builder
	if r.Color && r.lastLines > 0 {
		fmt.Fprintf(&b, "\x1b[%dA", r.lastLines) // cursor up N lines
	}

	line := func(format string, args ...any) {
		if r.Color {
			b.WriteString(ansiHome + ansiClearLine)
		}
		fmt.Fprintf(&b, format+"\n", args...)
	}

	title := m.Title
	if title == "" {
		title = "livewire — live stateful replay"
	}
	line("%s", r.c("1", title))
	line("iface %s   target %s   elapsed %s", dash(m.Iface), dash(m.Target), m.Elapsed.Round(time.Millisecond))
	line("%s", strings.Repeat("-", 72))
	line("%-3s %-40s %-12s %6s %5s", "id", "flow", "phase", "sent", "rtx")

	flows := append([]FlowState(nil), m.Flows...)
	sort.SliceStable(flows, func(i, j int) bool { return flows[i].Index < flows[j].Index })
	okCount := 0
	for _, f := range flows {
		if f.Phase == "closed" {
			okCount++
		}
		label := f.Label
		if len(label) > 40 {
			label = label[:39] + "…"
		}
		line("%-3d %-40s %-12s %6d %5d", f.Index, label, r.c(phaseColor(f.Phase), f.Phase), f.Sent, f.Retransmits)
		if f.ServerISN != 0 {
			line("      server ISN learned: 0x%08x", f.ServerISN)
		}
		if f.Note != "" {
			line("      %s", f.Note)
		}
	}
	line("%s", strings.Repeat("-", 72))
	line("%d/%d flow(s) completed", okCount, len(flows))

	// count drawn lines for the next in-place repaint
	out := b.String()
	io.WriteString(r.W, out)
	r.lastLines = strings.Count(strings.TrimSuffix(afterCursorMove(out), "\n"), "\n") + 1
}

// afterCursorMove strips a leading "\x1b[NA" cursor-up sequence.
func afterCursorMove(s string) string {
	if !strings.HasPrefix(s, "\x1b[") {
		return s
	}
	if i := strings.IndexByte(s, 'A'); i >= 0 && i < 8 {
		return s[i+1:]
	}
	return s
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
