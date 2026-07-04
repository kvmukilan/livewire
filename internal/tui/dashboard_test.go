package tui

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestRenderPlain(t *testing.T) {
	var buf bytes.Buffer
	r := &Renderer{W: &buf, Color: false}
	r.Render(Model{
		Iface:   "eth0",
		Target:  "10.0.0.1:502",
		Elapsed: 1500 * time.Millisecond,
		Flows: []FlowState{
			{Index: 0, Label: "10.0.0.9:5000 -> 10.0.0.1:502 (Modbus)", Phase: "established", Sent: 4, Retransmits: 1, ServerISN: 0xdeadbeef},
			{Index: 1, Label: "10.0.0.9:5001 -> 10.0.0.1:502 (Modbus)", Phase: "closed", Sent: 8},
		},
	})
	out := buf.String()

	for _, want := range []string{
		"livewire", "eth0", "10.0.0.1:502",
		"Modbus", "established", "closed",
		"server ISN learned: 0xdeadbeef",
		"1/2 flow(s) completed",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q in:\n%s", want, out)
		}
	}
	// Colour off => no ANSI escapes in the output.
	if strings.Contains(out, "\x1b[") {
		t.Fatalf("plain render should contain no ANSI escapes:\n%q", out)
	}
}

func TestRenderColorHasEscapes(t *testing.T) {
	var buf bytes.Buffer
	r := &Renderer{W: &buf, Color: true}
	r.Render(Model{Flows: []FlowState{{Index: 0, Label: "x", Phase: "aborted", Note: "peer sent RST"}}})
	out := buf.String()
	if !strings.Contains(out, "\x1b[") {
		t.Fatal("colour render should contain ANSI escapes")
	}
	if !strings.Contains(out, "peer sent RST") {
		t.Fatal("note not rendered")
	}
}

func TestRenderInPlaceRepaint(t *testing.T) {
	var buf bytes.Buffer
	r := &Renderer{W: &buf, Color: true}
	m := Model{Flows: []FlowState{{Index: 0, Label: "x", Phase: "syn-sent"}}}
	r.Render(m)
	first := r.lastLines
	if first == 0 {
		t.Fatal("expected a non-zero line count after first render")
	}
	buf.Reset()
	r.Render(m)
	// The second frame should begin by moving the cursor up over the first.
	if !strings.HasPrefix(buf.String(), "\x1b[") {
		t.Fatalf("second frame should start with a cursor-up escape, got %q", buf.String()[:8])
	}
}

func TestLongLabelTruncated(t *testing.T) {
	var buf bytes.Buffer
	r := &Renderer{W: &buf, Color: false}
	long := strings.Repeat("A", 80)
	r.Render(Model{Flows: []FlowState{{Index: 0, Label: long, Phase: "closed"}}})
	if strings.Contains(buf.String(), long) {
		t.Fatal("over-long label should be truncated")
	}
}
