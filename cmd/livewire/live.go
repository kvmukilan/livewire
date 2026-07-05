package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/tui"
)

// isTerminal reports whether f is a TTY, to decide whether to emit ANSI colour.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func cmdLive(args []string) error {
	fs := flag.NewFlagSet("live", flag.ContinueOnError)
	inPath := fs.String("in", "", "input pcap/pcapng file (required)")
	dryRun := fs.Bool("dry-run", true, "simulate replay with no NIC")
	mode := fs.String("mode", "both", "dry-run mode: rewrite | peer | both")
	seed := fs.Int64("seed", 1, "seed for reproducible live ISN/timestamp selection")
	outPath := fs.String("out", "", "write the rewritten capture to this pcap (rewrite mode)")
	flowSel := fs.Int("flow", -1, "only analyze this flow index (-1 = all)")
	verbose := fs.Bool("v", false, "print the per-packet sequence-rewrite table")
	iface := fs.String("iface", "", "interface for live replay (real path; implies -dry-run=false)")
	target := fs.String("target", "", "live target ip[:port] (default: the captured server endpoint)")
	noGuard := fs.Bool("no-rst-guard", false, "do not install host-RST suppression (host kernel may reset the flow)")
	useTUI := fs.Bool("tui", false, "render a live status dashboard instead of the per-flow text report")
	allFlows := fs.Bool("all", false, "replay every flow in the capture, each stateful, one after another")
	fs.Usage = func() {
		fmt.Println("usage:")
		fmt.Println("  dry-run:  livewire live -in <file> [-mode rewrite|peer|both] [-seed N] [-out rewritten.pcap] [-v]")
		fmt.Println("  live:     livewire live -in <file> -iface <name> [-target ip[:port]] [-flow N] [-no-rst-guard]")
		fmt.Println("\nStateful TCP replay. Learns the live peer's ISN and realigns seq/ack per flow.")
		fmt.Println("Protocol-agnostic (Modbus, DNP3, HTTP, ...): only TCP headers are rewritten.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inPath == "" {
		fs.Usage()
		return fmt.Errorf("-in is required")
	}
	// Supplying -iface selects the real on-wire path.
	realLive := *iface != "" || !*dryRun

	in, err := openInput(*inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	var recs []*pcapio.Record
	if err := in.eachRecord(func(rec *pcapio.Record) error {
		// Copy: parsing/rewriting aliases Data and we keep every record.
		cp := *rec
		recs = append(recs, &cp)
		return nil
	}); err != nil {
		return err
	}

	flows := engine.ExtractFlows(recs)
	if len(flows) == 0 {
		return fmt.Errorf("no TCP flows found in %s", *inPath)
	}
	fmt.Printf("found %d TCP flow(s) in %s\n\n", len(flows), *inPath)

	if realLive {
		if *iface == "" {
			return fmt.Errorf("live replay needs -iface (the interface to transmit on)")
		}
		if *allFlows {
			return liveAll(flows, *target, *iface, *seed, *noGuard, *verbose)
		}
		return liveReal(flows, *flowSel, *target, *iface, *seed, *noGuard, *useTUI, *verbose)
	}

	opts := engine.Options{Seed: *seed}
	var allFrames []pcapio.Record
	var tuiStates []tuiFlowState
	okCount, totalCount := 0, 0

	for i, f := range flows {
		if *flowSel >= 0 && i != *flowSel {
			continue
		}
		totalCount++
		proto := engine.ProtocolGuess(f.Server.Port, f.Client.Port)
		label := fmt.Sprintf("%s -> %s (%s)", f.Client, f.Server, proto)
		fmt.Printf("flow %d: %s <-> %s  (%s)  %d packets\n", i, f.Client, f.Server, proto, len(f.Packets))
		if !f.HasSyn || !f.HasSynAck {
			fmt.Printf("  SKIP: capture lacks a full handshake (SYN=%v SYN-ACK=%v) — cannot anchor ISNs\n\n", f.HasSyn, f.HasSynAck)
			tuiStates = append(tuiStates, tuiFlowState{Index: i, Label: label, Phase: "aborted", Note: "no handshake to anchor ISNs"})
			continue
		}

		flowOK := true
		st := tuiFlowState{Index: i, Label: label, Phase: "closed"}

		if *mode == "rewrite" || *mode == "both" {
			rep, err := engine.SimulateRewrite(f, opts)
			if err != nil {
				return err
			}
			aligned := 0
			for _, r := range rep.Rows {
				if r.AckAligned {
					aligned++
				}
			}
			status := "CONSISTENT"
			if !rep.Consistent() {
				status = fmt.Sprintf("INCONSISTENT (%d anomalies)", rep.Anomalies)
				flowOK = false
			}
			fmt.Printf("  captured ISNs:   client=0x%08x server=0x%08x\n", f.CapClientISN.Uint32(), f.CapServerISN.Uint32())
			fmt.Printf("  live ISNs:       client=0x%08x server=0x%08x  (delta client=0x%08x server=0x%08x)\n",
				rep.LiveClientISN, rep.LiveServerISN, rep.ClientDelta, rep.ServerDelta)
			fmt.Printf("  rewrite dry-run: %s  [%d/%d acks aligned]\n", status, aligned, len(rep.Rows))
			if *verbose {
				printRewriteTable(rep)
			}
			allFrames = append(allFrames, rep.Frames...)
		}

		if *mode == "peer" || *mode == "both" {
			rep, err := engine.LiveDryRun(f, opts)
			if err != nil {
				return err
			}
			inSync := len(rep.Rows) - rep.Mismatches
			status := "SUCCESS"
			if !rep.Succeeded() {
				status = fmt.Sprintf("FAILED (%d mismatches)", rep.Mismatches)
				flowOK = false
			}
			recovered := "no"
			if rep.LearnedServerISN == rep.PeerServerISN {
				recovered = "yes"
			}
			fmt.Printf("  peer dry-run:    %s  handshake=%v, server-ISN recovered=%s (peer chose 0x%08x, engine learned 0x%08x), %d/%d packets in sync\n",
				status, rep.HandshakeOK, recovered, rep.PeerServerISN, rep.LearnedServerISN, inSync, len(rep.Rows))
			st.Sent = len(rep.Rows)
			st.ServerISN = rep.LearnedServerISN
			if !rep.Succeeded() {
				st.Note = fmt.Sprintf("%d packet(s) out of sync", rep.Mismatches)
			}
		}

		if !flowOK {
			st.Phase = "aborted"
		}
		tuiStates = append(tuiStates, st)
		if flowOK {
			okCount++
		}
		fmt.Println()
	}

	if *outPath != "" && len(allFrames) > 0 {
		if err := writeFrames(*outPath, allFrames, in.nanos); err != nil {
			return err
		}
		fmt.Printf("wrote %d rewritten frames -> %s (open in Wireshark to verify seq/ack)\n", len(allFrames), *outPath)
	}

	fmt.Printf("summary: %d/%d analyzed flow(s) maintain sequence numbers coherently\n", okCount, totalCount)

	if *useTUI {
		fmt.Println()
		renderDashboard("(dry-run)", "(simulated peer)", tuiStates)
	}
	return nil
}

// tuiFlowState aliases the renderer's flow row.
type tuiFlowState = tui.FlowState

// renderDashboard prints the live-status dashboard; colour only on a TTY.
func renderDashboard(iface, target string, states []tuiFlowState) {
	r := &tui.Renderer{W: os.Stdout, Color: isTerminal(os.Stdout)}
	r.Render(tui.Model{Iface: iface, Target: target, Flows: states})
}

func printRewriteTable(rep *engine.RewriteReport) {
	fmt.Printf("    %-3s %-4s %-6s %-21s %-21s %s\n", "idx", "dir", "flags", "seq (cap -> live)", "ack (cap -> live)", "ack ok")
	for _, r := range rep.Rows {
		ackCol := "-"
		if r.AckSet {
			ackCol = fmt.Sprintf("%08x -> %08x", r.CapAck, r.LiveAck)
		}
		ok := "ok"
		if r.AckSet && !r.AckAligned {
			ok = "BAD: " + r.Note
		}
		fmt.Printf("    %-3d %-4s %-6s %08x -> %08x    %-21s %s\n",
			r.Index, r.Dir, r.Flags, r.CapSeq, r.LiveSeq, ackCol, ok)
	}
}

func writeFrames(path string, frames []pcapio.Record, nanos bool) error {
	sort.SliceStable(frames, func(i, j int) bool { return frames[i].Time.Before(frames[j].Time) })
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w, err := pcapio.NewWriter(f, frames[0].LinkType, nanos)
	if err != nil {
		return err
	}
	for i := range frames {
		if err := w.Write(&frames[i]); err != nil {
			return err
		}
	}
	return w.Flush()
}
