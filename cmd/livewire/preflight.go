package main

import (
	"fmt"

	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/engine"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/wire"
)

type preflightFinding struct {
	Severity string `json:"severity"` // info | warning | blocker
	Code     string `json:"code"`
	Detail   string `json:"detail"`
}

type preflightReport struct {
	Confidence int                `json:"confidence"`
	Packets    int                `json:"packets"`
	TCPFlows   int                `json:"tcpFlows"`
	Sessions   int                `json:"sessions"`
	UDP        int                `json:"udpSessions"`
	ICMP       int                `json:"icmpSessions"`
	RawFrames  int                `json:"rawFrames"`
	Findings   []preflightFinding `json:"findings,omitempty"`
}

func assessCapture(recs []*pcapio.Record, flows []*engine.Flow) preflightReport {
	trace := replay.ExtractTrace(recs, replay.ExtractOptions{})
	r := preflightReport{Confidence: 100, Packets: len(recs), TCPFlows: len(flows), Sessions: len(trace.Sessions), RawFrames: len(trace.Raw)}
	reassembledFragments := 0
	for _, s := range trace.Sessions {
		if s.Fragmented {
			for _, e := range s.Events {
				if e.Fragmented {
					reassembledFragments++
				}
			}
		}
		switch s.Transport {
		case replay.TransportUDP:
			r.UDP++
		case replay.TransportICMP4, replay.TransportICMP6:
			r.ICMP++
		}
	}
	add := func(severity, code, detail string, penalty int) {
		r.Findings = append(r.Findings, preflightFinding{Severity: severity, Code: code, Detail: detail})
		r.Confidence -= penalty
	}

	var truncated, fragments, parseErrors, nonTCP int
	for _, rec := range recs {
		if rec.OrigLen > rec.CapLen || len(rec.Data) < rec.OrigLen {
			truncated++
		}
		p, err := wire.Parse(rec.Data, rec.LinkType)
		if err != nil {
			parseErrors++
			continue
		}
		if p.IsFragment() {
			fragments++
		}
		if !p.IsTCP() {
			nonTCP++
		}
	}
	if truncated > 0 {
		add("blocker", "truncated-packets", fmt.Sprintf("%d packet(s) were snaplen-truncated; payload bytes are missing", truncated), 30)
	}
	if parseErrors > 0 {
		add("warning", "unparsed-packets", fmt.Sprintf("%d packet(s) could not be decoded", parseErrors), 10)
	}
	if fragments > 0 {
		add("warning", "ip-fragments", fmt.Sprintf("%d IP fragment(s) found; %d belong to complete sets reassembled for classification, while incomplete sets remain explicit wire lanes", fragments, reassembledFragments), 10)
	}
	if nonTCP > 0 {
		add("info", "non-tcp-traffic", fmt.Sprintf("%d non-TCP packet(s) classified into UDP, ICMP, or explicit wire lanes", nonTCP), 0)
	}
	if len(trace.Raw) > 0 {
		add("warning", "wire-only-frames", fmt.Sprintf("%d frame(s) have no stateful model and are explicitly limited to wire replay", len(trace.Raw)), 5)
	}

	missingHandshake, retransmits, encrypted := 0, 0, 0
	for i, f := range flows {
		if !f.HasSyn || !f.HasSynAck {
			missingHandshake++
		}
		seen := map[string]bool{}
		var clientPayload []byte
		for _, cp := range f.Packets {
			if cp.Dir != engine.C2S {
				continue
			}
			if cp.PayloadLen > 0 {
				p, err := wire.Parse(cp.Rec.Data, cp.Rec.LinkType)
				if err == nil {
					payload := p.Payload()
					if cp.PayloadLen <= len(payload) {
						clientPayload = append(clientPayload, payload[:cp.PayloadLen]...)
					}
				}
			}
			if cp.SegLen > 0 {
				key := fmt.Sprintf("%d/%d", cp.Seq.Uint32(), cp.SegLen)
				if seen[key] && !cp.IsSyn {
					retransmits++
				}
				seen[key] = true
			}
		}
		if dissect.DetectSSH(clientPayload) || dissect.DetectTLS(clientPayload).IsTLS {
			encrypted++
			add("blocker", "encrypted-flow", fmt.Sprintf("flow %d is TLS/SSH; captured ciphertext cannot reproduce a fresh authenticated session", i), 20)
		}
		if frames, _, err := dissect.ParseDNP3Stream(clientPayload); err == nil {
			for _, frame := range frames {
				if frame.UsesSecureAuth() {
					encrypted++
					add("blocker", "dnp3-secure-auth", fmt.Sprintf("flow %d uses DNP3 Secure Authentication; live nonces make captured authentication data invalid", i), 20)
					break
				}
			}
		}
	}
	if missingHandshake > 0 {
		add("warning", "missing-handshake", fmt.Sprintf("%d flow(s) start mid-session; livewire must synthesize a best-effort handshake", missingHandshake), 15)
	}
	if retransmits > 0 {
		add("info", "captured-retransmissions", fmt.Sprintf("%d repeated client segment(s) detected; use the transport profile if they trigger the issue", retransmits), 0)
	}
	if encrypted == 0 {
		add("info", "payload-replayable", "client payloads are available for application-level replay and comparison", 0)
	}
	if r.Confidence < 0 {
		r.Confidence = 0
	}
	return r
}

func printPreflight(r preflightReport) {
	fmt.Printf("Preflight: %d%% replay confidence (%d packets, %d session(s): %d TCP, %d UDP, %d ICMP; %d raw)\n",
		r.Confidence, r.Packets, r.Sessions, r.TCPFlows, r.UDP, r.ICMP, r.RawFrames)
	for _, f := range r.Findings {
		mark := "note"
		if f.Severity == "warning" {
			mark = "warning"
		} else if f.Severity == "blocker" {
			mark = "BLOCKER"
		}
		fmt.Printf("  %-7s %s\n", mark+":", f.Detail)
	}
}
