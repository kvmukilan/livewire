package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/kvmukilan/livewire/internal/flow"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

// captureStats is a read-only tally of what a capture file contains. It answers
// "is this the traffic I expected?" before anything is replayed.
type captureStats struct {
	format                    string
	count                     int
	tcpN, udpN, otherN        int
	v4N, v6N, nonIP           int
	fragN                     int
	synN, synAckN, rstN, finN int
	minLen, maxLen            int
	totLen                    int64
	truncated                 int
	badIP, badL4              int
	nanos                     bool
	firstTS, lastTS           time.Time
	links                     map[wire.LinkType]int
	flows                     int
}

// scanCapture walks every record once and tallies it. checksums adds per-packet
// checksum validation, which costs a pass over each payload, so it is opt-in.
func scanCapture(in *input, checksums bool) (captureStats, error) {
	s := captureStats{minLen: 1 << 30, links: map[wire.LinkType]int{}, nanos: in.nanos}
	flows := map[flow.Key]struct{}{}

	err := in.eachRecord(func(rec *pcapio.Record) error {
		s.count++
		s.links[rec.LinkType]++
		if rec.CapLen < rec.OrigLen {
			s.truncated++
		}
		if rec.CapLen < s.minLen {
			s.minLen = rec.CapLen
		}
		if rec.CapLen > s.maxLen {
			s.maxLen = rec.CapLen
		}
		s.totLen += int64(rec.CapLen)
		if !rec.Time.IsZero() {
			if s.firstTS.IsZero() || rec.Time.Before(s.firstTS) {
				s.firstTS = rec.Time
			}
			if rec.Time.After(s.lastTS) {
				s.lastTS = rec.Time
			}
		}

		p, perr := wire.Parse(rec.Data, rec.LinkType)
		if perr != nil {
			s.nonIP++
			return nil
		}
		switch {
		case p.IsIPv4():
			s.v4N++
		case p.IsIPv6():
			s.v6N++
		default:
			s.nonIP++
		}
		if p.IsFragment() {
			s.fragN++
		}
		switch {
		case p.IsTCP():
			s.tcpN++
			if p.HasFlags(wire.FlagSYN) && p.HasFlags(wire.FlagACK) {
				s.synAckN++
			} else if p.HasFlags(wire.FlagSYN) {
				s.synN++
			}
			if p.HasFlags(wire.FlagRST) {
				s.rstN++
			}
			if p.HasFlags(wire.FlagFIN) {
				s.finN++
			}
		case p.IsUDP():
			s.udpN++
		default:
			s.otherN++
		}
		if key, _, ok := flow.KeyFromPacket(p); ok {
			flows[key] = struct{}{}
		}
		if checksums {
			ipOK, l4OK := p.VerifyChecksums()
			if !ipOK {
				s.badIP++
			}
			if !l4OK {
				s.badL4++
			}
		}
		return nil
	})
	if err != nil {
		return captureStats{}, err
	}

	s.flows = len(flows)
	s.format = "classic pcap"
	if in.isNg {
		s.format = "pcapng"
		if in.ngMixed != nil && in.ngMixed() {
			s.format += " (mixed link types)"
		}
	}
	return s, nil
}

// printCaptureStats writes the capture summary. checksums must match what was
// passed to scanCapture; otherwise the counts would read as zero bad checksums
// when in fact none were computed.
func printCaptureStats(s captureStats, checksums bool) {
	fmt.Printf("file format:     %s\n", s.format)
	fmt.Printf("link type(s):    %s\n", linkSummary(s.links))
	fmt.Printf("timestamps:      %s resolution\n", tsRes(s.nanos))
	fmt.Printf("packets:         %d\n", s.count)
	if s.count > 0 {
		fmt.Printf("capture length:  min %d, max %d, avg %d bytes\n", s.minLen, s.maxLen, s.totLen/int64(s.count))
	}
	if s.truncated > 0 {
		fmt.Printf("truncated:       %d (caplen < origlen)\n", s.truncated)
	}
	if !s.firstTS.IsZero() {
		fmt.Printf("time span:       %s -> %s (%s)\n",
			s.firstTS.Format(time.RFC3339Nano), s.lastTS.Format(time.RFC3339Nano), s.lastTS.Sub(s.firstTS))
	}
	fmt.Printf("network:         IPv4 %d, IPv6 %d, non-IP %d\n", s.v4N, s.v6N, s.nonIP)
	if s.fragN > 0 {
		fmt.Printf("ip fragments:    %d (reassemble with 'convert -reassemble')\n", s.fragN)
	}
	fmt.Printf("transport:       TCP %d, UDP %d, other %d\n", s.tcpN, s.udpN, s.otherN)
	fmt.Printf("tcp handshakes:  SYN %d, SYN-ACK %d, RST %d, FIN %d\n", s.synN, s.synAckN, s.rstN, s.finN)
	fmt.Printf("distinct flows:  %d\n", s.flows)
	if checksums {
		fmt.Printf("bad checksums:   IP %d, transport %d\n", s.badIP, s.badL4)
	}
}

// cmdInfo is the compatibility entry point for the merged 'check' command: it
// prints the capture summary alone, exactly as it always has.
func cmdInfo(args []string) error {
	fs := flag.NewFlagSet("info", flag.ContinueOnError)
	verbose := fs.Bool("v", false, "verbose: include checksum validation")
	fs.Usage = func() {
		fmt.Println("usage: livewire info [-v] <file.pcap|file.pcapng>")
		fmt.Println("\n'info' is now part of 'check', which also reports whether the capture")
		fmt.Println("can be replayed. This spelling keeps working and prints the summary only.")
		printFlags(fs, "v")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("expected exactly one input file")
	}

	in, err := openInput(fs.Arg(0))
	if err != nil {
		return err
	}
	stats, err := scanCapture(in, *verbose)
	if err != nil {
		return err
	}
	printCaptureStats(stats, *verbose)
	return nil
}

func linkSummary(links map[wire.LinkType]int) string {
	if len(links) == 0 {
		return "none"
	}
	s := ""
	for lt, n := range links {
		if s != "" {
			s += ", "
		}
		s += fmt.Sprintf("%s (%d)", linkName(lt), n)
	}
	return s
}

func linkName(lt wire.LinkType) string {
	switch lt {
	case wire.LinkEthernet:
		return "Ethernet"
	case wire.LinkRaw:
		return "RawIP"
	case wire.LinkNull:
		return "Null/Loopback"
	case wire.LinkLinuxSLL:
		return "LinuxSLL"
	case wire.LinkLoop:
		return "OpenBSDLoop"
	default:
		return fmt.Sprintf("DLT%d", uint16(lt))
	}
}

func tsRes(nanos bool) string {
	if nanos {
		return "nanosecond"
	}
	return "microsecond"
}
