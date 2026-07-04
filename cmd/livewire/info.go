package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/kvmukilan/livewire/internal/flow"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

func cmdInfo(args []string) error {
	fs := flag.NewFlagSet("info", flag.ContinueOnError)
	verbose := fs.Bool("v", false, "verbose: include checksum validation")
	fs.Usage = func() {
		fmt.Println("usage: livewire info [-v] <file.pcap|file.pcapng>")
		fs.PrintDefaults()
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
	defer in.Close()

	var (
		count                     int
		tcpN, udpN, otherN        int
		v4N, v6N, nonIP           int
		fragN                     int
		synN, synAckN, rstN, finN int
		minLen, maxLen            = 1 << 30, 0
		totLen                    int64
		truncated                 int
		badIP, badL4              int
		firstTS, lastTS           time.Time
		links                     = map[wire.LinkType]int{}
		flows                     = map[flow.Key]struct{}{}
	)

	err = in.eachRecord(func(rec *pcapio.Record) error {
		count++
		links[rec.LinkType]++
		if rec.CapLen < rec.OrigLen {
			truncated++
		}
		if rec.CapLen < minLen {
			minLen = rec.CapLen
		}
		if rec.CapLen > maxLen {
			maxLen = rec.CapLen
		}
		totLen += int64(rec.CapLen)
		if !rec.Time.IsZero() {
			if firstTS.IsZero() || rec.Time.Before(firstTS) {
				firstTS = rec.Time
			}
			if rec.Time.After(lastTS) {
				lastTS = rec.Time
			}
		}

		p, perr := wire.Parse(rec.Data, rec.LinkType)
		if perr != nil {
			nonIP++
			return nil
		}
		switch {
		case p.IsIPv4():
			v4N++
		case p.IsIPv6():
			v6N++
		default:
			nonIP++
		}
		if p.IsFragment() {
			fragN++
		}
		switch {
		case p.IsTCP():
			tcpN++
			if p.HasFlags(wire.FlagSYN) && p.HasFlags(wire.FlagACK) {
				synAckN++
			} else if p.HasFlags(wire.FlagSYN) {
				synN++
			}
			if p.HasFlags(wire.FlagRST) {
				rstN++
			}
			if p.HasFlags(wire.FlagFIN) {
				finN++
			}
		case p.IsUDP():
			udpN++
		default:
			otherN++
		}
		if key, _, ok := flow.KeyFromPacket(p); ok {
			flows[key] = struct{}{}
		}
		if *verbose {
			if ipOK, l4OK := p.VerifyChecksums(); true {
				if !ipOK {
					badIP++
				}
				if !l4OK {
					badL4++
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	format := "classic pcap"
	if in.isNg {
		format = "pcapng"
		if in.ngMixed != nil && in.ngMixed() {
			format += " (mixed link types)"
		}
	}

	fmt.Printf("file format:     %s\n", format)
	fmt.Printf("link type(s):    %s\n", linkSummary(links))
	fmt.Printf("timestamps:      %s resolution\n", tsRes(in.nanos))
	fmt.Printf("packets:         %d\n", count)
	if count > 0 {
		fmt.Printf("capture length:  min %d, max %d, avg %d bytes\n", minLen, maxLen, totLen/int64(count))
	}
	if truncated > 0 {
		fmt.Printf("truncated:       %d (caplen < origlen)\n", truncated)
	}
	if !firstTS.IsZero() {
		fmt.Printf("time span:       %s -> %s (%s)\n",
			firstTS.Format(time.RFC3339Nano), lastTS.Format(time.RFC3339Nano), lastTS.Sub(firstTS))
	}
	fmt.Printf("network:         IPv4 %d, IPv6 %d, non-IP %d\n", v4N, v6N, nonIP)
	if fragN > 0 {
		fmt.Printf("ip fragments:    %d (reassemble with 'convert -reassemble')\n", fragN)
	}
	fmt.Printf("transport:       TCP %d, UDP %d, other %d\n", tcpN, udpN, otherN)
	fmt.Printf("tcp handshakes:  SYN %d, SYN-ACK %d, RST %d, FIN %d\n", synN, synAckN, rstN, finN)
	fmt.Printf("distinct flows:  %d\n", len(flows))
	if *verbose {
		fmt.Printf("bad checksums:   IP %d, transport %d\n", badIP, badL4)
	}
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
