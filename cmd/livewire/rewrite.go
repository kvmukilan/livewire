package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/kvmukilan/livewire/internal/edit"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

func cmdRewrite(args []string) error {
	fs := flag.NewFlagSet("rewrite", flag.ContinueOnError)
	inPath := fs.String("in", "", "input pcap/pcapng file (required)")
	outPath := fs.String("out", "", "output classic pcap file (required)")
	srcMAC := fs.String("srcmac", "", "rewrite source MAC (aa:bb:cc:dd:ee:ff)")
	dstMAC := fs.String("dstmac", "", "rewrite destination MAC")
	var pnat, srcMap, dstMap, portMap stringSlice
	fs.Var(&pnat, "pnat", "pseudo-NAT both endpoints: MATCH_CIDR,REWRITE_CIDR (repeatable)")
	fs.Var(&srcMap, "srcipmap", "pseudo-NAT source only: MATCH_CIDR,REWRITE_CIDR (repeatable)")
	fs.Var(&dstMap, "dstipmap", "pseudo-NAT destination only: MATCH_CIDR,REWRITE_CIDR (repeatable)")
	fs.Var(&portMap, "portmap", "remap TCP/UDP port FROM:TO (repeatable)")
	ttl := fs.Int("ttl", -1, "set IPv4 TTL / IPv6 hop limit (-1 = leave unchanged)")
	seqShift := fs.Uint("tcp-seq-shift", 0, "add a uniform offset to every TCP seq and ack")
	vlanAdd := fs.Int("vlan-add", -1, "push an 802.1Q VLAN tag with this VID (-1 = none)")
	vlanPCP := fs.Int("vlan-pcp", 0, "PCP for -vlan-add")
	vlanDel := fs.Bool("vlan-del", false, "strip all VLAN tags")
	fixcsum := fs.Bool("fixcsum", false, "recompute all checksums even when no field changed")
	fs.Usage = func() {
		fmt.Println("usage: livewire rewrite -in <in> -out <out> [edit flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inPath == "" || *outPath == "" {
		fs.Usage()
		return fmt.Errorf("-in and -out are required")
	}

	rules := &edit.Rules{PortMap: map[uint16]uint16{}}
	if *srcMAC != "" {
		m, err := parseMAC(*srcMAC)
		if err != nil {
			return err
		}
		rules.SrcMAC = &m
	}
	if *dstMAC != "" {
		m, err := parseMAC(*dstMAC)
		if err != nil {
			return err
		}
		rules.DstMAC = &m
	}
	for _, s := range pnat {
		m, err := parseIPMap(s)
		if err != nil {
			return err
		}
		rules.SrcIPMap = append(rules.SrcIPMap, m)
		rules.DstIPMap = append(rules.DstIPMap, m)
	}
	for _, s := range srcMap {
		m, err := parseIPMap(s)
		if err != nil {
			return err
		}
		rules.SrcIPMap = append(rules.SrcIPMap, m)
	}
	for _, s := range dstMap {
		m, err := parseIPMap(s)
		if err != nil {
			return err
		}
		rules.DstIPMap = append(rules.DstIPMap, m)
	}
	for _, s := range portMap {
		f, t, err := parsePortMap(s)
		if err != nil {
			return err
		}
		rules.PortMap[f] = t
	}
	if *ttl >= 0 {
		v := uint8(*ttl)
		rules.TTL = &v
	}
	rules.SeqShift = uint32(*seqShift)
	if *vlanDel {
		rules.StripVLAN = true
	}
	if *vlanAdd >= 0 {
		rules.PushVLAN = &edit.VLANTag{VID: uint16(*vlanAdd), PCP: uint8(*vlanPCP)}
	}

	in, err := openInput(*inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	outFile, err := os.Create(*outPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	var w *pcapio.Writer
	var link wire.LinkType
	edited := 0
	total := 0
	err = in.eachRecord(func(rec *pcapio.Record) error {
		total++
		if w == nil {
			link = rec.LinkType
			w, err = pcapio.NewWriter(outFile, link, in.nanos)
			if err != nil {
				return err
			}
		}
		origCap := len(rec.Data)
		buf := rules.PreTransform(rec.Data)
		p, perr := wire.Parse(buf, rec.LinkType)
		if perr == nil {
			if rules.Apply(p) {
				edited++
			} else if *fixcsum {
				p.RecalcChecksums()
			}
		}
		// Account for length change from VLAN edits.
		delta := len(buf) - origCap
		rec.Data = buf
		rec.CapLen = len(buf)
		rec.OrigLen += delta
		return w.Write(rec)
	})
	if err != nil {
		return err
	}
	if w != nil {
		if err := w.Flush(); err != nil {
			return err
		}
	}
	fmt.Printf("rewrote %d/%d packets -> %s (link %s)\n", edited, total, *outPath, linkName(link))
	return nil
}
