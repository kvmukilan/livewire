package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/netip"
	"os"

	"github.com/kvmukilan/livewire/internal/classify"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

func cmdPrep(args []string) error {
	fs := flag.NewFlagSet("prep", flag.ContinueOnError)
	inPath := fs.String("in", "", "input pcap/pcapng file (required)")
	outPath := fs.String("out", "", "output cache file (required)")
	mode := fs.String("mode", "auto", "classification mode: auto | port | cidr")
	var clientCIDRs stringSlice
	fs.Var(&clientCIDRs, "client-cidr", "client network for cidr mode (repeatable)")
	comment := fs.String("comment", "", "comment stored in the cache header")
	fs.Usage = func() {
		fmt.Println("usage: livewire prep -in <in> -out <cache> [-mode auto|port|cidr] [-client-cidr CIDR]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inPath == "" || *outPath == "" {
		fs.Usage()
		return fmt.Errorf("-in and -out are required")
	}

	c := &classify.Classifier{}
	switch *mode {
	case "auto":
		c.Mode = classify.ModeAuto
	case "port":
		c.Mode = classify.ModePort
	case "cidr":
		c.Mode = classify.ModeClientCIDR
		for _, s := range clientCIDRs {
			pfx, err := netip.ParsePrefix(s)
			if err != nil {
				return fmt.Errorf("client-cidr %q: %w", s, err)
			}
			c.ClientNets = append(c.ClientNets, pfx)
		}
		if len(c.ClientNets) == 0 {
			return fmt.Errorf("cidr mode requires at least one -client-cidr")
		}
	default:
		return fmt.Errorf("unknown mode %q", *mode)
	}

	in, err := openInput(*inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	var pkts []*wire.Packet
	err = in.eachRecord(func(rec *pcapio.Record) error {
		p, perr := wire.Parse(rec.Data, rec.LinkType)
		if perr != nil {
			pkts = append(pkts, nil) // keep index alignment with file order
			return nil
		}
		pkts = append(pkts, p)
		return nil
	})
	if err != nil {
		return err
	}

	cache := c.Classify(pkts)
	outFile, err := os.Create(*outPath)
	if err != nil {
		return err
	}
	defer outFile.Close()
	bw := bufio.NewWriter(outFile)
	if err := classify.WriteCache(bw, cache, *comment); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}

	pri, sec, none := cache.Counts()
	fmt.Printf("classified %d packets -> %s (primary/client %d, secondary/server %d, none %d)\n",
		cache.Len(), *outPath, pri, sec, none)
	return nil
}
