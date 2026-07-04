package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/kvmukilan/livewire/internal/ipreasm"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

func cmdConvert(args []string) error {
	fs := flag.NewFlagSet("convert", flag.ContinueOnError)
	inPath := fs.String("in", "", "input pcapng (or pcap) file (required)")
	outPath := fs.String("out", "", "output classic pcap file (required)")
	reassemble := fs.Bool("reassemble", false, "reassemble IPv4 fragments into whole datagrams")
	fs.Usage = func() {
		fmt.Println("usage: livewire convert -in <in.pcapng> -out <out.pcap> [-reassemble]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inPath == "" || *outPath == "" {
		fs.Usage()
		return fmt.Errorf("-in and -out are required")
	}

	in, err := openInput(*inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	if in.isNg && in.ngMixed != nil && in.ngMixed() {
		return pcapio.ErrMixedLinks
	}

	outFile, err := os.Create(*outPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	var w *pcapio.Writer
	var link wire.LinkType
	var frames [][]byte
	n := 0
	// pcapng is treated as nanosecond-resolution; preserve that in the output.
	err = in.eachRecord(func(rec *pcapio.Record) error {
		if w == nil {
			link = rec.LinkType
			w, err = pcapio.NewWriter(outFile, link, true)
			if err != nil {
				return err
			}
		}
		if rec.LinkType != link {
			return pcapio.ErrMixedLinks
		}
		if *reassemble {
			frames = append(frames, append([]byte(nil), rec.Data...))
			return nil
		}
		n++
		return w.Write(rec)
	})
	if err != nil {
		return err
	}

	if *reassemble {
		out, dropped, rerr := ipreasm.ReassembleAll(frames, link)
		if rerr != nil {
			return rerr
		}
		for _, f := range out {
			if werr := w.Write(&pcapio.Record{Data: f, CapLen: len(f), OrigLen: len(f), LinkType: link}); werr != nil {
				return werr
			}
			n++
		}
		if dropped > 0 {
			fmt.Printf("note: %d incomplete fragment set(s) dropped\n", dropped)
		}
	}
	if w != nil {
		if err := w.Flush(); err != nil {
			return err
		}
	}
	fmt.Printf("converted %d packets -> %s (link %s, nanosecond timestamps)\n", n, *outPath, linkName(link))
	return nil
}
