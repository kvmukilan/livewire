package main

import (
	"errors"
	"flag"
	"fmt"

	"github.com/kvmukilan/livewire/internal/ipreasm"
	"github.com/kvmukilan/livewire/internal/orchestration"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

func cmdConvert(args []string) (retErr error) {
	fs := flag.NewFlagSet("convert", flag.ContinueOnError)
	var inPath string
	fs.StringVar(&inPath, flagIn, "", "input pcapng (or pcap) file")
	var outPath string
	fs.StringVar(&outPath, flagOut, "", "output classic pcap file")
	fs.StringVar(&outPath, "out", "", "alias for -o")
	reassemble := fs.Bool("reassemble", false, "reassemble IPv4 and IPv6 fragments into whole datagrams")
	allFlags := registerAllFlags(fs)
	fs.Usage = func() {
		fmt.Println("usage: livewire convert -in <in.pcapng> -o <out.pcap> [-reassemble]")
		printFlags(fs, flagIn, flagOut, "reassemble")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if handleAllFlags(fs, *allFlags, aliasSet{"out": true}) {
		return errAllFlags
	}
	if inPath == "" || outPath == "" {
		fs.Usage()
		return fmt.Errorf("-in and -o are required")
	}

	in, err := openInput(inPath)
	if err != nil {
		return err
	}
	if in.isNg && in.ngMixed != nil && in.ngMixed() {
		return pcapio.ErrMixedLinks
	}

	af, err := orchestration.CreateArtifact(outPath)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, af.Abort()) }()

	var w *pcapio.Writer
	var link wire.LinkType
	var frames [][]byte
	n := 0
	// pcapng is treated as nanosecond-resolution; preserve that in the output.
	err = in.eachRecord(func(rec *pcapio.Record) error {
		if w == nil {
			link = rec.LinkType
			w, err = pcapio.NewWriter(af, link, true)
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
	if err := af.Commit(); err != nil {
		return err
	}
	fmt.Printf("converted %d packets -> %s (link %s, nanosecond timestamps)\n", n, outPath, linkName(link))
	return nil
}
