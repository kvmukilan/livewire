package main

import (
	"flag"
	"fmt"

	"github.com/kvmukilan/livewire/internal/supportbundle"
)

func cmdBundle(args []string) error {
	fs := flag.NewFlagSet("bundle", flag.ContinueOnError)
	report := fs.String("report", "", "Livewire JSON run report (required)")
	var out string
	fs.StringVar(&out, flagOut, "", "output support ZIP (must not already exist)")
	fs.StringVar(&out, "out", "", "alias for -o")
	var evidence fileFlags
	fs.Var(&evidence, "evidence", "evidence PCAP/PCAPNG to reference by digest, never embed (repeatable)")
	allFlags := registerAllFlags(fs)
	fs.Usage = func() {
		fmt.Println("usage: livewire bundle -report run.json [-evidence actual.pcapng] -o support.zip")
		fmt.Println("\nCreates a redacted support archive. Packet evidence is referenced by digest only because captures can contain credentials.")
		printFlags(fs, "report", flagOut, "evidence")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if handleAllFlags(fs, *allFlags, aliasSet{"out": true}) {
		return errAllFlags
	}
	if *report == "" || out == "" {
		fs.Usage()
		return fmt.Errorf("-report and -o are required")
	}
	manifest, err := supportbundle.Create(supportbundle.Options{ReportPath: *report, EvidencePaths: evidence, OutputPath: out, Version: version})
	if err != nil {
		return err
	}
	fmt.Printf("Support bundle: %s\nReport: %s\nCapture: %s\nEvidence references: %d (packet bytes not embedded)\n", out, manifest.ReportSHA256, manifest.CaptureDigest, len(manifest.Evidence))
	return nil
}
