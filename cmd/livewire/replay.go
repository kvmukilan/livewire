package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/stateless"
)

// cmdReplay is a tcpreplay-style stateless send: blast a capture's frames onto
// an interface at a chosen rate, with no live sequence state. Use `live` when
// the frames must land on a real TCP peer that answers.
func cmdReplay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	inPath := fs.String("in", "", "input pcap/pcapng file (required)")
	iface := fs.String("iface", "", "interface to send on (required)")
	pps := fs.Float64("pps", 0, "send at this many packets per second")
	mbps := fs.Float64("mbps", 0, "send at this many megabits per second")
	mult := fs.Float64("multiplier", 0, "scale the capture's own timing (2 = twice as fast)")
	topspeed := fs.Bool("topspeed", false, "send as fast as possible")
	loop := fs.Int("loop", 1, "send the capture this many times (0 = forever)")
	dryRun := fs.Bool("dry-run", false, "compute and print the schedule without sending")
	fs.Usage = func() {
		fmt.Println("usage: livewire replay -in <file> -iface <name> [-pps N | -mbps N | -multiplier N | -topspeed] [-loop N]")
		fmt.Println("\nStateless replay: send captured frames as-is at a chosen rate.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inPath == "" {
		fs.Usage()
		return fmt.Errorf("-in is required")
	}

	recs, nanos, err := loadRecords(*inPath)
	if err != nil {
		return err
	}
	_ = nanos
	if len(recs) == 0 {
		return fmt.Errorf("no records in %s", *inPath)
	}

	pace := stateless.Pace{TopSpeed: *topspeed, PPS: *pps, Mbps: *mbps, Multiplier: *mult}
	sched := stateless.Schedule(recs, pace)
	fmt.Printf("%d frames, one pass takes %s at the chosen rate\n", len(recs), stateless.TotalDuration(sched))

	if *dryRun {
		fmt.Println("dry-run: not sending. Remove -dry-run and pass -iface to transmit.")
		return nil
	}
	if *iface == "" {
		return fmt.Errorf("-iface is required to send (or pass -dry-run)")
	}

	snd, err := backend.OpenSender(*iface)
	if err != nil {
		return err
	}
	defer snd.Close()

	pass := 0
	for *loop == 0 || pass < *loop {
		start := time.Now()
		for i, rec := range recs {
			if d := sched[i] - time.Since(start); d > 0 {
				time.Sleep(d)
			}
			if err := snd.Send(rec.Data); err != nil {
				return fmt.Errorf("send frame %d: %w", i, err)
			}
		}
		pass++
		fmt.Printf("pass %d complete (%d frames)\n", pass, len(recs))
	}
	return nil
}

// loadRecords reads every record from a capture into memory.
func loadRecords(path string) ([]*pcapio.Record, bool, error) {
	in, err := openInput(path)
	if err != nil {
		return nil, false, err
	}
	defer in.Close()
	var recs []*pcapio.Record
	err = in.eachRecord(func(rec *pcapio.Record) error {
		cp := *rec
		cp.Data = append([]byte(nil), rec.Data...)
		recs = append(recs, &cp)
		return nil
	})
	return recs, in.nanos, err
}
