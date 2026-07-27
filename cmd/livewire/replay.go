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
	var inPath string
	fs.StringVar(&inPath, flagIn, "", "input pcap/pcapng file")
	var iface string
	fs.StringVar(&iface, flagIface, "", "network connection to send on")
	fs.StringVar(&iface, "iface", "", "alias for -i")
	pps := fs.Float64("pps", 0, "send at this many packets per second")
	mbps := fs.Float64("mbps", 0, "send at this many megabits per second")
	mult := fs.Float64("multiplier", 0, "scale the capture's own timing (2 = twice as fast)")
	topspeed := fs.Bool("topspeed", false, "send as fast as possible")
	var loop int
	fs.IntVar(&loop, flagCount, 1, "send the capture this many times (0 = forever)")
	fs.IntVar(&loop, "loop", 1, "alias for -n")
	dryRun := fs.Bool("dry-run", false, "compute and print the schedule without sending")
	allFlags := registerAllFlags(fs)
	fs.Usage = func() {
		fmt.Println("usage: livewire replay -in <file> -i <connection> [-pps N | -mbps N | -multiplier N | -topspeed] [-n N]")
		fmt.Println("\nStateless replay: send captured frames as-is at a chosen rate. There is no")
		fmt.Println("live peer and no reply checking — use 'reproduce' or 'live' for that.")
		printFlags(fs, flagIn, flagIface, flagCount, "pps", "mbps", "multiplier", "topspeed", "dry-run")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if handleAllFlags(fs, *allFlags, aliasSet{"iface": true, "loop": true}) {
		return errAllFlags
	}
	if inPath == "" {
		fs.Usage()
		return fmt.Errorf("-in is required")
	}
	if loop < 0 {
		return fmt.Errorf("-n cannot be negative (0 = forever)")
	}

	recs, nanos, err := loadRecords(inPath)
	if err != nil {
		return err
	}
	_ = nanos
	if len(recs) == 0 {
		return fmt.Errorf("no records in %s", inPath)
	}

	pace := stateless.Pace{TopSpeed: *topspeed, PPS: *pps, Mbps: *mbps, Multiplier: *mult}
	sched := stateless.Schedule(recs, pace)
	fmt.Printf("%d frames, one pass takes %s at the chosen rate\n", len(recs), stateless.TotalDuration(sched))

	if *dryRun {
		fmt.Println("dry-run: not sending. Remove -dry-run and pass -i to transmit.")
		return nil
	}
	if iface == "" {
		return fmt.Errorf("-i is required to send (or pass -dry-run)")
	}

	snd, err := backend.OpenSender(iface)
	if err != nil {
		return err
	}
	defer snd.Close()

	pass := 0
	for loop == 0 || pass < loop {
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
