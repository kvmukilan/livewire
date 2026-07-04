package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/pcapio"
)

// cmdCapture records live frames from an interface into a pcap, stopping on
// -count, -duration, or Ctrl-C.
func cmdCapture(args []string) error {
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	iface := fs.String("iface", "", "interface/device to capture on (required; see 'livewire ifaces')")
	outPath := fs.String("out", "", "output pcap file (required)")
	count := fs.Int("count", 0, "stop after this many packets (0 = unlimited)")
	dur := fs.Duration("duration", 0, "stop after this long (0 = until Ctrl-C or -count)")
	promisc := fs.Bool("promisc", true, "put the interface in promiscuous mode")
	fs.Usage = func() {
		fmt.Println("usage: livewire capture -iface <device> -out <file.pcap> [-count N] [-duration 10s]")
		fmt.Println("\nRecord frames from a live interface to a pcap (for later replay).")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *iface == "" || *outPath == "" {
		fs.Usage()
		return fmt.Errorf("-iface and -out are required")
	}

	snd, err := backend.OpenCapture(*iface, *promisc)
	if err != nil {
		return err
	}
	defer snd.Close()

	f, err := os.Create(*outPath)
	if err != nil {
		return err
	}
	defer f.Close()
	w, err := pcapio.NewWriter(f, snd.LinkType(), true)
	if err != nil {
		return err
	}
	defer w.Flush()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	deadline := time.Time{}
	if *dur > 0 {
		deadline = time.Now().Add(*dur)
	}

	fmt.Printf("capturing on %s -> %s (Ctrl-C to stop)\n", *iface, *outPath)
	buf := make([]byte, 65536)
	n := 0
	for {
		select {
		case <-stop:
			fmt.Printf("\nstopped: captured %d packet(s)\n", n)
			return w.Flush()
		default:
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			fmt.Printf("duration elapsed: captured %d packet(s)\n", n)
			return w.Flush()
		}
		nn, ok, err := snd.Recv(buf, 500*time.Millisecond)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		rec := &pcapio.Record{Time: snd.Now(), Data: append([]byte(nil), buf[:nn]...), CapLen: nn, OrigLen: nn, LinkType: snd.LinkType()}
		if err := w.Write(rec); err != nil {
			return err
		}
		n++
		if *count > 0 && n >= *count {
			fmt.Printf("captured %d packet(s)\n", n)
			return w.Flush()
		}
	}
}
