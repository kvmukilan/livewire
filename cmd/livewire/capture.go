package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/pcapio"
)

// captureAliases names the flags on 'capture' kept only for compatibility.
var captureAliases = aliasSet{"iface": true, "out": true, "count": true}

// cmdCapture records live frames from an interface into a pcap, stopping on
// -count, -duration, or Ctrl-C.
func cmdCapture(args []string) error {
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	var iface string
	fs.StringVar(&iface, flagIface, "", "network connection to record from (see 'livewire ifaces')")
	fs.StringVar(&iface, "iface", "", "alias for -i")
	var outPath string
	fs.StringVar(&outPath, flagOut, "", "the file to record into")
	fs.StringVar(&outPath, "out", "", "alias for -o")
	// -n counts packets here rather than attempts: on a recording command "how
	// many" can only mean packets, and it matches tcpdump -c.
	var count int
	fs.IntVar(&count, flagCount, 0, "stop after this many packets (0 = until Ctrl-C)")
	fs.IntVar(&count, "count", 0, "alias for -n")
	dur := fs.Duration("duration", 0, "stop after this long (0 = until Ctrl-C or -n)")
	promisc := fs.Bool("promisc", true, "put the interface in promiscuous mode")
	allFlags := registerAllFlags(fs)
	fs.Usage = func() {
		fmt.Println("usage: livewire capture -i <connection> -o <file.pcap> [-n 1000] [-duration 10s]")
		fmt.Println("\nRecord traffic from a network connection into a file, for later replay.")
		printFlags(fs, flagIface, flagOut, flagCount, "duration")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if handleAllFlags(fs, *allFlags, captureAliases) {
		return errAllFlags
	}
	if iface == "" || outPath == "" {
		fs.Usage()
		return fmt.Errorf("-i (which connection) and -o (where to save) are required")
	}

	snd, err := backend.OpenCapture(iface, *promisc)
	if err != nil {
		return err
	}
	defer snd.Close()

	f, err := os.Create(outPath)
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
	// SIGTERM as well as Ctrl-C: a capture is often started by a supervisor or a
	// script, and losing the buffered tail on shutdown loses the evidence.
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	deadline := time.Time{}
	if *dur > 0 {
		deadline = time.Now().Add(*dur)
	}

	fmt.Printf("capturing on %s -> %s (Ctrl-C to stop)\n", iface, outPath)
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
		if count > 0 && n >= count {
			fmt.Printf("captured %d packet(s)\n", n)
			return w.Flush()
		}
	}
}
