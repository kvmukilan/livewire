package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/buildinfo"
	"github.com/kvmukilan/livewire/internal/replaylab"
)

func main() {
	var o replaylab.Options
	var names string
	var list bool
	flag.StringVar(&o.Binary, "binary", "", "actual livewire binary to exercise")
	flag.StringVar(&o.SourceRoot, "source-root", ".", "source root bound into evidence")
	flag.StringVar(&o.Output, "out", "", "new private evidence directory")
	flag.StringVar(&o.Version, "version", buildinfo.Version, "expected binary version")
	flag.StringVar(&o.Command, "command", "reproduce", "front door: live or reproduce")
	flag.StringVar(&o.Environment, "environment", "", "software-lab environment description")
	flag.DurationVar(&o.Duration, "duration", 2*time.Hour, "minimum span of successful checks for every case")
	flag.DurationVar(&o.Interval, "interval", time.Second, "pause between complete matrix rounds")
	flag.DurationVar(&o.ProcessTimeout, "process-timeout", 45*time.Second, "timeout for one CLI process")
	flag.IntVar(&o.Repeat, "repeat", 3, "iterations inside each CLI process")
	flag.StringVar(&names, "cases", "", "comma-separated subset for smoke checks")
	flag.BoolVar(&list, "list", false, "list registered cases")
	flag.Parse()
	if list {
		fmt.Println(strings.Join(replaylab.Cases(), "\n"))
		return
	}
	if o.Binary == "" || o.Output == "" {
		fmt.Fprintln(os.Stderr, "-binary and -out are required")
		os.Exit(2)
	}
	if names != "" {
		o.Cases = strings.Split(names, ",")
	}
	o.Progress = func(message string) { fmt.Println(time.Now().UTC().Format(time.RFC3339), message) }
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	result, err := replaylab.Run(ctx, o)
	fmt.Printf("lab command=%s cases=%d seconds=%.3f interrupted=%v cleanup=%v\n", result.Command, len(result.Cases), result.Finished.Sub(result.Started).Seconds(), result.Interrupted, result.CleanupVerified)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
