package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/orchestration"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/replayintent"
	"github.com/kvmukilan/livewire/internal/stateless"
)

type wireReplayReport struct {
	Status        string             `json:"status,omitempty"`
	Selection     *replay.ReplayPlan `json:"selection,omitempty"`
	Tool          string             `json:"tool"`
	Command       string             `json:"command"`
	Version       string             `json:"version"`
	When          time.Time          `json:"when"`
	CaptureDigest string             `json:"captureDigest"`
	Interface     string             `json:"interface,omitempty"`
	Mode          string             `json:"mode"`
	FramesPerPass int                `json:"framesPerPass"`
	Passes        int                `json:"passes"`
	FramesSent    int                `json:"framesSent"`
	Completed     bool               `json:"completed"`
	Verified      bool               `json:"verified"`
	Limitations   []string           `json:"limitations"`
	Error         string             `json:"error,omitempty"`
}

// cmdReplay is a tcpreplay-style stateless send: blast a capture's frames onto
// an interface at a chosen rate, with no live sequence state. Use `live` when
// the frames must land on a real TCP peer that answers.
func cmdReplay(args []string) error {
	return cmdStatelessReplay("replay", args)
}

func cmdStatelessReplay(command string, args []string) error {
	return cmdStatelessReplayWithSender(command, args, backend.OpenSender)
}

func cmdReplayWithSender(args []string, openSender func(string) (backend.PacketBackend, error)) error {
	return cmdStatelessReplayWithSender("replay", args, openSender)
}

func cmdStatelessReplayWithSender(command string, args []string, openSender func(string) (backend.PacketBackend, error)) (retErr error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
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
	fs.IntVar(&loop, "times", 1, "alias for -n")
	fs.IntVar(&loop, "iterations", 1, "alias for -n")
	var selectedSessions fileFlags
	fs.Var(&selectedSessions, "session", "select session ID (repeatable)")
	dryRun := fs.Bool("dry-run", false, "compute and print the schedule without sending")
	reportPath := fs.String("report", "", "write a JSON execution report without packet payloads")
	allFlags := registerAllFlags(fs)
	fs.Usage = func() {
		fmt.Printf("usage: livewire %s <capture.pcap> -i <connection> [-pps N | -mbps N | -multiplier N | -topspeed] [-n N]\n", command)
		fmt.Printf("   or: livewire %s -in <capture.pcap> -i <connection> [options]\n", command)
		fmt.Println("\nStateless replay: send captured frames as-is at a chosen rate. There is no")
		fmt.Println("fresh TCP/TLS connection or reply checking. Both recorded directions are sent.")
		fmt.Println("Captured TLS bytes need no key log here and do not form a fresh TLS session.")
		fmt.Println("Use live <capture> -t <target> for fresh application sessions and response checks.")
		fmt.Println("Without a rate flag, preserve captured timing. Use -dry-run to preview without sending.")
		printFlags(fs, flagIn, flagIface, flagCount, "pps", "mbps", "multiplier", "topspeed", "dry-run", "report")
	}
	if name := applicationOnlyReplayFlag(fs, args); name != "" {
		return fmt.Errorf("-%s is not supported by stateless %s; no packets were sent. Use live <capture> with that option for application/session replay", name, command)
	}
	capturePath, err := parseCaptureArgs(fs, args, &inPath)
	if err != nil {
		return err
	}
	inPath = capturePath
	if handleAllFlags(fs, *allFlags, aliasSet{"iface": true, "loop": true, "times": true, "iterations": true}) {
		return errAllFlags
	}
	if inPath == "" {
		fs.Usage()
		return fmt.Errorf("a capture file is required, e.g. livewire %s issue.pcap -i <connection>", command)
	}
	if loop < 0 {
		return fmt.Errorf("-n cannot be negative (0 = forever)")
	}
	if loop > maxReplayAttempts {
		return fmt.Errorf("-n must not exceed %d (0 still means run until interrupted)", maxReplayAttempts)
	}
	var invalidRate string
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "pps":
			if *pps <= 0 {
				invalidRate = f.Name
			}
		case "mbps":
			if *mbps <= 0 {
				invalidRate = f.Name
			}
		case "multiplier":
			if *mult <= 0 {
				invalidRate = f.Name
			}
		}
	})
	if invalidRate != "" {
		return fmt.Errorf("-%s must be greater than zero", invalidRate)
	}

	capture, captureDigest, err := loadCaptureSnapshot(inPath)
	if err != nil {
		return err
	}
	recs, nanos := capture.Records, capture.Nanosecond
	_ = nanos
	if len(recs) == 0 {
		return fmt.Errorf("no records in %s", inPath)
	}

	inspection, err := replayintent.Inspect(recs, replayintent.Options{Mode: "wire", Sessions: selectedSessions}, nil)
	if err != nil {
		return err
	}
	if !inspection.Readiness.Supported {
		return fmt.Errorf("%s", inspection.Readiness.Blocker)
	}
	if len(selectedSessions) > 0 {
		indexes := map[int]bool{}
		for _, e := range inspection.Plan.Entries {
			if !e.Excluded {
				for _, i := range e.PacketIndexes {
					indexes[i] = true
				}
			}
		}
		filtered := make([]*pcapio.Record, 0)
		for i, r := range recs {
			if indexes[i] {
				filtered = append(filtered, r)
			}
		}
		recs = filtered
	}
	if len(recs) == 0 {
		return fmt.Errorf("no captured frames match the selected sessions")
	}
	pace := stateless.Pace{TopSpeed: *topspeed, PPS: *pps, Mbps: *mbps, Multiplier: *mult}
	sched, err := stateless.CheckedSchedule(recs, pace)
	if err != nil {
		return err
	}
	for i, rec := range recs {
		if len(rec.Data) == 0 {
			return fmt.Errorf("capture record %d has no frame bytes; no packets were sent", i)
		}
		if rec.LinkType != recs[0].LinkType {
			return fmt.Errorf("selected capture mixes link types (%d and %d); select one compatible session or capture before replay; no packets were sent", recs[0].LinkType, rec.LinkType)
		}
	}
	fmt.Printf("%d frames, one pass takes %s at the chosen rate\n", len(recs), stateless.TotalDuration(sched))

	var report *wireReplayReport
	if *reportPath != "" {
		resolved, err := resolveOutputPath(*reportPath, "", "-report")
		if err != nil {
			return err
		}
		*reportPath = resolved
		mode := "wire"
		if *dryRun {
			mode = "dry-run"
		}
		report = &wireReplayReport{
			Tool: "livewire", Command: command, Version: version, When: time.Now().UTC(), CaptureDigest: captureDigest, Selection: &inspection.Plan,
			Interface: iface, Mode: mode, FramesPerPass: len(recs), Verified: false,
			Limitations: []string{"captured frames are not adapted to a live session and replies are not compared with the recording"},
		}
		defer func() {
			report.Completed = retErr == nil
			report.Status = replay.ResultStatus(report.Completed, false, false, !*dryRun, retErr)
			if *dryRun && retErr == nil {
				report.Status = "preview"
			}
			if retErr != nil {
				report.Error = retErr.Error()
			}
			if err := orchestration.WriteJSON(*reportPath, report, nil); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("write wire replay report: %w", err))
			} else {
				fmt.Printf("Report: %s\n", *reportPath)
			}
		}()
	}

	if *dryRun {
		fmt.Println("dry-run: not sending. Remove -dry-run and pass -i to transmit.")
		return nil
	}
	if iface == "" {
		return fmt.Errorf("-i is required to send (or pass -dry-run)")
	}

	snd, err := openSender(iface)
	if err != nil {
		return err
	}
	defer func() {
		if err := snd.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close replay sender: %w", err))
		}
	}()
	if recs[0].LinkType != snd.LinkType() {
		return fmt.Errorf("capture link type %d does not match interface link type %d; captured frames cannot be injected unchanged; no packets were sent", recs[0].LinkType, snd.LinkType())
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pass := 0
	for loop == 0 || pass < loop {
		start := time.Now()
		for i, rec := range recs {
			if d := sched[i] - time.Since(start); d > 0 && !waitReplayContext(ctx, d) {
				return fmt.Errorf("replay interrupted: %w", ctx.Err())
			}
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("replay interrupted: %w", err)
			}
			if err := snd.Send(rec.Data); err != nil {
				return fmt.Errorf("send frame %d: %w", i, err)
			}
			if report != nil {
				report.FramesSent++
			}
		}
		pass++
		if report != nil {
			report.Passes = pass
		}
		fmt.Printf("attempt %d complete (%d frames)\n", pass, len(recs))
	}
	return nil
}

// applicationOnlyReplayFlag recognizes option tokens, never filenames or flag
// values. Old application invocations must fail before opening a capture or a
// sender; secure inputs must never silently switch stateless reproduction modes.
func applicationOnlyReplayFlag(fs *flag.FlagSet, args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		if !isFlagArg(arg) {
			continue
		}
		name, _, assigned := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		switch name {
		case "t", "to", "target", "keylog", "ca", "server-name", "insecure-skip-verify", "user", "pass", "key", "host-key", "cmd", "expect", "timeout", "response-timeout", "expect-fault", "under-load", "exact-tcp", "gap", "stop-when-different", "mode", "profile", "strict", "strict-exit", "actual-out", "no-rst-guard", "udp-idle", "set", "rules", "scenario", "state-dir", "resume", "run-timeout", "concurrency", "wire":
			return name
		}
		if assigned {
			continue
		}
		if f := fs.Lookup(name); f != nil {
			boolean, ok := f.Value.(interface{ IsBoolFlag() bool })
			if (!ok || !boolean.IsBoolFlag()) && i+1 < len(args) {
				i++
			}
		}
	}
	return ""
}

func waitReplayContext(ctx context.Context, duration time.Duration) bool {
	if duration <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// loadRecords reads every record from a capture into memory.
func loadRecords(path string) ([]*pcapio.Record, bool, error) {
	capture, err := orchestration.LoadFile(path)
	if err != nil {
		return nil, false, err
	}
	recs := make([]*pcapio.Record, 0, len(capture.Records))
	for _, rec := range capture.Records {
		cp := *rec
		cp.Data = append([]byte(nil), rec.Data...)
		recs = append(recs, &cp)
	}
	return recs, capture.Nanosecond, nil
}
