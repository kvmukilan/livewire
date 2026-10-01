package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/orchestration"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/recording"
)

const tlsRecordingMaxBytes = 64 << 20

func captureTLS(iface, outPath string, count int, duration time.Duration, promisc bool, argv []string, open func(string, bool) (backend.PacketBackend, error)) (retErr error) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM, syscall.SIGPIPE)
	// Register first so signal handling is restored after every owned resource.
	defer signal.Stop(stop)
	af, err := orchestration.CreateArtifact(outPath)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, af.Abort()) }()
	if err := recording.RestrictFile(af.File()); err != nil {
		return fmt.Errorf("protect TLS capture: %w", err)
	}
	snd, err := open(iface, promisc)
	if err != nil {
		return err
	}
	backendOpen := true
	defer func() {
		if backendOpen {
			retErr = errors.Join(retErr, snd.Close())
		}
	}()
	w, err := pcapio.NewNgWriter(af, []pcapio.NgInterface{{Name: iface, LinkType: snd.LinkType()}})
	if err != nil {
		return err
	}
	if _, err := fmt.Printf("recording TLS on %s -> %s; the capture will contain sensitive session secrets\n", iface, outPath); err != nil {
		return fmt.Errorf("write recording progress: %w", err)
	}
	child, err := recording.Start(argv)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, child.Close()) }()
	deadline := time.Time{}
	if duration > 0 {
		deadline = time.Now().Add(duration)
	}
	buf := make([]byte, 65536)
	n, dataBytes := 0, 0
	done := child.Done()
	nextLogCheck := time.Time{}
	var captureErr error
loop:
	for {
		select {
		case <-stop:
			break loop
		case <-done:
			captureErr = child.ExitError()
			done = nil
			// Drain packets already in the backend after the application exits.
			tail := time.Now().Add(500 * time.Millisecond)
			if deadline.IsZero() || tail.Before(deadline) {
				deadline = tail
			}
		default:
		}
		now := time.Now()
		if !deadline.IsZero() && !now.Before(deadline) {
			break
		}
		if !now.Before(nextLogCheck) {
			if err := child.CheckLog(); err != nil {
				captureErr = errors.Join(captureErr, err)
				break
			}
			nextLogCheck = now.Add(100 * time.Millisecond)
		}
		nn, ok, err := snd.Recv(buf, 100*time.Millisecond)
		if err != nil {
			captureErr = errors.Join(captureErr, err)
			break
		}
		if !ok {
			continue
		}
		if nn <= 0 || nn > len(buf) {
			captureErr = errors.Join(captureErr, fmt.Errorf("capture backend returned an invalid packet size"))
			break
		}
		if dataBytes+nn > tlsRecordingMaxBytes || n >= 1_000_000 {
			captureErr = errors.Join(captureErr, fmt.Errorf("TLS recording reached its 64 MiB / 1,000,000 packet safety limit; record a shorter exchange"))
			break
		}
		if err := w.Write(&pcapio.Record{Time: snd.Now(), Data: buf[:nn], CapLen: nn, OrigLen: nn, LinkType: snd.LinkType()}); err != nil {
			return err
		}
		n++
		dataBytes += nn
		if count > 0 && n >= count {
			break
		}
	}
	// Stop all owned writers before inspecting the key log. This also handles
	// duration/count limits, Ctrl-C, backend failures, and descendant processes.
	if done != nil {
		select {
		case <-done:
			captureErr = errors.Join(captureErr, child.ExitError())
		default:
			captureErr = errors.Join(captureErr, fmt.Errorf("recording stopped before the application exited"))
		}
	}
	captureErr = errors.Join(captureErr, child.Stop())
	if err := w.Flush(); err != nil {
		return err
	}
	backendOpen = false
	captureErr = errors.Join(captureErr, snd.Close())
	keys, keyErr := child.Secrets()
	var matched []byte
	var sessions int
	if keyErr == nil {
		info, err := af.File().Stat()
		if err != nil {
			return err
		}
		capture, err := pcapio.Load(io.NewSectionReader(af.File(), 0, info.Size()), pcapio.DefaultLimits())
		if err != nil {
			keyErr = err
		} else {
			matched, sessions, keyErr = recording.MatchSecrets(&capture, keys)
		}
	}
	clear(keys)
	if keyErr == nil {
		keyErr = w.WriteTLSSecrets(matched)
		clear(matched)
		if keyErr == nil {
			keyErr = w.Flush()
		}
	}
	captureErr = errors.Join(captureErr, keyErr, child.Close())
	if captureErr != nil {
		path, err := af.PreservePartial()
		return errors.Join(fmt.Errorf("TLS recording incomplete; %d packet(s) preserved in partial capture %q: %w", n, path, captureErr), err)
	}
	if err := af.Commit(); err != nil {
		return err
	}
	if _, err := fmt.Printf("saved %d packet(s) with embedded secrets for %d captured TLS session(s)\n", n, sessions); err != nil {
		return err
	}
	_, err = fmt.Printf("inspect supported application replay: livewire check %q -details\n", outPath)
	return err
}
