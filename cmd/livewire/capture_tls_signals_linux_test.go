package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
)

func TestTLSRecordingBrokenOutputHelper(t *testing.T) {
	if os.Getenv("LIVEWIRE_RECORDING_PIPE_TEST") == "" {
		return
	}
	path := os.Getenv("LIVEWIRE_RECORDING_PIPE_TEST")
	b := &captureTestBackend{}
	err := captureTLS("test", path, 0, time.Second, false, []string{"must-not-be-launched"}, func(string, bool) (backend.PacketBackend, error) { return b, nil })
	if !errors.Is(err, syscall.EPIPE) || b.closed != 1 {
		fmt.Fprintf(os.Stderr, "broken output did not clean up before application launch: %v close=%d\n", err, b.closed)
		os.Exit(2)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		os.Exit(3)
	}
	os.Exit(0)
}

func TestTLSRecordingBrokenOutputReleasesCapture(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = read.Close()
	defer write.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTLSRecordingBrokenOutputHelper$")
	cmd.Env = append(os.Environ(), "LIVEWIRE_RECORDING_PIPE_TEST="+filepath.Join(t.TempDir(), "closed.pcapng"))
	cmd.Stdout = write
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("capture exited before cleanup: %v %s", err, stderr.String())
	}
}
