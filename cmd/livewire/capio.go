package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/kvmukilan/livewire/internal/orchestration"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"io"
	"os"
)

// loadCaptureSnapshot hashes the exact byte stream passed to the strict loader.
// A later rename or edit of the source cannot change the report's identity.
func loadCaptureSnapshot(path string) (capture pcapio.Capture, digest string, retErr error) {
	// #nosec G703 -- the CLI operator explicitly selects a local capture path;
	// unlike the dashboard, the CLI has no confined directory. Parsing is bounded.
	f, err := os.Open(path)
	if err != nil {
		return capture, "", err
	}
	defer func() { retErr = errors.Join(retErr, f.Close()) }()
	h := sha256.New()
	capture, err = orchestration.Load(io.TeeReader(f, h))
	if err != nil {
		return capture, "", err
	}
	return capture, fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}

// input preserves the small iterator surface used by older command stages while
// delegating all parsing, validation, and limits to pcapio.LoadFile.
type input struct {
	records []*pcapio.Record
	next    int
	nanos   bool
	isNg    bool
	ngMixed func() bool
}

// openInput is the sole CLI capture loader. The dashboard calls the same
// pcapio.LoadFile implementation directly through its rooted file handle.
func openInput(path string) (*input, error) {
	capture, err := orchestration.LoadFile(path)
	if err != nil {
		return nil, err
	}
	mixed := capture.MixedLinks
	return &input{
		records: capture.Records,
		nanos:   capture.Nanosecond,
		isNg:    capture.PCAPNG,
		ngMixed: func() bool { return mixed },
	}, nil
}

// eachRecord visits every remaining validated record and returns callback
// errors without treating parser failures as EOF (parsing already completed).
func (in *input) eachRecord(fn func(rec *pcapio.Record) error) error {
	for in.next < len(in.records) {
		rec := in.records[in.next]
		in.next++
		if err := fn(rec); err != nil {
			return err
		}
	}
	return nil
}
