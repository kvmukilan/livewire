package main

import (
	"github.com/kvmukilan/livewire/internal/orchestration"
	"github.com/kvmukilan/livewire/internal/pcapio"
)

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
