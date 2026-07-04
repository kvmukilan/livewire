package main

import (
	"bufio"
	"encoding/binary"
	"io"
	"os"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

// capReader unifies the classic pcap and pcapng readers.
type capReader interface {
	Read() (*pcapio.Record, error)
	LinkType() wire.LinkType
}

// input is an opened capture with its backing file and metadata.
type input struct {
	rd      capReader
	file    *os.File
	nanos   bool // source had nanosecond timestamps
	isNg    bool
	ngMixed func() bool
}

func (in *input) Close() error { return in.file.Close() }

// openInput opens path and returns a unified reader, detecting pcap vs pcapng by
// magic. pcapng is treated as nanosecond-resolution.
func openInput(path string) (*input, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(f, 1<<16)
	magic, err := br.Peek(4)
	if err != nil {
		f.Close()
		return nil, err
	}
	if isPcapng(magic) {
		nr, err := pcapio.NewNgReader(br)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &input{rd: nr, file: f, nanos: true, isNg: true, ngMixed: nr.Mixed}, nil
	}
	r, err := pcapio.NewReader(br)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &input{rd: r, file: f, nanos: r.Nanosecond()}, nil
}

func isPcapng(magic []byte) bool {
	return binary.LittleEndian.Uint32(magic) == 0x0A0D0D0A
}

// eachRecord streams every record to fn, stopping at EOF or the first error.
func (in *input) eachRecord(fn func(rec *pcapio.Record) error) error {
	for {
		rec, err := in.rd.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
}
