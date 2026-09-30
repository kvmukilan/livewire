package replaylab

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

// embedFixtureKeys makes the HTTP TLS qualification exercise a PCAPNG that
// already contains secrets, without passing an external keylog to the CLI.
func embedFixtureKeys(f *Fixture) error {
	var keyPath string
	var args []string
	for i := 0; i < len(f.Args); i++ {
		if f.Args[i] == "-keylog" {
			i++
			keyPath = f.Args[i]
			continue
		}
		args = append(args, f.Args[i])
	}
	keys, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	input, err := os.Open(f.Capture)
	if err != nil {
		return err
	}
	capture, readErr := pcapio.Load(input, pcapio.DefaultLimits())
	if err := errors.Join(readErr, input.Close()); err != nil {
		return err
	}
	var output bytes.Buffer
	w, err := pcapio.NewNgWriter(&output, []pcapio.NgInterface{{LinkType: wire.LinkEthernet, SnapLen: 65535}})
	if err != nil {
		return err
	}
	for _, record := range capture.Records {
		if err := w.Write(record); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body, 0x544c534b)
	binary.LittleEndian.PutUint32(body[4:], uint32(len(keys)))
	body = append(body, keys...)
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	block := binary.LittleEndian.AppendUint32(nil, 10)
	block = binary.LittleEndian.AppendUint32(block, uint32(len(body)+12))
	block = append(block, body...)
	block = binary.LittleEndian.AppendUint32(block, uint32(len(body)+12))
	output.Write(block)
	path := filepath.Join(filepath.Dir(f.Capture), "fixture-embedded.pcapng")
	if err := writeNew(path, output.Bytes()); err != nil {
		return err
	}
	f.Capture, f.Args = path, args
	return nil
}
