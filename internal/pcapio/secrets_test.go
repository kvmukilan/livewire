package pcapio

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func secretBlock(order binary.ByteOrder, kind uint32, data, options []byte) []byte {
	padded := (len(data) + 3) &^ 3
	out := make([]byte, 20+padded+len(options))
	order.PutUint32(out[:4], ngBlockDSB)
	order.PutUint32(out[4:8], uint32(len(out)))
	order.PutUint32(out[8:12], kind)
	order.PutUint32(out[12:16], uint32(len(data)))
	copy(out[16:], data)
	copy(out[16+padded:], options)
	order.PutUint32(out[len(out)-4:], uint32(len(out)))
	return out
}

func TestPCAPNGTLSSecretsBoundedAndPrivate(t *testing.T) {
	first := []byte("CLIENT_RANDOM " + strings.Repeat("01", 32) + " " + strings.Repeat("02", 48) + "\r\n")
	second := []byte("CLIENT_HANDSHAKE_TRAFFIC_SECRET " + strings.Repeat("03", 32) + " " + strings.Repeat("04", 32) + "\n")
	pcap := buildMinimalPcapng(1, 0, []byte("packet"))
	// Exercise both pre-packet and post-packet DSBs, including options and an
	// unknown binary secret type that must never be passed to TLS execution.
	options := []byte{1, 0, 1, 0, 'x', 0, 0, 0, 0, 0, 0, 0}
	input := append(bytes.Clone(pcap[:60]), secretBlock(binary.LittleEndian, ngSecretsTLS, first, options)...)
	input = append(input, pcap[60:]...)
	input = append(input, secretBlock(binary.LittleEndian, 0x12345678, []byte{0, 1, 2}, nil)...)
	input = append(input, secretBlock(binary.LittleEndian, ngSecretsTLS, second, nil)...)
	capture, err := Load(bytes.NewReader(input), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	want := append(bytes.Clone(first), second...)
	if !bytes.Equal(capture.TLSKeyLog(), want) || len(capture.Records) != 1 || string(capture.Records[0].Data) != "packet" {
		t.Fatal("secrets or packet data did not survive the complete load")
	}
	copyOfKeys := capture.TLSKeyLog()
	copyOfKeys[0] = '!'
	if !bytes.Equal(capture.TLSKeyLog(), want) {
		t.Fatal("caller can mutate capture secrets")
	}
	encoded, err := json.Marshal(capture)
	if err != nil || bytes.Contains(encoded, []byte("CLIENT_RANDOM")) || bytes.Contains(encoded, first) {
		t.Fatal("sensitive metadata serialized")
	}
	reader, err := NewNgReader(bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reader.Read(); err != nil || !bytes.Equal(reader.TLSKeyLog(), first) {
		t.Fatal("stream reader should expose only secrets already read")
	}
	if _, err = reader.Read(); err != io.EOF || !bytes.Equal(reader.TLSKeyLog(), want) {
		t.Fatal("stream reader lost trailing secrets")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if got := fmt.Sprintf(format, capture); got != "pcapio.Capture{Records:1, PCAPNG:true, TLSSecrets:true}" {
			t.Fatal("capture formatting exposed data")
		}
		if got := fmt.Sprintf(format, reader); got != "pcapio.NgReader{Interfaces:1, TLSSecrets:true}" {
			t.Fatal("reader formatting exposed data")
		}
	}
	// A normal PCAPNG packet writer must not implicitly copy sensitive metadata.
	var roundTrip bytes.Buffer
	writer, err := NewNgWriter(&roundTrip, []NgInterface{{LinkType: capture.PrimaryLink}})
	if err != nil {
		t.Fatal(err)
	}
	if err = writer.Write(capture.Records[0]); err != nil {
		t.Fatal(err)
	}
	if err = writer.Flush(); err != nil {
		t.Fatal(err)
	}
	stripped, err := Load(bytes.NewReader(roundTrip.Bytes()), Limits{})
	if err != nil || len(stripped.TLSKeyLog()) != 0 {
		t.Fatal("packet writer copied secret metadata")
	}
	if _, err = Load(bytes.NewReader(input), Limits{MaxCaptureData: int64(len(want) + 5)}); !errors.Is(err, ErrLimit) {
		t.Fatal("secret metadata bypassed total capture budget")
	}
}

func TestPCAPNGTLSSecretsRejectMalformedBlocks(t *testing.T) {
	prefix := buildMinimalPcapng(1, 0, []byte{1})[:60]
	valid := secretBlock(binary.LittleEndian, ngSecretsTLS, []byte("# a fixture\n"), nil)
	for _, test := range []struct {
		name  string
		block []byte
	}{
		{"missing line ending", secretBlock(binary.LittleEndian, ngSecretsTLS, []byte("secret"), nil)},
		{"nul text", secretBlock(binary.LittleEndian, ngSecretsTLS, []byte("secret\x00\n"), nil)},
		{"oversized option", secretBlock(binary.LittleEndian, ngSecretsTLS, []byte("# ok\n"), []byte{1, 0, 255, 255})},
		{"nonempty end option", secretBlock(binary.LittleEndian, ngSecretsTLS, []byte("# ok\n"), []byte{0, 0, 1, 0})},
		{"trailing option data", secretBlock(binary.LittleEndian, ngSecretsTLS, []byte("# ok\n"), []byte{0, 0, 0, 0, 1, 0, 0, 0})},
		{"declared data overflow", func() []byte { b := bytes.Clone(valid); binary.LittleEndian.PutUint32(b[12:16], ^uint32(0)); return b }()},
		{"bad footer", func() []byte { b := bytes.Clone(valid); b[len(b)-1]++; return b }()},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Load(bytes.NewReader(append(bytes.Clone(prefix), test.block...)), Limits{})
			if !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "secret\x00") {
				t.Fatalf("invalid block was accepted or sensitive content exposed: %v", err)
			}
		})
	}
	data := bytes.Repeat([]byte("# fixture\n"), MaxTLSKeyLogBytes/10/2+1)
	twice := append(bytes.Clone(prefix), secretBlock(binary.LittleEndian, ngSecretsTLS, data, nil)...)
	twice = append(twice, secretBlock(binary.LittleEndian, ngSecretsTLS, data, nil)...)
	if _, err := Load(bytes.NewReader(twice), Limits{}); !errors.Is(err, ErrLimit) {
		t.Fatal("multiple DSBs bypassed aggregate secret budget")
	}
}

func TestPCAPNGTLSSecretsByteOrderAndSections(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		shb := make([]byte, 28)
		order.PutUint32(shb[:4], ngBlockSHB)
		order.PutUint32(shb[4:8], 28)
		order.PutUint32(shb[8:12], ngByteMagic)
		order.PutUint16(shb[12:14], 1)
		order.PutUint64(shb[16:24], ^uint64(0))
		order.PutUint32(shb[24:28], 28)
		input := append(bytes.Clone(shb), secretBlock(order, ngSecretsTLS, []byte("# one\n"), nil)...)
		input = append(input, shb...)
		input = append(input, secretBlock(order, ngSecretsTLS, []byte("# two\n"), nil)...)
		capture, err := Load(bytes.NewReader(input), Limits{})
		if err != nil || string(capture.TLSKeyLog()) != "# one\n# two\n" {
			t.Fatalf("%s: same-endian sections lost secrets: %v", order, err)
		}
	}
}

func FuzzPCAPNGTLSSecrets(f *testing.F) {
	prefix := buildMinimalPcapng(1, 0, []byte("packet"))[:60]
	f.Add(secretBlock(binary.LittleEndian, ngSecretsTLS, []byte("# fixture\n"), nil))
	f.Add(secretBlock(binary.LittleEndian, ngSecretsTLS, []byte("# fixture\r\n"), []byte{0, 0, 0, 0}))
	f.Add(secretBlock(binary.LittleEndian, 0x12345678, []byte{0, 1, 2, 3}, nil))
	f.Fuzz(func(t *testing.T, block []byte) {
		if len(block) > 64<<10 {
			t.Skip()
		}
		capture, err := Load(bytes.NewReader(append(bytes.Clone(prefix), block...)), Limits{MaxRecordBytes: 8192, MaxCaptureData: 4096, MaxRecords: 64})
		if err != nil {
			return
		}
		total := len(capture.TLSKeyLog())
		for _, packet := range capture.Records {
			total += len(packet.Data)
		}
		if total > 4096 || len(capture.Records) > 64 {
			t.Fatal("loaded capture exceeds configured limits")
		}
	})
}
