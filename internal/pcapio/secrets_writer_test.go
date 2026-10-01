package pcapio

import (
	"bytes"
	"github.com/kvmukilan/livewire/internal/wire"
	"testing"
)

func TestNgWriterExplicitTLSSecretsRoundTripAndLimit(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewNgWriter(&buf, []NgInterface{{LinkType: wire.LinkEthernet}})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, []byte("unterminated"), []byte("nul\x00\n"), bytes.Repeat([]byte{'\n'}, MaxTLSKeyLogBytes+1)} {
		if err := w.WriteTLSSecrets(bad); err == nil {
			t.Fatal("invalid DSB accepted")
		}
	}
	keys := bytes.Repeat([]byte{'\n'}, MaxTLSKeyLogBytes)
	if err := w.WriteTLSSecrets(keys); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteTLSSecrets([]byte("\n")); err == nil {
		t.Fatal("aggregate secret limit ignored")
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	capture, err := Load(bytes.NewReader(buf.Bytes()), DefaultLimits())
	if err != nil || !bytes.Equal(capture.TLSKeyLog(), keys) {
		t.Fatalf("DSB round trip failed: %v", err)
	}
}
