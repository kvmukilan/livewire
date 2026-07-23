package pcapio

import (
	"bytes"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/wire"
)

func TestNgWriterRoundTripInterfaces(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewNgWriter(&buf, []NgInterface{{Name: "client", LinkType: wire.LinkEthernet}, {Name: "server", LinkType: wire.LinkRaw}})
	if err != nil {
		t.Fatal(err)
	}
	when := time.Unix(1_700_000_000, 123456789)
	if err := w.Write(&Record{Time: when, Data: []byte{1, 2, 3}, InterfaceID: 1, LinkType: wire.LinkRaw}); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	r, err := NewNgReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	if rec.InterfaceID != 1 || rec.LinkType != wire.LinkRaw || !rec.Time.Equal(when.UTC()) || !bytes.Equal(rec.Data, []byte{1, 2, 3}) {
		t.Fatalf("record=%+v", rec)
	}
	if !r.Mixed() {
		t.Fatal("different interface link types should report mixed")
	}
}
