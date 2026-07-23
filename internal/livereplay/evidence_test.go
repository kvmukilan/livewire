package livereplay

import (
	"bytes"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/backend"
	"github.com/kvmukilan/livewire/internal/wire"
)

type evidenceStub struct {
	now time.Time
	rx  []byte
}

func (s *evidenceStub) Send([]byte) error { return nil }
func (s *evidenceStub) Recv(buf []byte, _ time.Duration) (int, bool, error) {
	if s.rx == nil {
		return 0, false, nil
	}
	n := copy(buf, s.rx)
	s.rx = nil
	return n, true, nil
}
func (s *evidenceStub) Now() time.Time             { return s.now }
func (s *evidenceStub) LinkType() wire.LinkType    { return wire.LinkEthernet }
func (s *evidenceStub) Caps() backend.Capabilities { return backend.CanReceive }
func (s *evidenceStub) Close() error               { return nil }

func TestEvidenceBackendRecordsSuccessfulTxAndRx(t *testing.T) {
	stub := &evidenceStub{now: time.Unix(10, 20), rx: []byte{4, 5, 6}}
	e := &evidenceBackend{PacketBackend: stub, link: wire.LinkEthernet}
	tx := []byte{1, 2, 3}
	if err := e.Send(tx); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if _, ok, err := e.Recv(buf, time.Second); err != nil || !ok {
		t.Fatalf("recv: ok=%v err=%v", ok, err)
	}
	if len(e.frames) != 2 || !bytes.Equal(e.frames[0].Data, tx) || !bytes.Equal(e.frames[1].Data, []byte{4, 5, 6}) {
		t.Fatalf("unexpected evidence: %+v", e.frames)
	}
	tx[0] = 9
	if e.frames[0].Data[0] != 1 {
		t.Fatal("evidence must own a copy of each frame")
	}
}
