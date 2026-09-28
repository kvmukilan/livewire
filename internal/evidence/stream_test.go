package evidence

import (
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStreamingEvidenceAndCollision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "actual.pcap")
	s := New(path)
	defer s.Close()
	for i := 0; i < 100; i++ {
		r := pcapio.Record{Time: time.Unix(1, int64(i)), Data: []byte{1, 2, 3, 4}, LinkType: wire.LinkEthernet}
		if e := s.Record(r); e != nil {
			t.Fatal(e)
		}
	}
	if n, e := s.Commit(); e != nil || n != 100 {
		t.Fatalf("commit=%d %v", n, e)
	}
	capture, e := pcapio.LoadFile(path, pcapio.DefaultLimits())
	if e != nil || len(capture.Records) != 100 {
		t.Fatalf("capture=%v err=%v", capture, e)
	}
	before, _ := os.ReadFile(path)
	other := New(path)
	defer other.Close()
	if e := other.Record(pcapio.Record{Data: []byte{5}, LinkType: wire.LinkEthernet}); e == nil {
		t.Fatal("existing evidence overwritten")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("existing capture changed")
	}
}
