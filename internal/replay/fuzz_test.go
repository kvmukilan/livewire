package replay

import (
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

func FuzzTraceExtractionCoverage(f *testing.F) {
	f.Add([]byte{0, 1, 2})
	f.Add(ipv4Frame(wire.ProtoUDP, [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, udp(1000, 53, []byte("x"))))
	f.Fuzz(func(t *testing.T, frame []byte) {
		if len(frame) > 1<<20 {
			t.Skip()
		}
		record := &pcapio.Record{Time: time.Unix(0, 0), Data: append([]byte(nil), frame...), CapLen: len(frame), OrigLen: len(frame), LinkType: wire.LinkEthernet}
		trace := ExtractTrace([]*pcapio.Record{record}, ExtractOptions{})
		plan := BuildPlan(trace, ProfileFunctional, nil)
		if err := plan.ValidateCoverage(); err != nil {
			t.Fatal(err)
		}
	})
}
