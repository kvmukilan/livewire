package secureexec

import (
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/adapters"
	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/tlsreplay"
)

func TestTLSDNP3ScriptNormalizesFragmentsAcrossRecordsAndConfirms(t *testing.T) {
	frame := func(src, dst uint16, transport byte, app []byte) []byte {
		return (dissect.DNP3{Control: 0x44, Source: src, Dest: dst, UserData: append([]byte{transport}, app...)}).Encode()
	}
	request := frame(1, 4, 0xc1, []byte{0xc1, 1, 30, 1, 6})
	first := frame(4, 1, 0xc1, []byte{0xa1, 0x81, 0, 0, 30, 1, 0, 0, 0, 1, 42, 0, 0, 0})
	confirm := frame(1, 4, 0xc2, []byte{0xc1, 0})
	last := frame(4, 1, 0xc2, []byte{0x42, 0x81, 0, 0, 30, 1, 0, 1, 1, 1, 43, 0, 0, 0})
	var records []tlsreplay.AppMessage
	appendRecord := func(role tlsreplay.AppRole, data []byte) {
		records = append(records, tlsreplay.AppMessage{Role: role, Data: data, HasCaptureTime: true, CapturedAt: time.Duration(len(records)) * time.Millisecond, CapturedPacket: len(records)})
	}
	appendRecord(tlsreplay.FromClient, request[:7])
	appendRecord(tlsreplay.FromClient, request[7:])
	appendRecord(tlsreplay.FromServer, first[:11])
	appendRecord(tlsreplay.FromServer, first[11:])
	appendRecord(tlsreplay.FromClient, confirm)
	appendRecord(tlsreplay.FromServer, last[:9])
	appendRecord(tlsreplay.FromServer, last[9:])
	script, err := BuildTLSAdapterScript(records, adapters.DNP3{}, replay.NewRuntimeState(nil))
	if err != nil || len(script) != 2 {
		t.Fatalf("script=%+v err=%v", script, err)
	}
	if script[0].Request == nil || len(script[1].Expected) != 1 || script[1].CapturedAt != 6*time.Millisecond {
		t.Fatalf("wrong logical script or completion time: %+v", script)
	}
	live := frame(4, 1, 0xc9, []byte{0xc1, 0x81, 0, 0, 30, 1, 0, 0, 1, 1, 42, 0, 0, 0, 1, 43, 0, 0, 0})
	m, err := (adapters.DNP3{}).Decode(replay.ServerToClient, live)
	if err != nil {
		t.Fatal(err)
	}
	if diff := (adapters.DNP3{}).Compare(script[1].Expected[0], m[0], replay.VerifyStrict); len(diff) > 0 {
		t.Fatalf("TLS logical response mismatch: %+v", diff)
	}
}
