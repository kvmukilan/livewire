package adapters

import (
	"testing"

	"github.com/kvmukilan/livewire/internal/dissect"
	"github.com/kvmukilan/livewire/internal/replay"
)

func dnpMessage(t *testing.T, source, dest uint16, transport byte, app []byte) replay.Message {
	t.Helper()
	d := dissect.DNP3{Control: 0x44, Source: source, Dest: dest, UserData: append([]byte{transport}, app...)}
	raw := d.Encode()
	f, _, err := dissect.ParseDNP3(raw)
	if err != nil {
		t.Fatal(err)
	}
	return replay.Message{Kind: "dnp3", Raw: raw, Fields: map[string]any{"source": f.Source, "destination": f.Dest, "appSeq": f.AppSeq, "function": f.AppFunc, "transportSeq": f.TransportSeq}}
}

func TestDNP3FragmentStateIsPerLink(t *testing.T) {
	a := DNP3{}
	state := replay.NewRuntimeState(nil)
	for _, m := range []replay.Message{
		dnpMessage(t, 4, 1, 0x40|63, []byte{0xc1, 0x81, 0, 0}),
		dnpMessage(t, 5, 1, 0x40|8, []byte{0xc1, 0x81, 0, 0}),
		dnpMessage(t, 4, 1, 0x80, []byte{0x11, 0x22}),
		dnpMessage(t, 5, 1, 0x80|9, []byte{0x33, 0x44}),
	} {
		if err := replay.Observe(a, replay.ServerToClient, m, m, state); err != nil {
			t.Fatal(err)
		}
	}
	first := dnpMessage(t, 4, 1, 0x40|5, []byte{0xc2, 0x81, 0, 0})
	gap := dnpMessage(t, 4, 1, 0x80|7, []byte{0x11, 0x22})
	if err := replay.Observe(a, replay.ServerToClient, first, first, state); err != nil {
		t.Fatal(err)
	}
	if err := replay.Observe(a, replay.ServerToClient, gap, gap, state); err == nil {
		t.Fatal("transport sequence gap was accepted")
	}
}

func TestDNP3UnsolicitedConfirmationMappingIsPerLink(t *testing.T) {
	a := DNP3{}
	state := replay.NewRuntimeState(nil)
	for _, link := range []struct {
		source uint16
		seq    byte
	}{{4, 8}, {5, 9}} {
		captured := dnpMessage(t, link.source, 1, 0xc0, []byte{0xd1, 0x82, 0, 0})
		actual := dnpMessage(t, link.source, 1, 0xc0, []byte{0xd0 | link.seq, 0x82, 0, 0})
		if err := replay.Observe(a, replay.ServerToClient, captured, actual, state); err != nil {
			t.Fatal(err)
		}
	}
	for _, link := range []struct {
		dest uint16
		seq  byte
	}{{4, 8}, {5, 9}} {
		confirm := dnpMessage(t, 1, link.dest, 0xc0, []byte{0xd1, 0})
		raw, err := a.Prepare(replay.ClientToServer, confirm, state)
		if err != nil {
			t.Fatal(err)
		}
		d, _, err := dissect.ParseDNP3(raw)
		if err != nil || d.AppSeq != link.seq {
			t.Fatalf("confirmation for link %d: app sequence=%d want=%d err=%v", link.dest, d.AppSeq, link.seq, err)
		}
	}
}

func TestDNP3ContinuationPayloadIsNotAnApplicationHeader(t *testing.T) {
	a := DNP3{}
	want := dnpMessage(t, 4, 1, 0x81, []byte{0x11, 0x22, 0x33})
	got := dnpMessage(t, 4, 1, 0x81, []byte{0x44, 0x55, 0x66})
	if match := a.Correlate(want, got, replay.NewRuntimeState(nil)); !match.Matched {
		t.Fatalf("continuation data incorrectly used as correlation header: %+v", match)
	}
	diffs := a.Compare(want, got, replay.VerifyLenient)
	if len(diffs) != 1 || diffs[0].Structural {
		t.Fatalf("continuation payload drift classified as header change: %+v", diffs)
	}
	if d := a.Compare(want, got, replay.VerifyStrict); len(d) == 0 || !d[0].Structural {
		t.Fatalf("strict comparison lost payload drift: %+v", d)
	}
}

func TestDNP3CorrelationRequiresSameLinkAndFragmentPhase(t *testing.T) {
	a := DNP3{}
	want := dnpMessage(t, 4, 1, 0x41, []byte{0xc1, 0x81, 0, 0})
	for _, got := range []replay.Message{
		dnpMessage(t, 5, 1, 0x41, []byte{0xc1, 0x81, 0, 0}),
		dnpMessage(t, 4, 2, 0x41, []byte{0xc1, 0x81, 0, 0}),
		dnpMessage(t, 4, 1, 0xc1, []byte{0xc1, 0x81, 0, 0}),
	} {
		if match := a.Correlate(want, got, replay.NewRuntimeState(nil)); match.Matched {
			t.Fatalf("different link or transport fragment boundary correlated: %+v", got.Fields)
		}
	}
}
