package adapters

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/kvmukilan/livewire/internal/replay"
)

// dnsCompressedResponse answers a CNAME question with a CNAME whose target is
// compressed against the question's parent domain, then an A record whose owner
// points at that CNAME target: pointers to the question, into it, and past it.
func dnsCompressedResponse(t *testing.T, name string) []byte {
	t.Helper()
	b := []byte{0, 7, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0}
	question, err := encodeDNSName(name)
	if err != nil {
		t.Fatal(err)
	}
	b = append(append(b, question...), 0, 5, 0, 1)
	parent := 12 + 1 + len(strings.Split(name, ".")[0])
	rdata := []byte{5, 'a', 'l', 'i', 'a', 's', 0xc0, byte(parent)}
	b = append(b, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, byte(len(rdata)))
	target := len(b)
	b = append(b, rdata...)
	return append(b, 0xc0, byte(target), 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 1)
}

func TestDNSRenameRepairsCompressionPointers(t *testing.T) {
	a := DNS{Transport: replay.TransportUDP}
	captured, err := a.Decode(replay.ServerToClient, dnsCompressedResponse(t, "dev.example.org"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a-much-longer-name.example.org", "x.example.org"} {
		state := replay.NewRuntimeState(map[string]string{"dns.name": name})
		normalized, err := a.NormalizeExpected(replay.ServerToClient, captured[0], state)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// What a live server would send for the renamed question.
		live, err := a.Decode(replay.ServerToClient, dnsCompressedResponse(t, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(normalized.Raw) != string(live[0].Raw) {
			t.Fatalf("%s: renamed response\n% x\nwant\n% x", name, normalized.Raw, live[0].Raw)
		}
	}
	// A deeper name keeps the alias under the captured parent domain.
	deep, err := a.NormalizeExpected(replay.ServerToClient, captured[0], replay.NewRuntimeState(map[string]string{"dns.name": "deep.sub.example.org"}))
	if err != nil {
		t.Fatal(err)
	}
	if alias, _, err := dnsName(deep.Raw, 12+len("\x04deep\x03sub\x07example\x03org\x00")+4+12, 0); err != nil || alias != "alias.example.org" {
		t.Fatalf("alias after deeper rename = %q, %v", alias, err)
	}
	state := replay.NewRuntimeState(map[string]string{"dns.name": "dev.other.net"})
	if _, err := a.NormalizeExpected(replay.ServerToClient, captured[0], state); err == nil || !strings.Contains(err.Error(), `must stay under "example.org"`) {
		t.Fatalf("rename out of the compressed parent domain: %v", err)
	}
}

func TestDNSRenameOverTCPKeepsLengthPrefix(t *testing.T) {
	a := DNS{Transport: replay.TransportTCP}
	raw := dnsCompressedResponse(t, "dev.example.org")
	framed := append(binary.BigEndian.AppendUint16(nil, uint16(len(raw))), raw...)
	captured, err := a.Decode(replay.ServerToClient, framed)
	if err != nil {
		t.Fatal(err)
	}
	state := replay.NewRuntimeState(map[string]string{"dns.name": "longer-device.example.org"})
	normalized, err := a.NormalizeExpected(replay.ServerToClient, captured[0], state)
	if err != nil {
		t.Fatal(err)
	}
	want := dnsCompressedResponse(t, "longer-device.example.org")
	if int(binary.BigEndian.Uint16(normalized.Raw)) != len(want) || string(normalized.Raw[2:]) != string(want) {
		t.Fatalf("renamed TCP response % x", normalized.Raw)
	}
}
