package replayintent

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/wire"
)

// Fixtures preserve sequence numbers and both directions so inspection uses
// the same reassembly and adapter validation as a capture loaded from disk.
func exchange(port, clientPort uint16, request, response []byte) []*pcapio.Record {
	frame := func(reverse bool, seq, ack uint32, flags byte, payload []byte) *pcapio.Record {
		src, dst := netip.MustParseAddr("192.0.2.10").As4(), netip.MustParseAddr("192.0.2.20").As4()
		sp, dp := clientPort, port
		if reverse {
			src, dst, sp, dp = dst, src, dp, sp
		}
		data := make([]byte, 54+len(payload))
		copy(data[:12], []byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1})
		binary.BigEndian.PutUint16(data[12:14], 0x0800)
		data[14], data[22], data[23] = 0x45, 64, 6
		binary.BigEndian.PutUint16(data[16:18], uint16(40+len(payload)))
		copy(data[26:30], src[:])
		copy(data[30:34], dst[:])
		binary.BigEndian.PutUint16(data[34:36], sp)
		binary.BigEndian.PutUint16(data[36:38], dp)
		binary.BigEndian.PutUint32(data[38:42], seq)
		binary.BigEndian.PutUint32(data[42:46], ack)
		data[46], data[47] = 0x50, flags
		binary.BigEndian.PutUint16(data[48:50], 65535)
		copy(data[54:], payload)
		return &pcapio.Record{Data: data, CapLen: len(data), OrigLen: len(data), LinkType: wire.LinkEthernet}
	}
	rows := []*pcapio.Record{frame(false, 100, 0, 2, nil), frame(true, 900, 101, 18, nil), frame(false, 101, 901, 16, nil), frame(false, 101, 901, 24, request)}
	if len(response) > 0 {
		rows = append(rows, frame(true, 901, 101+uint32(len(request)), 24, response))
	}
	for i, r := range rows {
		r.Time = time.Unix(1, int64(i)*int64(time.Millisecond))
	}
	return rows
}

func arp() *pcapio.Record {
	b, _ := hex.DecodeString("ffffffffffff02000000000108060001080006040001020000000001c000020a000000000000c0000214")
	return &pcapio.Record{Data: b, CapLen: len(b), OrigLen: len(b), LinkType: wire.LinkEthernet, Time: time.Unix(2, 0)}
}

func TestIntentPolicyAndPacketAccounting(t *testing.T) {
	binaryBody := make([]byte, 2048)
	_, _ = rand.New(rand.NewSource(92)).Read(binaryBody)
	http := exchange(80, 41000, []byte("GET / HTTP/1.1\r\nHost: device\r\n\r\n"), append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(binaryBody))), binaryBody...))
	tls := exchange(443, 41001, []byte{0x16, 3, 3, 0, 4, 1, 0, 0, 0}, nil)
	ssh := exchange(22, 41002, []byte("SSH-2.0-client\r\n"), []byte("SSH-2.0-server\r\n"))
	opaque := exchange(4567, 41003, binaryBody, nil)
	unknown := exchange(4567, 41004, []byte{1, 2, 3, 4}, nil)
	cases := []struct {
		name, mode       string
		records          []*pcapio.Record
		sessions         []string
		supported, iface bool
		route            Kind
		excluded         int
	}{
		{"binary HTTP application", "application", http, nil, true, false, Generic, 0},
		{"binary HTTP automatic", "auto", http, nil, true, false, Generic, 0},
		{"opaque automatic", "auto", opaque, nil, false, false, Opaque, 0},
		{"opaque explicit transport", "transport", opaque, nil, true, true, Generic, 0},
		{"unknown application", "application", unknown, nil, false, false, Generic, 0},
		{"TLS fresh session", "application", tls, nil, true, false, TLS, 0},
		{"TLS transport refused", "transport", tls, nil, false, false, TLS, 0},
		{"TLS wire", "wire", tls, nil, true, true, "wire", 0},
		{"SSH fresh session", "application", ssh, nil, true, false, SSH, 0},
		{"SSH transport refused", "transport", ssh, nil, false, false, SSH, 0},
		{"mixed security refused", "application", append(append([]*pcapio.Record{}, tls...), ssh...), nil, false, false, Opaque, 0},
		{"mixed security selected", "application", append(append([]*pcapio.Record{}, tls...), ssh...), []string{"tcp-0"}, true, false, TLS, len(ssh)},
		{"background ARP refused", "application", append(append([]*pcapio.Record{}, http...), arp()), nil, false, false, Generic, 0},
		{"background ARP excluded", "application", append(append([]*pcapio.Record{}, http...), arp()), []string{"tcp-0"}, true, false, Generic, 1},
		{"only raw selected", "wire", append(append([]*pcapio.Record{}, http...), arp()), []string{"raw-0"}, true, true, "wire", len(http)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Inspect(tc.records, Options{Mode: tc.mode, Sessions: tc.sessions}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got.Readiness.Supported != tc.supported || got.Readiness.Route != tc.route {
				t.Fatalf("readiness: %+v", got.Readiness)
			}
			if tc.supported && got.Readiness.NeedsInterface != tc.iface {
				t.Fatalf("interface requirement: %+v", got.Readiness)
			}
			if got.ExcludedPackets != tc.excluded || got.SelectedPackets+got.ExcludedPackets != len(tc.records) {
				t.Fatalf("packet accounting: %+v", got)
			}
			if err := got.Plan.ValidateCoverage(); err != nil {
				t.Fatal(err)
			}
			if !tc.supported {
				if got.Readiness.State != "blocked" || got.Readiness.Blocker == "" {
					t.Fatalf("missing diagnostic: %+v", got.Readiness)
				}
				for _, e := range got.Plan.Entries {
					if !e.Excluded && e.Mode != replay.ModeBlocked {
						t.Fatalf("blocked readiness advertises runnable entry: %+v", e)
					}
				}
			}
			if tc.mode == "wire" {
				for _, r := range got.Readiness.Requirements {
					if strings.Contains(r, "key") {
						t.Fatalf("wire requires credentials: %s", r)
					}
				}
			}
		})
	}
}

func TestInvalidOptionsAndTruncatedCapture(t *testing.T) {
	secure := exchange(443, 41000, []byte{0x16, 3, 3, 0, 4, 1, 0, 0, 0}, nil)
	timing, err := Inspect(secure, Options{Mode: "application", Profile: "timing"}, nil)
	if err != nil || timing.Readiness.Supported || !strings.Contains(timing.Readiness.Blocker, "functional profile") {
		t.Fatalf("secure preview promises unsupported timing: %v %+v", err, timing)
	}
	for _, opts := range []Options{{Mode: "guess"}, {Profile: "unknown"}, {Mode: "application", Profile: "wire"}, {Mode: "transport", Profile: "wire"}, {Sessions: []string{"tcp-99"}}, {KeyLog: []byte("CLIENT_RANDOM invalid invalid\n")}} {
		if _, err := Inspect(nil, opts, nil); err == nil {
			t.Fatalf("accepted %+v", opts)
		}
	}
	for _, mode := range []string{"application", "wire"} {
		rows := exchange(443, 41000, []byte{0x16, 3, 3, 0, 4, 1, 0, 0, 0}, nil)
		rows[3].OrigLen++
		got, err := Inspect(rows, Options{Mode: mode}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got.Readiness.Supported || !strings.Contains(got.Readiness.Blocker, "truncat") {
			t.Fatalf("truncated %s: %+v", mode, got.Readiness)
		}
	}
	got, err := Inspect(nil, Options{}, nil)
	if err != nil || got.Readiness.Supported {
		t.Fatalf("empty capture: %v %+v", err, got)
	}
	mode, p, err := Resolve("", "wire")
	if err != nil || mode != "wire" || p != replay.ProfileWire {
		t.Fatalf("legacy wire alias: %s %s %v", mode, p, err)
	}
}

func TestLabAdvertisesActualActorCapabilities(t *testing.T) {
	rows := exchange(80, 41000, []byte("GET / HTTP/1.1\r\nHost: device\r\n\r\n"), nil)
	for _, mode := range []string{"application", "transport", "wire", "auto"} {
		got, err := InspectLab(rows, Options{Mode: mode})
		if err != nil {
			t.Fatal(err)
		}
		if got.Readiness.Supported != (mode != "application") {
			t.Fatalf("lab %s: %+v", mode, got.Readiness)
		}
		if !got.Readiness.NeedsInterface {
			t.Fatal("lab lacks interface requirement")
		}
	}
	if _, err := InspectLab(rows, Options{Sessions: []string{"tcp-0"}}); err == nil {
		t.Fatal("lab accepted partial topology")
	}
	if _, err := InspectLab(rows, Options{Mode: "unknown"}); err == nil {
		t.Fatal("lab accepted invalid mode")
	}
	for _, rows := range [][]*pcapio.Record{nil, append(rows, arp())} {
		got, err := InspectLab(rows, Options{Mode: "transport"})
		if err != nil || got.Readiness.Supported {
			t.Fatalf("unsupported lab: %v %+v", err, got)
		}
	}
}

func TestKeyLogRegistryIsRequestScoped(t *testing.T) {
	base, err := RegistryWithKeyLog(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := []byte("CLIENT_RANDOM " + strings.Repeat("00", 32) + " " + strings.Repeat("11", 48) + "\n")
	keyed, err := RegistryWithKeyLog(base, keys)
	if err != nil {
		t.Fatal(err)
	}
	if keyed == base {
		t.Fatal("key material shared across requests")
	}
	if _, ok := base.ByName("ftp").(keyedFTP); ok {
		t.Fatal("base registry mutated")
	}
	if len(base.Names()) != len(keyed.Names()) {
		t.Fatal("custom registry entries lost")
	}
	rows := exchange(990, 41000, []byte{0x16, 3, 3, 0, 4, 1, 0, 0, 0}, nil)
	got, err := Inspect(rows, Options{Mode: "application", KeyLog: keys}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Readiness.Supported || got.Readiness.Blocker == "" {
		t.Fatalf("unmatched FTPS key accepted: %+v", got.Readiness)
	}
	if NeedsKeyLog(nil) {
		t.Fatal("nil session needs key log")
	}
}
