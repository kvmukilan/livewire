package dissect

import (
	"bytes"
	"testing"
)

func TestDNP3ApplicationHeaderOnlyInFirstTransportSegment(t *testing.T) {
	for _, tc := range []struct {
		name      string
		transport byte
		app       byte
		hasApp    bool
		appFirst  bool
	}{
		{"first application fragment", 0x40, 0xc1, true, true},
		{"later application fragment", 0xc0, 0x41, true, false},
		{"middle transport segment", 0x01, 0xc1, false, false},
		{"last transport segment", 0x82, 0xc1, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := (DNP3{Control: 0x44, Source: 4, Dest: 1, UserData: []byte{tc.transport, tc.app, 0x81, 0x11}}).Encode()
			d, _, err := ParseDNP3(raw)
			if err != nil {
				t.Fatal(err)
			}
			if d.HasApp != tc.hasApp || d.AppFIR != tc.appFirst {
				t.Fatalf("HasApp=%v AppFIR=%v, want %v %v", d.HasApp, d.AppFIR, tc.hasApp, tc.appFirst)
			}
			if !d.HasApp {
				d.AppSeq = 7 // changing absent header metadata must not corrupt object bytes
			}
			if !bytes.Equal(d.Encode(), raw) {
				t.Fatal("round trip changed transport segment payload")
			}
		})
	}
}
