package dissect

import (
	"strings"
	"testing"
)

func TestParseDNP3Stream(t *testing.T) {
	// Build a valid response frame via Encode (correct CRCs), then parse it back.
	d := DNP3{Control: 0x44, Dest: 1, Source: 10,
		UserData: []byte{0x00, 0x00, 0x81}, HasTransport: true, HasApp: true}
	frame := d.Encode()
	frames, leftover, err := ParseDNP3Stream(frame)
	if err != nil || leftover != 0 || len(frames) != 1 {
		t.Fatalf("ParseDNP3Stream: err=%v leftover=%d n=%d", err, leftover, len(frames))
	}
	if frames[0].AppFunc != 0x81 {
		t.Fatalf("app function = 0x%02x, want 0x81", frames[0].AppFunc)
	}
}

func TestCompareDNP3(t *testing.T) {
	want := DNP3{HasApp: true, AppFunc: 0x81, AppSeq: 3, UserData: []byte{0x81, 0x00, 0x00}}

	if d := CompareDNP3(want, want); len(d) != 0 {
		t.Fatalf("identical frames should not differ, got %+v", d)
	}

	// Different application function -> structural.
	badFn := want
	badFn.AppFunc = 0x82
	d := CompareDNP3(want, badFn)
	if len(d) == 0 || !d[0].Structural || !strings.Contains(d[0].Detail, "function") {
		t.Fatalf("function change should be structural, got %+v", d)
	}

	// Same function, different user data -> non-structural value drift.
	drift := want
	drift.UserData = []byte{0x81, 0x11, 0x22}
	d = CompareDNP3(want, drift)
	if len(d) != 1 || d[0].Structural {
		t.Fatalf("data drift should be one non-structural diff, got %+v", d)
	}
}
