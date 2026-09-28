package dissect

import "testing"

func TestDNP3SecurityInspectionFollowsTransportAndObjectBoundaries(t *testing.T) {
	frame := func(transport byte, data []byte) []byte {
		return (DNP3{Control: 0x44, Source: 4, Dest: 1, UserData: append([]byte{transport}, data...)}).Encode()
	}
	first := []byte{0xc1, 0x81, 0, 0, 30, 1, 0, 0, 0, 1, 42, 0, 0, 0}
	last := []byte{120, 1, 7, 1, 0, 0, 0}
	stream := append(frame(0x40|63, first), frame(0x80, last)...)
	recognized, secure, err := InspectDNP3Stream(stream)
	if err != nil || !recognized || !secure {
		t.Fatalf("recognized=%v secure=%v err=%v", recognized, secure, err)
	}
	if _, secure, err = InspectDNP3Stream(frame(0xc0, first)); err != nil || secure {
		t.Fatalf("plain objects rejected: secure=%v err=%v", secure, err)
	}
	unknown := append(append([]byte(nil), first...), 199, 1, 7, 1, 0)
	if _, _, err = InspectDNP3Stream(frame(0xc0, unknown)); err == nil {
		t.Fatal("unknown object width treated as safe")
	}
	if _, _, err = InspectDNP3Stream(frame(0x40, first)); err == nil {
		t.Fatal("incomplete fragment treated as safe")
	}
}
