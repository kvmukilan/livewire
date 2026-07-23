package main

import "testing"

func TestParseFidelityProfile(t *testing.T) {
	cases := []struct {
		name                string
		adaptive, pace, raw bool
	}{
		{"functional", true, false, false},
		{"timing", true, true, false},
		{"transport", false, true, true},
		{"wire", false, true, true},
	}
	for _, tc := range cases {
		p, err := parseFidelityProfile(tc.name)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if p.Adaptive != tc.adaptive || p.Pace != tc.pace || p.RawL4 != tc.raw {
			t.Fatalf("%s profile has unexpected settings: %+v", tc.name, p)
		}
	}
	if _, err := parseFidelityProfile("magic"); err == nil {
		t.Fatal("unknown profile should fail")
	}
}
