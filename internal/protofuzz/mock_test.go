package protofuzz

import "testing"

// newMockTarget starts a mock target on an ephemeral loopback port and closes it
// when the test finishes. The server itself ships in target.go, so the suite and
// 'livewire fuzz -demo' exercise exactly the same implementation.
func newMockTarget(t *testing.T, d Defects) *MockTarget {
	t.Helper()
	m, err := ServeMock("127.0.0.1:0", d)
	if err != nil {
		t.Fatalf("ServeMock: %v", err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}
