package units

import (
	"math"
	"testing"
	"testing/quick"
)

func TestAddSubRoundTrip(t *testing.T) {
	f := func(a, n uint32) bool {
		return Seq(a).Add(n).Sub(n) == Seq(a)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Fatal(err)
	}
}

func TestDeltaReconstructs(t *testing.T) {
	// For any pair, s.AddDelta(s.Delta(o)) == o, including across the wrap.
	f := func(a, b uint32) bool {
		s, o := Seq(a), Seq(b)
		return s.AddDelta(s.Delta(o)) == o
	}
	if err := quick.Check(f, nil); err != nil {
		t.Fatal(err)
	}
}

func TestWrapBoundary(t *testing.T) {
	near := Seq(math.MaxUint32 - 1) // 0xFFFFFFFE
	if got := near.Add(3); got != Seq(1) {
		t.Fatalf("wrap add: got %d want 1", got)
	}
	if !near.Less(near.Add(3)) {
		t.Fatal("0xFFFFFFFE should be Less than 1 across the wrap")
	}
	if !Seq(0).Greater(Seq(math.MaxUint32)) {
		t.Fatal("0 should be Greater than 0xFFFFFFFF (one step apart)")
	}
}

func TestOrderingIsAntisymmetric(t *testing.T) {
	// For distinct values less than 2^31 apart, exactly one of Less/Greater holds.
	f := func(a uint32, d uint16) bool {
		if d == 0 {
			return true
		}
		s := Seq(a)
		o := s.Add(uint32(d)) // within 2^31, so ordering is well-defined
		return s.Less(o) && o.Greater(s) && !o.Less(s)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Fatal(err)
	}
}

func TestBetween(t *testing.T) {
	lo := Seq(0xFFFFFFF0)
	hi := lo.Add(0x20) // wraps past zero to 0x10
	if !Seq(0xFFFFFFF8).Between(lo, hi) {
		t.Fatal("value inside wrapped window should be Between")
	}
	if !Seq(0x05).Between(lo, hi) {
		t.Fatal("value past the wrap inside window should be Between")
	}
	if Seq(0x40).Between(lo, hi) {
		t.Fatal("value outside window should not be Between")
	}
}
