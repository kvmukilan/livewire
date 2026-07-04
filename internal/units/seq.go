// Package units defines wrap-safe TCP sequence-number arithmetic. Seq/Ack wrap
// modulo 2^32 (RFC 793 / RFC 9293) and keep all comparison and delta logic in
// one place instead of scattering raw uint32 math.
package units

// Seq is a TCP sequence number. Arithmetic wraps modulo 2^32.
type Seq uint32

// Ack is a TCP acknowledgement number. It shares Seq's representation and rules.
type Ack = Seq

// Add returns s advanced by n, wrapping modulo 2^32.
func (s Seq) Add(n uint32) Seq { return Seq(uint32(s) + n) }

// Sub returns s reduced by n, wrapping modulo 2^32.
func (s Seq) Sub(n uint32) Seq { return Seq(uint32(s) - n) }

// Delta returns the wrapping distance from s to o: the d where s.Add(d) == o.
func (s Seq) Delta(o Seq) uint32 { return uint32(o) - uint32(s) }

// AddDelta applies a raw wrapping delta (from Delta) to s. Used to realign a
// captured sequence onto a live peer: captured.AddDelta(liveISN.Delta(capturedISN)).
func (s Seq) AddDelta(d uint32) Seq { return Seq(uint32(s) + d) }

// Less reports whether s is strictly before o (RFC 1982 serial-number order).
// Correct across the wrap for distances below 2^31.
func (s Seq) Less(o Seq) bool { return int32(uint32(s)-uint32(o)) < 0 }

// LessEqual reports whether s is at or before o (RFC 1982).
func (s Seq) LessEqual(o Seq) bool { return s == o || s.Less(o) }

// Greater reports whether s is strictly after o (RFC 1982).
func (s Seq) Greater(o Seq) bool { return o.Less(s) }

// GreaterEqual reports whether s is at or after o (RFC 1982).
func (s Seq) GreaterEqual(o Seq) bool { return s == o || o.Less(s) }

// Between reports whether s lies in the half-open window [lo, hi) (RFC 1982).
func (s Seq) Between(lo, hi Seq) bool { return s.GreaterEqual(lo) && s.Less(hi) }

// Uint32 returns the underlying value in host byte order.
func (s Seq) Uint32() uint32 { return uint32(s) }
