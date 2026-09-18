//go:build !windows && !linux

package qualification

// peakRSS is unavailable on this platform; benchmarks record zero and the
// metrics file names the sampling method so a reader knows why.
func peakRSS(int) uint64 { return 0 }
