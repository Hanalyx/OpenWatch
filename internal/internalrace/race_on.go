//go:build race

package internalrace

// Multiplier returns 20 when the race detector is on. -race overhead is
// typically 5-10x for CPU-bound code, 10-20x for hot-path goroutine
// scheduling. 20 is the safe ceiling.
func Multiplier() int { return 20 }

// Enabled reports whether the race detector is compiled in.
func Enabled() bool { return true }
