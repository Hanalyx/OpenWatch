//go:build !race

// Package internalrace exposes a single helper for adjusting performance
// budgets when the race detector is on. -race instrumentation adds ~10x
// runtime overhead on hot paths; perf tests that pass without -race
// would otherwise spuriously fail under it.
//
// Usage:
//
//	if p99 > 50*time.Microsecond*time.Duration(internalrace.Multiplier()) { ... }
//
// Outside of -race the multiplier is 1, so the spec target stands.
package internalrace

// Multiplier returns 1 under normal builds.
func Multiplier() int { return 1 }

// Enabled reports whether the race detector is compiled in.
func Enabled() bool { return false }
