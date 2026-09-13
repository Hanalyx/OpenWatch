package scheduler

import (
	"testing"

	"github.com/Hanalyx/openwatch/internal/compliance"
)

// mustScore builds a present score through the validated constructor.
//
// Tests go through the same door production does. A test-only shortcut that
// skipped validation would let a fixture assert behavior for a score the product
// can never hold.
func mustScore(t *testing.T, pct float64) compliance.Score {
	t.Helper()
	s, err := compliance.ScoreFromPercent(pct)
	if err != nil {
		t.Fatalf("mustScore(%v): %v", pct, err)
	}
	return s
}
