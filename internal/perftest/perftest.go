// Package perftest gates latency-budget assertions behind an explicit opt-in.
//
// Tail-latency budgets — a p99 taken over a few hundred samples — are noisy
// when measured on a shared CI runner, and more so under the `-race` detector,
// which inflates timing by design. Gating a merge on such a budget produces
// false failures on changes that cannot affect performance (a docs-only PR has
// tripped the job-queue enqueue budget at 11ms vs a 10ms target).
//
// So by default these checks RUN and LOG their measurement but do NOT fail the
// build. To enforce the budgets — on a quiet, dedicated runner, ideally a
// non-`-race` build — set OPENWATCH_PERF_ASSERT=1.
package perftest

import (
	"fmt"
	"os"
	"testing"
)

// envEnforce is the opt-in switch for latency-budget enforcement.
const envEnforce = "OPENWATCH_PERF_ASSERT"

// Enforce reports whether latency budgets should fail the test rather than
// only log. False unless OPENWATCH_PERF_ASSERT=1.
func Enforce() bool { return os.Getenv(envEnforce) == "1" }

// Budgetf records a latency-budget overrun. Call it on the over-budget path
// with the same message you would have passed to t.Errorf. When enforcement is
// enabled it fails the test; otherwise it logs the overrun and lets the test
// pass, so a noisy runner never produces a false failure.
func Budgetf(t testing.TB, format string, args ...any) {
	t.Helper()
	msg := fmt.Sprintf(format, args...)
	if Enforce() {
		t.Error(msg)
		return
	}
	t.Logf("perf (non-gating; set %s=1 to enforce): %s", envEnforce, msg)
}
