//go:build !race

package audit

import "time"

// burstFlushBudget is the wall-clock budget for TestEmit_BurstFlushes1000.
// Spec system-audit-emission AC-05 sets it at 200ms. The race detector
// adds ~10x instrumentation overhead — the parallel _race file relaxes
// the budget when -race is set, but the spec target stands without it.
const burstFlushBudget = 200 * time.Millisecond
