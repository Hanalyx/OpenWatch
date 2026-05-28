//go:build race

package audit

import "time"

// burstFlushBudget under the race detector. Same 2-second budget as the
// non-race build — race instrumentation adds ~10x overhead on hot inserts,
// but the budget is already wide enough to absorb that on top of CI DB
// latency. See race_off_test.go and spec system-audit-emission AC-05.
const burstFlushBudget = 2 * time.Second
