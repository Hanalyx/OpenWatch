//go:build race

package audit

import "time"

// burstFlushBudget under the race detector. -race adds ~10x instrumentation
// overhead on hot inserts; the spec target is preserved without -race.
const burstFlushBudget = 2 * time.Second
