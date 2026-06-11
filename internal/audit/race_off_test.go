//go:build !race

package audit

import "time"

// burstFlushBudget is the wall-clock budget for TestEmit_BurstFlushes1000.
// Spec system-audit-emission AC-05 sets it at 2 seconds — wide enough
// to be robust on shared-CI Postgres containers (where commit latency
// dominates), while still proving the flush mechanism works end to end.
// Production hardware completes well under 500ms.
const burstFlushBudget = 2 * time.Second
