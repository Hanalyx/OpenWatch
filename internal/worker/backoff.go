// Backoff ladder for transient scan failures.
//
// system-worker-subcommand C-05 / AC-10: when executor.Run returns a
// transient error, the worker calls queue.Fail (the queue has no
// retry-with-next-attempt-at infrastructure) AND UPSERTs
// host_backoff_state.suppress_until to throttle the scheduler dispatcher.
//
// Ladder (per consecutive_failures count after UPSERT):
//
//   1 → 1 min
//   2 → 2 min
//   3 → 4 min
//   4 → 8 min
//   5 → 16 min
//   6+ → 24 h (ceiling)
//
// Reset to 0 on a successful scan via kensa.Executor.RecordSuccess.

package worker

import "time"

// MaxBackoff is the suppress_until ceiling that kicks in at the 6th
// consecutive failure. After this point, the scheduler dispatcher will
// not enqueue a new job for the host for 24h — that is the de facto
// dead-letter.
const MaxBackoff = 24 * time.Hour

// transientBackoff returns the suppression interval for the given
// post-increment consecutive_failures value. Pure function for
// unit-testability — no clock dependency, no DB access.
//
// Spec: system-worker-subcommand C-05 / AC-04 / AC-10.
func transientBackoff(consecutiveFailures int) time.Duration {
	switch consecutiveFailures {
	case 1:
		return 1 * time.Minute
	case 2:
		return 2 * time.Minute
	case 3:
		return 4 * time.Minute
	case 4:
		return 8 * time.Minute
	case 5:
		return 16 * time.Minute
	default:
		// f <= 0 should not happen (UPSERT always increments to >= 1).
		// f >= 6 hits the 24h ceiling.
		if consecutiveFailures <= 0 {
			return 0
		}
		return MaxBackoff
	}
}
