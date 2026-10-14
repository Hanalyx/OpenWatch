package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Hanalyx/openwatch/internal/queue"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Job ownership and failure backoff for Discovery (bugs/OW-120).
//
// At most one discovery job per host is pending or processing. The database
// enforces it (migration 0066, uq_job_queue_discovery_active), and every path
// that starts a discovery goes through Enqueue or ClaimRun so the refusal is
// an answer rather than an error. Every run holds a lease; its results, its
// failure and the job's completion are written only while the lease is
// current. A failed run backs the host off before the scheduler picks it
// again.
//
// Spec system-discovery-scheduler C-09 to C-12; system-host-discovery C-15.

const (
	// RunTimeout bounds one Discover run, so a live run always ends before
	// StaleDeadline retires its job.
	RunTimeout = 10 * time.Minute

	// StaleDeadline is how long a discovery job may stay processing before
	// the scheduler retires it as stale and counts it as a failure.
	StaleDeadline = 15 * time.Minute

	// BackoffBase is the wait after the first consecutive failure. Each
	// further failure doubles it, up to BackoffCap.
	BackoffBase = 5 * time.Minute

	// BackoffCap is the longest wait between attempts on a failing host.
	BackoffCap = 24 * time.Hour
)

// ErrNoLease is returned by Discover when called without a lease. A run
// that holds no job must not write results.
var ErrNoLease = errors.New("discovery: no job lease")

// Enqueue queues a discovery job for hostID unless one is already pending or
// processing. enqueued=false with a nil error means a job was already active.
// The scheduler, host creation and the sweep all start discovery this way.
//
// Spec system-discovery-scheduler C-09.
func Enqueue(ctx context.Context, db queue.Execer, hostID uuid.UUID) (bool, error) {
	_, enqueued, err := queue.EnqueueIfAbsent(ctx, db, JobKindHostDiscovery,
		HostDiscoveryJobPayload{HostID: hostID})
	return enqueued, err
}

// ClaimRun creates an already-claimed discovery job for a synchronous run,
// so the run holds the host's discovery slot like a queued job does.
// claimed=false with a nil error means a job is already pending or
// processing for the host.
//
// Spec system-host-discovery C-15.
func ClaimRun(ctx context.Context, db queue.Execer, hostID uuid.UUID) (queue.Lease, bool, error) {
	return queue.Claim(ctx, db, JobKindHostDiscovery, HostDiscoveryJobPayload{HostID: hostID})
}

// BackoffFor returns the wait after the nth consecutive failure (n >= 1):
// BackoffBase doubled n-1 times, capped at BackoffCap.
//
// Spec system-discovery-scheduler C-11.
func BackoffFor(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	d := BackoffBase
	for i := 1; i < n; i++ {
		d *= 2
		if d >= BackoffCap {
			return BackoffCap
		}
	}
	return d
}

// recordFailure increments hostID's consecutive failures and sets the next
// time the scheduler may pick it. A host that no longer exists records
// nothing.
func recordFailure(ctx context.Context, tx pgx.Tx, hostID uuid.UUID, now time.Time, errMsg string) error {
	var n int
	err := tx.QueryRow(ctx, `
		SELECT consecutive_failures FROM host_discovery_backoff WHERE host_id = $1 FOR UPDATE`,
		hostID).Scan(&n)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("discovery: read backoff: %w", err)
	}
	n++
	_, err = tx.Exec(ctx, `
		INSERT INTO host_discovery_backoff
		       (host_id, consecutive_failures, last_failure_at, next_attempt_at, last_error)
		SELECT $1, $2, $3, $4, $5
		 WHERE EXISTS (SELECT 1 FROM hosts WHERE id = $1)
		ON CONFLICT (host_id) DO UPDATE
		   SET consecutive_failures = EXCLUDED.consecutive_failures,
		       last_failure_at      = EXCLUDED.last_failure_at,
		       next_attempt_at      = EXCLUDED.next_attempt_at,
		       last_error           = EXCLUDED.last_error`,
		hostID, n, now, now.Add(BackoffFor(n)), errMsg)
	if err != nil {
		return fmt.Errorf("discovery: record backoff: %w", err)
	}
	return nil
}

// clearFailures removes hostID's backoff after a successful run.
func clearFailures(ctx context.Context, tx pgx.Tx, hostID uuid.UUID) error {
	if _, err := tx.Exec(ctx, `DELETE FROM host_discovery_backoff WHERE host_id = $1`, hostID); err != nil {
		return fmt.Errorf("discovery: clear backoff: %w", err)
	}
	return nil
}

// failRun records a failed run: the job is failed under its lease and the
// host backs off, in one transaction. A lost lease records nothing, because
// the job has already been retired and counted.
func failRun(ctx context.Context, pool *pgxpool.Pool, l queue.Lease, hostID uuid.UUID, now time.Time, runErr error) error {
	msg := fmt.Sprintf("host.discovery: %v", runErr)
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("discovery: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := queue.FailLeased(ctx, tx, l, msg); err != nil {
		return err
	}
	if err := recordFailure(ctx, tx, hostID, now, msg); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RetireStaleJobs retires discovery jobs processing for longer than
// StaleDeadline and backs their hosts off, in one transaction. Returns how
// many it retired. The scheduler calls it every tick.
//
// Spec system-discovery-scheduler C-10.
func RetireStaleJobs(ctx context.Context, pool *pgxpool.Pool, now time.Time) (int, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, fmt.Errorf("discovery: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	const msg = "host.discovery: stale: processing deadline exceeded"
	stale, err := queue.RetireStale(ctx, tx, JobKindHostDiscovery, StaleDeadline, msg)
	if err != nil {
		return 0, err
	}
	for _, j := range stale {
		var p HostDiscoveryJobPayload
		if err := json.Unmarshal(j.Payload, &p); err != nil || p.HostID == uuid.Nil {
			continue
		}
		if err := recordFailure(ctx, tx, p.HostID, now, msg); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("discovery: commit: %w", err)
	}
	return len(stale), nil
}
