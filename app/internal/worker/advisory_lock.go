// Per-host concurrency guard for the scan-job worker.
//
// Two workers must not execute scans against the same host simultaneously
// (system-worker-subcommand C-09 / AC-07). The guard is a PostgreSQL
// transaction-scoped advisory lock keyed on a deterministic int64 hash of
// the host_id UUID. The lock is acquired with pg_advisory_xact_lock inside
// a transaction; it releases automatically on commit or rollback.
//
// The hash derivation is FNV-1a 64-bit over the UUID's 16 raw bytes, cast
// to int64 (two's complement). Pinned by AC-15 source inspection — a
// future contributor who silently changes the strategy would split workers
// across pre/post-change deployments and let two concurrent scans race.

package worker

import (
	"context"
	"hash/fnv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// hostLockKey derives the advisory-lock key for a host UUID. Pure
// function; no DB access. FNV-1a 64-bit over uuid[:] bytes, cast to int64.
//
// Spec: system-worker-subcommand AC-15 (source-inspection pins the
// pattern: hash/fnv.New64a + Write(uuid[:]) + Sum64() + int64(cast)).
func hostLockKey(hostID uuid.UUID) int64 {
	h := fnv.New64a()
	h.Write(hostID[:])
	return int64(h.Sum64())
}

// acquireHostLock takes a pg_advisory_xact_lock keyed on the host. The
// returned tx must be committed or rolled back to release the lock —
// callers MUST defer one of the two. Blocks until the lock is available.
//
// Returns the tx so the caller can carry it through executor.Run and
// transactionlog.Writer.Apply on success, then Commit. On any failure
// path, Rollback releases the lock.
func acquireHostLock(ctx context.Context, db pgxBeginner, hostID uuid.UUID) (pgx.Tx, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, hostLockKey(hostID)); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	return tx, nil
}

// pgxBeginner is the subset of pgxpool.Pool we need. Defined locally so
// tests can pass a fake.
type pgxBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}
