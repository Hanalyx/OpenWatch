// @spec system-discovery-scheduler

package discovery

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/queue"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// @ac AC-18
// AC-18 (enqueue half): an enqueue that starts while a failure is being
// recorded waits for it, then sees the backoff and queues nothing. This is
// the path the sweep and host creation use.
func TestEnqueue_WaitsForAFailureBeingRecorded(t *testing.T) {
	t.Run("system-discovery-scheduler/AC-18", func(t *testing.T) {
		pool, hostID, _ := freshDBHost(t)
		ctx := context.Background()
		if _, err := pool.Exec(ctx, "TRUNCATE TABLE job_queue"); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		now := time.Now()
		l := claimLease(t, pool, hostID)

		// A failure being recorded, not yet committed: the same steps, in
		// the same order, as a failed run.
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := lockHost(ctx, tx, hostID); err != nil {
			t.Fatalf("lock: %v", err)
		}
		if err := queue.FailLeased(ctx, tx, l, "host.discovery: test failure"); err != nil {
			t.Fatalf("fail: %v", err)
		}
		if err := recordFailure(ctx, tx, hostID, now, "host.discovery: test failure"); err != nil {
			t.Fatalf("record: %v", err)
		}

		type res struct {
			ok  bool
			err error
		}
		done := make(chan res, 1)
		go func() {
			ectx := claimCtx()
			ok, err := Enqueue(ectx, pool, hostID, now)
			done <- res{ok, err}
		}()
		select {
		case r := <-done:
			t.Fatalf("Enqueue returned (ok=%v err=%v) while the failure was uncommitted", r.ok, r.err)
		case <-time.After(300 * time.Millisecond):
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
		select {
		case r := <-done:
			if r.err != nil || r.ok {
				t.Fatalf("Enqueue after the failure committed: ok=%v err=%v, want false, nil", r.ok, r.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("Enqueue still blocked after the failure committed")
		}
		var pending int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM job_queue WHERE status = 'pending'`).Scan(&pending); err != nil {
			t.Fatalf("count: %v", err)
		}
		if pending != 0 {
			t.Fatalf("pending jobs = %d, want 0 during the new backoff", pending)
		}
		// Once the backoff ends, Enqueue queues again.
		if ok, err := Enqueue(claimCtx(), pool, hostID, now.Add(BackoffFor(1))); err != nil || !ok {
			t.Fatalf("Enqueue after the backoff: ok=%v err=%v, want true", ok, err)
		}
	})
}

// pauseInRecordFailure starts fn, which must end by recording a failure for
// hostID, and holds it inside recordFailure: an expired backoff row exists
// and this test holds its row lock. It returns a release func and fn's
// result channel.
func pauseInRecordFailure(t *testing.T, ctx context.Context, pool *pgxpool.Pool, hostID uuid.UUID, fn func() error) (func(), chan error) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		INSERT INTO host_discovery_backoff (host_id, consecutive_failures, last_failure_at, next_attempt_at)
		VALUES ($1, 1, now() - interval '2 hours', now() - interval '1 hour')
		ON CONFLICT (host_id) DO UPDATE SET next_attempt_at = now() - interval '1 hour'`, hostID); err != nil {
		t.Fatalf("seed expired backoff: %v", err)
	}
	holder, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin holder: %v", err)
	}
	if _, err := holder.Exec(ctx, `SELECT 1 FROM host_discovery_backoff WHERE host_id = $1 FOR UPDATE`, hostID); err != nil {
		t.Fatalf("hold backoff row: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- fn() }()
	time.Sleep(300 * time.Millisecond) // let fn reach recordFailure
	return func() { _ = holder.Commit(ctx) }, done
}

// @ac AC-18
// AC-18 (real failure paths): Enqueue waits for a failed run and for a
// stale retirement that are mid-way through recording, and then refuses.
func TestEnqueue_WaitsForRealFailurePaths(t *testing.T) {
	t.Run("system-discovery-scheduler/AC-18", func(t *testing.T) {
		pool, hostID, _ := freshDBHost(t)
		ctx := context.Background()

		paths := map[string]func(l queue.Lease) error{
			"failed run": func(l queue.Lease) error {
				return failRun(ctx, pool, l, hostID, time.Now(), errors.New("test failure"))
			},
			"stale retirement": func(l queue.Lease) error {
				if _, err := pool.Exec(ctx,
					`UPDATE job_queue SET locked_at = now() - make_interval(secs => $2) WHERE id = $1`,
					l.JobID, (StaleDeadline + time.Minute).Seconds()); err != nil {
					return err
				}
				_, err := RetireStaleJobs(ctx, pool, time.Now())
				return err
			},
		}
		for name, path := range paths {
			if _, err := pool.Exec(ctx, "TRUNCATE TABLE job_queue"); err != nil {
				t.Fatalf("truncate: %v", err)
			}
			l := claimLease(t, pool, hostID)
			release, pathDone := pauseInRecordFailure(t, ctx, pool, hostID, func() error { return path(l) })

			enq := make(chan bool, 1)
			go func() {
				ok, err := Enqueue(claimCtx(), pool, hostID, time.Now())
				if err != nil {
					t.Errorf("%s: Enqueue: %v", name, err)
				}
				enq <- ok
			}()
			select {
			case ok := <-enq:
				release()
				t.Fatalf("%s: Enqueue returned %v while the failure was being recorded", name, ok)
			case <-time.After(300 * time.Millisecond):
			}
			release()
			if err := <-pathDone; err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			select {
			case ok := <-enq:
				if ok {
					t.Fatalf("%s: Enqueue queued a job during the new backoff", name)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s: Enqueue still blocked", name)
			}
		}
	})
}
