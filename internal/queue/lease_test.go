// @spec system-job-queue
//
// Leased jobs (bugs/OW-120). The partial unique index these tests rely on
// is the host.discovery one from migration 0066, so the job type and the
// payload key are discovery's.

package queue

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/correlation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const leaseJobType = "host.discovery"

func leaseCtx() context.Context {
	return correlation.Set(context.Background(), "req-lease-test")
}

func subject() map[string]string { return map[string]string{"host_id": uuid.NewString()} }

type jobRow struct {
	status    string
	token     *uuid.UUID
	lastError *string
	attempts  int
}

func readJob(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) jobRow {
	t.Helper()
	var r jobRow
	if err := pool.QueryRow(context.Background(),
		`SELECT status, lease_token, last_error, attempts FROM job_queue WHERE id = $1`, id).
		Scan(&r.status, &r.token, &r.lastError, &r.attempts); err != nil {
		t.Fatalf("read job %s: %v", id, err)
	}
	return r
}

// @ac AC-14
// AC-14: every claim mints a fresh lease token.
func TestLease_EveryClaimMintsAToken(t *testing.T) {
	t.Run("system-job-queue/AC-14", func(t *testing.T) {
		pool := freshPool(t)
		ctx := leaseCtx()
		id, err := Enqueue(ctx, pool, "diagnostics.test_job", nil)
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		j, _, err := Dequeue(ctx, pool)
		if err != nil || j.ID != id {
			t.Fatalf("dequeue: %v", err)
		}
		if j.LeaseToken == uuid.Nil || !j.Lease().Valid() {
			t.Fatalf("dequeued job has no lease token")
		}
		first := j.LeaseToken
		if _, err := pool.Exec(ctx, `UPDATE job_queue SET status = 'pending' WHERE id = $1`, id); err != nil {
			t.Fatalf("requeue: %v", err)
		}
		again, _, err := Dequeue(ctx, pool)
		if err != nil {
			t.Fatalf("dequeue again: %v", err)
		}
		if again.LeaseToken == uuid.Nil || again.LeaseToken == first {
			t.Fatalf("second claim token = %s, want a new non-nil token (first %s)", again.LeaseToken, first)
		}

		l, ok, err := Claim(ctx, pool, leaseJobType, subject())
		if err != nil || !ok {
			t.Fatalf("claim: ok=%v err=%v", ok, err)
		}
		r := readJob(t, pool, l.JobID)
		if r.status != "processing" || r.attempts != 1 || r.token == nil || *r.token != l.Token {
			t.Fatalf("claimed row = %+v, want processing, attempts 1, token %s", r, l.Token)
		}
	})
}

// @ac AC-15
// AC-15: EnqueueIfAbsent and Claim answer a unique-index refusal with
// false and no row, and keep the correlation guard.
func TestLease_IfAbsentRespectsTheUniqueIndex(t *testing.T) {
	t.Run("system-job-queue/AC-15", func(t *testing.T) {
		pool := freshPool(t)
		ctx := leaseCtx()
		subj := subject()
		count := func() int {
			var n int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM job_queue WHERE payload->>'host_id' = $1`,
				subj["host_id"]).Scan(&n); err != nil {
				t.Fatalf("count: %v", err)
			}
			return n
		}

		id, ok, err := EnqueueIfAbsent(ctx, pool, leaseJobType, subj)
		if err != nil || !ok || id == uuid.Nil {
			t.Fatalf("first EnqueueIfAbsent: id=%s ok=%v err=%v", id, ok, err)
		}
		if _, ok, err := EnqueueIfAbsent(ctx, pool, leaseJobType, subj); err != nil || ok {
			t.Fatalf("second EnqueueIfAbsent: ok=%v err=%v, want false, nil", ok, err)
		}
		if _, ok, err := Claim(ctx, pool, leaseJobType, subj); err != nil || ok {
			t.Fatalf("Claim with a pending job: ok=%v err=%v, want false, nil", ok, err)
		}
		if n := count(); n != 1 {
			t.Fatalf("rows for the subject = %d, want 1", n)
		}

		// Another subject is unaffected.
		if _, ok, err := Claim(ctx, pool, leaseJobType, subject()); err != nil || !ok {
			t.Fatalf("Claim for another subject: ok=%v err=%v", ok, err)
		}
		// The correlation guard still applies.
		if _, _, err := EnqueueIfAbsent(context.Background(), pool, leaseJobType, subject()); !errors.Is(err, ErrMissingCorrelation) {
			t.Fatalf("EnqueueIfAbsent without correlation: %v, want ErrMissingCorrelation", err)
		}
		if _, _, err := Claim(context.Background(), pool, leaseJobType, subject()); !errors.Is(err, ErrMissingCorrelation) {
			t.Fatalf("Claim without correlation: %v, want ErrMissingCorrelation", err)
		}
	})
}

// @ac AC-16
// AC-16: leased transitions succeed only with the current token.
func TestLease_OnlyTheCurrentTokenFinishes(t *testing.T) {
	t.Run("system-job-queue/AC-16", func(t *testing.T) {
		pool := freshPool(t)
		ctx := leaseCtx()

		claim := func() Lease {
			t.Helper()
			l, ok, err := Claim(ctx, pool, leaseJobType, subject())
			if err != nil || !ok {
				t.Fatalf("claim: ok=%v err=%v", ok, err)
			}
			return l
		}
		inTx := func(fn func(tx pgx.Tx) error) error {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if err := fn(tx); err != nil {
				return err
			}
			return tx.Commit(ctx)
		}

		// Wrong token and zero lease: refused, row unchanged.
		l := claim()
		wrong := Lease{JobID: l.JobID, Token: uuid.New()}
		for name, err := range map[string]error{
			"complete wrong": CompleteLeased(ctx, pool, wrong),
			"fail wrong":     FailLeased(ctx, pool, wrong, "x"),
			"complete zero":  CompleteLeased(ctx, pool, Lease{}),
			"fail zero":      FailLeased(ctx, pool, Lease{}, "x"),
		} {
			if !errors.Is(err, ErrLeaseLost) {
				t.Errorf("%s: %v, want ErrLeaseLost", name, err)
			}
		}
		if r := readJob(t, pool, l.JobID); r.status != "processing" || r.token == nil || *r.token != l.Token {
			t.Fatalf("row changed by refused calls: %+v", r)
		}

		// Current token: complete; the token is cleared.
		if err := CompleteLeased(ctx, pool, l); err != nil {
			t.Fatalf("complete current: %v", err)
		}
		if r := readJob(t, pool, l.JobID); r.status != "completed" || r.token != nil {
			t.Fatalf("after complete: %+v, want completed with no token", r)
		}
		// After finishing, the same lease is refused everywhere.
		if err := FailLeased(ctx, pool, l, "late"); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("fail after complete: %v, want ErrLeaseLost", err)
		}
		if r := readJob(t, pool, l.JobID); r.status != "completed" {
			t.Fatalf("late fail changed a completed job: %+v", r)
		}

		// Fail with the current token records the message.
		f := claim()
		if err := FailLeased(ctx, pool, f, "boom"); err != nil {
			t.Fatalf("fail current: %v", err)
		}
		if r := readJob(t, pool, f.JobID); r.status != "failed" || r.lastError == nil || *r.lastError != "boom" || r.token != nil {
			t.Fatalf("after fail: %+v", r)
		}

		// After RetireStale the lease is refused.
		s := claim()
		if _, err := pool.Exec(ctx, `UPDATE job_queue SET locked_at = now() - interval '1 hour' WHERE id = $1`, s.JobID); err != nil {
			t.Fatalf("backdate: %v", err)
		}
		if err := inTx(func(tx pgx.Tx) error {
			_, err := RetireStale(ctx, tx, leaseJobType, time.Minute, "stale")
			return err
		}); err != nil {
			t.Fatalf("retire: %v", err)
		}
		if err := CompleteLeased(ctx, pool, s); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("complete after retire: %v, want ErrLeaseLost", err)
		}
		if err := FailLeased(ctx, pool, s, "late"); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("fail after retire: %v, want ErrLeaseLost", err)
		}

		// A RetireStale started while another transaction has completed the
		// job under its lease, but not yet committed, waits for it.
		w := claim()
		if _, err := pool.Exec(ctx, `UPDATE job_queue SET locked_at = now() - interval '1 hour' WHERE id = $1`, w.JobID); err != nil {
			t.Fatalf("backdate: %v", err)
		}
		holder, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin holder: %v", err)
		}
		if err := CompleteLeased(ctx, holder, w); err != nil {
			t.Fatalf("complete in holder: %v", err)
		}
		done := make(chan error, 1)
		go func() {
			done <- inTx(func(tx pgx.Tx) error {
				_, err := RetireStale(ctx, tx, leaseJobType, time.Minute, "stale")
				return err
			})
		}()
		select {
		case err := <-done:
			t.Fatalf("RetireStale returned (%v) while the completing transaction was open", err)
		case <-time.After(300 * time.Millisecond):
		}
		if err := holder.Commit(ctx); err != nil {
			t.Fatalf("commit holder: %v", err)
		}
		if err := <-done; err != nil {
			t.Fatalf("retire after holder: %v", err)
		}
		if r := readJob(t, pool, w.JobID); r.status != "completed" {
			t.Fatalf("job completed under its lease ended as %q, want completed", r.status)
		}
	})
}

// @ac AC-17
// AC-17: RetireStale touches only old processing claims of its type.
func TestLease_RetireStaleIsNarrow(t *testing.T) {
	t.Run("system-job-queue/AC-17", func(t *testing.T) {
		pool := freshPool(t)
		ctx := leaseCtx()

		claim := func(jobType string) Lease {
			t.Helper()
			l, ok, err := Claim(ctx, pool, jobType, subject())
			if err != nil || !ok {
				t.Fatalf("claim: ok=%v err=%v", ok, err)
			}
			return l
		}
		backdate := func(id uuid.UUID) {
			t.Helper()
			if _, err := pool.Exec(ctx, `UPDATE job_queue SET locked_at = now() - interval '1 hour' WHERE id = $1`, id); err != nil {
				t.Fatalf("backdate: %v", err)
			}
		}
		old := claim(leaseJobType)
		backdate(old.JobID)
		recent := claim(leaseJobType)
		otherType := claim("diagnostics.test_job")
		backdate(otherType.JobID)
		pendingID, _, err := EnqueueIfAbsent(ctx, pool, leaseJobType, subject())
		if err != nil {
			t.Fatalf("enqueue pending: %v", err)
		}
		if _, err := pool.Exec(ctx, `UPDATE job_queue SET created_at = now() - interval '1 hour' WHERE id = $1`, pendingID); err != nil {
			t.Fatalf("age pending: %v", err)
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		got, err := RetireStale(ctx, tx, leaseJobType, 15*time.Minute, "stale: test")
		if err != nil {
			t.Fatalf("retire: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
		if len(got) != 1 || got[0].ID != old.JobID || len(got[0].Payload) == 0 {
			t.Fatalf("retired = %+v, want only %s with its payload", got, old.JobID)
		}
		if r := readJob(t, pool, old.JobID); r.status != "failed" || r.token != nil || r.lastError == nil || *r.lastError != "stale: test" {
			t.Fatalf("retired row = %+v", r)
		}
		for name, id := range map[string]uuid.UUID{"recent": recent.JobID, "other type": otherType.JobID} {
			if r := readJob(t, pool, id); r.status != "processing" || r.token == nil {
				t.Errorf("%s claim changed: %+v", name, r)
			}
		}
		if r := readJob(t, pool, pendingID); r.status != "pending" {
			t.Errorf("pending job changed: %+v", r)
		}
	})
}
