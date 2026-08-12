// @spec system-license-validation
//
// AC traceability (this file):
//
//	@ac AC-19  (TestWatermark_MissingRowIsZero)
//	@ac AC-20  (TestAdvanceWatermark_NeverMovesBackwards,
//	            TestAdvanceWatermark_MovesForward,
//	            TestAdvanceWatermark_ConcurrentAdvancesSettleOnTheMaximum)
//	@ac AC-21  (TestLicenseClockWatermark_IsASingleton)
//
// These cover the persisted store. AC-16 and AC-18 cover the in-process
// behavior of the same constraints, C-07 and C-13, and are annotated from
// validator_test.go and service_test.go.

package license

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgreSQL SQLSTATE codes the singleton test asserts on. Naming which
// constraint fired is the difference between proving the table refuses a
// second row and proving only that some write failed.
const (
	sqlStateUniqueViolation = "23505"
	sqlStateCheckViolation  = "23514"
)

// watermarkPool returns an isolated, migrated pool with the watermark table
// empty. dbtest.Pool resolves the per-package database from its caller's
// source directory, so this helper has to live in the package under test.
func watermarkPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	if _, err := pool.Exec(context.Background(), `TRUNCATE TABLE license_clock_watermark`); err != nil {
		t.Fatalf("truncate license_clock_watermark: %v", err)
	}
	return pool
}

// microNow returns the current time rounded to what TIMESTAMPTZ can hold.
// PostgreSQL keeps microseconds, Go keeps nanoseconds, so an unrounded value
// does not survive the round trip and every equality assertion would fail for
// a reason that has nothing to do with the watermark.
func microNow() time.Time {
	return time.Now().UTC().Truncate(time.Microsecond)
}

// @ac AC-19
// AC-19: a deployment that has never recorded a watermark reads the zero time
// and no error. Zero is load-bearing: it is what makes Verify skip the rollback
// check on a first boot (C-11). An error here would instead fail the boot path
// that reads it.
func TestWatermark_MissingRowIsZero(t *testing.T) {
	t.Run("system-license-validation/AC-19", func(t *testing.T) {
		pool := watermarkPool(t)

		got, err := Watermark(context.Background(), pool)
		if err != nil {
			t.Fatalf("Watermark with no row: %v, want nil error", err)
		}
		if !got.IsZero() {
			t.Errorf("Watermark with no row = %v, want the zero time", got)
		}
	})
}

// @ac AC-20
// AC-20: C-13 in the database. Verify tolerates an hour of backwards drift, so
// an earlier reading can be accepted and handed to the store. Writing it back
// would drop the watermark, and repeating that would walk it down after a
// wound-back clock with no check ever failing. GREATEST in the upsert makes the
// backwards write a no-op.
func TestAdvanceWatermark_NeverMovesBackwards(t *testing.T) {
	t.Run("system-license-validation/AC-20", func(t *testing.T) {
		pool := watermarkPool(t)
		ctx := context.Background()
		anchor := microNow()

		if err := AdvanceWatermark(ctx, pool, anchor); err != nil {
			t.Fatalf("advance to the anchor: %v", err)
		}
		if err := AdvanceWatermark(ctx, pool, anchor.Add(-time.Hour)); err != nil {
			t.Fatalf("advance to an hour earlier: %v", err)
		}

		got, err := Watermark(ctx, pool)
		if err != nil {
			t.Fatalf("Watermark: %v", err)
		}
		if !got.Equal(anchor) {
			t.Errorf("watermark = %v, want %v; an earlier write moved it backwards", got, anchor)
		}
	})
}

// @ac AC-20
// AC-20: the ratchet still has to ratchet. A later reading replaces the stored
// one, which is the whole point of persisting it.
func TestAdvanceWatermark_MovesForward(t *testing.T) {
	t.Run("system-license-validation/AC-20", func(t *testing.T) {
		pool := watermarkPool(t)
		ctx := context.Background()
		anchor := microNow()
		later := anchor.Add(time.Hour)

		if err := AdvanceWatermark(ctx, pool, anchor); err != nil {
			t.Fatalf("advance to the anchor: %v", err)
		}
		if err := AdvanceWatermark(ctx, pool, later); err != nil {
			t.Fatalf("advance to an hour later: %v", err)
		}

		got, err := Watermark(ctx, pool)
		if err != nil {
			t.Fatalf("Watermark: %v", err)
		}
		if !got.Equal(later) {
			t.Errorf("watermark = %v, want %v", got, later)
		}
	})
}

// @ac AC-20
// AC-20: serve, a standalone worker, and the hourly ticker all advance the same
// row. Because the monotonicity is in the SQL rather than in a read-then-write
// in Go, two writers cannot interleave into a lost update. Mixed earlier and
// later timestamps land in an arbitrary order and the maximum still wins.
func TestAdvanceWatermark_ConcurrentAdvancesSettleOnTheMaximum(t *testing.T) {
	t.Run("system-license-validation/AC-20", func(t *testing.T) {
		pool := watermarkPool(t)
		ctx := context.Background()
		base := microNow()

		offsets := []time.Duration{
			-3 * time.Hour,
			90 * time.Minute,
			-30 * time.Minute,
			2 * time.Hour, // the maximum
			0,
			-time.Minute,
			45 * time.Minute,
			-2 * time.Hour,
		}
		want := base.Add(2 * time.Hour)

		var wg sync.WaitGroup
		errCh := make(chan error, len(offsets))
		for _, off := range offsets {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := AdvanceWatermark(ctx, pool, base.Add(off)); err != nil {
					errCh <- err
				}
			}()
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			t.Errorf("concurrent advance: %v", err)
		}

		got, err := Watermark(ctx, pool)
		if err != nil {
			t.Fatalf("Watermark: %v", err)
		}
		if !got.Equal(want) {
			t.Errorf("watermark = %v, want %v; a concurrent write lost the maximum", got, want)
		}
	})
}

// @ac AC-21
// AC-21: the table holds one watermark, and the schema is what says so. A
// second row would give the two boot paths two different answers about the same
// deployment, and whichever one they read would be a coin flip. Both escape
// paths are closed, and this asserts which constraint closed each.
func TestLicenseClockWatermark_IsASingleton(t *testing.T) {
	t.Run("system-license-validation/AC-21", func(t *testing.T) {
		pool := watermarkPool(t)
		ctx := context.Background()
		now := microNow()

		if err := AdvanceWatermark(ctx, pool, now); err != nil {
			t.Fatalf("advance: %v", err)
		}

		// The default id is TRUE, so a plain second insert collides with the
		// primary key.
		_, err := pool.Exec(ctx,
			`INSERT INTO license_clock_watermark (observed_at) VALUES ($1)`, now)
		assertSQLState(t, err, sqlStateUniqueViolation, "a second row at the default id")

		// id = FALSE dodges the primary key, so the CHECK is what has to stop it.
		_, err = pool.Exec(ctx,
			`INSERT INTO license_clock_watermark (id, observed_at) VALUES (FALSE, $1)`, now)
		assertSQLState(t, err, sqlStateCheckViolation, "a second row at id = FALSE")

		var rows int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM license_clock_watermark`).Scan(&rows); err != nil {
			t.Fatalf("count rows: %v", err)
		}
		if rows != 1 {
			t.Errorf("row count = %d, want 1", rows)
		}
	})
}

// TestRollbackLoad_RowAndMemoryAgree walks the whole boot sequence that
// cmd/openwatch/main.go performs on a wound-back clock: read the row, load the
// license against it, then advance the row with the local clock. Two ratchets
// run here, one in SQL and one in Go, and they have to reach the same answer.
// A row ahead of memory would make the warning depend on which of the two a
// surface happened to read.
//
// No @ac line: AC-23 pins the in-process half and its conforming test is
// spelled out against LoadJWT. This is the pair of them together.
func TestRollbackLoad_RowAndMemoryAgree(t *testing.T) {
	pool := watermarkPool(t)
	ctx := context.Background()
	installTestKeyring(t)

	anchor := microNow()
	wound := anchor.Add(-6 * time.Hour)

	// The deployment has already recorded T.
	if err := AdvanceWatermark(ctx, pool, anchor); err != nil {
		t.Fatalf("seed the watermark: %v", err)
	}
	given, err := Watermark(ctx, pool)
	if err != nil {
		t.Fatalf("read the watermark: %v", err)
	}

	// Boot with the clock behind T. The load warns and installs.
	jwtBlob := signJWT(t, claimsAt(wound), "")
	result, err := LoadJWT(jwtBlob, VerifyOptions{Now: fixedNow(wound), LastKnownGood: given})
	if err != nil {
		t.Fatalf("boot load: %v", err)
	}
	if result != VerifyValid {
		t.Fatalf("boot load: result = %s, want valid", result)
	}

	// Boot advances the row afterwards, whatever the license outcome was, using
	// the local clock. That clock is the wound-back one.
	if err := AdvanceWatermark(ctx, pool, wound); err != nil {
		t.Fatalf("advance after the load: %v", err)
	}

	row, err := Watermark(ctx, pool)
	if err != nil {
		t.Fatalf("read the watermark back: %v", err)
	}
	memory := CurrentState().LastKnownGood

	if !row.Equal(anchor) {
		t.Errorf("row = %v, want %v; GREATEST did not hold against the wound-back clock", row, anchor)
	}
	if !memory.Equal(anchor) {
		t.Errorf("in-memory watermark = %v, want %v", memory, anchor)
	}
	if !row.Equal(memory) {
		t.Errorf("row %v and memory %v diverged; the warning would depend on which one a surface reads", row, memory)
	}
}

// assertSQLState fails unless err is a PostgreSQL error carrying want. Which
// constraint rejected the write is the assertion; that something failed is not.
func assertSQLState(t *testing.T, err error, want, what string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s was accepted, want SQLSTATE %s", what, want)
		return
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Errorf("%s failed with %v, want a PostgreSQL error carrying SQLSTATE %s", what, err, want)
		return
	}
	if pgErr.Code != want {
		t.Errorf("%s failed with SQLSTATE %s (%s), want %s", what, pgErr.Code, pgErr.Message, want)
	}
}
