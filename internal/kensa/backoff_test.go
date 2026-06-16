// @spec system-kensa-executor
//
// AC traceability (this file):
//   AC-16  TestBackoffPolicy_ComputeSuppressUntil_BelowThreshold
//          TestBackoffPolicy_ComputeSuppressUntil_AtThresholdDoubles
//          TestBackoffPolicy_ComputeSuppressUntil_DoublesEachAdditionalFailure
//          TestBackoffPolicy_ComputeSuppressUntil_CapsAt24h
//          TestRecordFailure_FirstFailure_InsertsRow                (integration)
//          TestRecordFailure_ReachesThreshold_SetsSuppressUntil     (integration)
//          TestRecordSuccess_ResetsCountAndClearsSuppressUntil       (integration)

package kensa

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/db/dbtest"
)

// @ac AC-16
// AC-16 (pure logic): below the failure threshold, suppress_until is
// the zero time (no suppression — scheduler dispatches normally).
func TestBackoffPolicy_ComputeSuppressUntil_BelowThreshold(t *testing.T) {
	t.Run("system-kensa-executor/AC-16", func(t *testing.T) {
		policy := DefaultBackoffPolicy(60 * time.Minute)
		now := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)

		for n := 0; n < policy.FailureThreshold; n++ {
			got := policy.computeSuppressUntil(now, n)
			if !got.IsZero() {
				t.Errorf("n=%d: suppress_until = %v, want zero (below threshold of %d)",
					n, got, policy.FailureThreshold)
			}
		}
	})
}

// @ac AC-16
// AC-16: at the threshold (3 consecutive failures), suppress_until is
// now + 2 × baseInterval (one doubling).
func TestBackoffPolicy_ComputeSuppressUntil_AtThresholdDoubles(t *testing.T) {
	t.Run("system-kensa-executor/AC-16", func(t *testing.T) {
		policy := DefaultBackoffPolicy(60 * time.Minute)
		now := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)

		got := policy.computeSuppressUntil(now, 3)
		want := now.Add(2 * 60 * time.Minute) // 1h doubled once = 2h

		if !got.Equal(want) {
			t.Errorf("suppress_until at threshold = %v, want %v", got, want)
		}
	})
}

// @ac AC-16
// AC-16: each additional failure beyond the threshold doubles the
// suppression interval.
func TestBackoffPolicy_ComputeSuppressUntil_DoublesEachAdditionalFailure(t *testing.T) {
	t.Run("system-kensa-executor/AC-16", func(t *testing.T) {
		policy := DefaultBackoffPolicy(60 * time.Minute)
		now := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)

		cases := []struct {
			failures int
			wantHrs  int
		}{
			{3, 2},  // 1h × 2¹ = 2h
			{4, 4},  // 1h × 2² = 4h
			{5, 8},  // 1h × 2³ = 8h
			{6, 16}, // 1h × 2⁴ = 16h
		}
		for _, c := range cases {
			got := policy.computeSuppressUntil(now, c.failures)
			want := now.Add(time.Duration(c.wantHrs) * time.Hour)
			if !got.Equal(want) {
				t.Errorf("failures=%d: got %v, want %v (delta=%v)",
					c.failures, got, want, got.Sub(want))
			}
		}
	})
}

// @ac AC-16
// AC-16: the doubling chain caps at MaxSuppressDuration (24h default).
// A host with many consecutive failures suppresses for at most 24h,
// not forever.
func TestBackoffPolicy_ComputeSuppressUntil_CapsAt24h(t *testing.T) {
	t.Run("system-kensa-executor/AC-16", func(t *testing.T) {
		policy := DefaultBackoffPolicy(60 * time.Minute)
		now := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)

		// 1h × 2⁵ = 32h > 24h cap. Should clamp to 24h.
		got := policy.computeSuppressUntil(now, 7)
		want := now.Add(24 * time.Hour)
		if !got.Equal(want) {
			t.Errorf("failures=7 (above cap): got %v, want %v", got, want)
		}

		// Very many failures: still 24h ceiling.
		got = policy.computeSuppressUntil(now, 50)
		if !got.Equal(want) {
			t.Errorf("failures=50: got %v, want %v (cap still 24h)", got, want)
		}
	})
}

// ---------------------------------------------------------------------
// Integration tests (require OPENWATCH_TEST_DSN)
// ---------------------------------------------------------------------

// freshPool returns a pool against a clean schedule + backoff state.
// Applies all migrations through 0011 and truncates tables this
// package writes to.
func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()

	for _, stmt := range []string{
		"TRUNCATE TABLE host_backoff_state CASCADE",
		"TRUNCATE TABLE host_compliance_schedule CASCADE",
		"TRUNCATE TABLE hosts CASCADE",
		"TRUNCATE TABLE users CASCADE",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Logf("truncate (ok if table absent): %v", err)
		}
	}
	return pool
}

// seedUser inserts a minimal users row so hosts.created_by FK is satisfiable.
func seedUser(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, username, email, password_hash)
		 VALUES ($1, $2, $3, $4)`,
		id, "kensa-test-user", "ktu@example.com", "argon2id$dummy") // pragma: allowlist secret
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

// seedHost inserts a minimal hosts row for the backoff state FK.
func seedHost(t *testing.T, pool *pgxpool.Pool, createdBy uuid.UUID) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO hosts (id, hostname, ip_address, created_by)
		 VALUES ($1, $2, $3::inet, $4)`,
		id, "host-"+id.String(), "192.0.2.10", createdBy)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return id
}

// newTestExecutor builds an Executor with a deterministic clock.
func newTestExecutor(t *testing.T, now time.Time) *Executor {
	t.Helper()
	bridge := &fakeCredentialBridge{errorFor: make(map[uuid.UUID]error)}
	exec := NewExecutor(bridge, func(ctx context.Context, code audit.Code, ev audit.Event) {})
	exec.clock = func() time.Time { return now }
	return exec
}

// @ac AC-16
// AC-16: the first failure for a host creates a host_backoff_state row
// at consecutive_failures = 1 with suppress_until NULL.
func TestRecordFailure_FirstFailure_InsertsRow(t *testing.T) {
	t.Run("system-kensa-executor/AC-16", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		now := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
		exec := newTestExecutor(t, now)
		policy := DefaultBackoffPolicy(60 * time.Minute)

		count, suppressUntil, err := exec.RecordFailure(context.Background(), pool, hostID, policy, ReasonKensaError)
		if err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}
		if count != 1 {
			t.Errorf("count = %d, want 1", count)
		}
		if !suppressUntil.IsZero() {
			t.Errorf("suppress_until = %v, want zero (below threshold)", suppressUntil)
		}

		// Verify DB state.
		var dbCount int
		var dbSuppressUntil *time.Time
		var dbLastError string
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err = pool.QueryRow(ctx,
			`SELECT consecutive_failures, suppress_until, last_error_code
			   FROM host_backoff_state WHERE host_id = $1`,
			hostID).Scan(&dbCount, &dbSuppressUntil, &dbLastError)
		if err != nil {
			t.Fatalf("read backoff row: %v", err)
		}
		if dbCount != 1 {
			t.Errorf("DB consecutive_failures = %d, want 1", dbCount)
		}
		if dbSuppressUntil != nil {
			t.Errorf("DB suppress_until = %v, want NULL", *dbSuppressUntil)
		}
		if dbLastError != string(ReasonKensaError) {
			t.Errorf("DB last_error_code = %q, want %q", dbLastError, ReasonKensaError)
		}
	})
}

// @ac AC-16
// AC-16: at the failure threshold (3 consecutive failures), suppress_until
// is written to the DB at now + 2× tier interval. The scheduler's
// dispatcher reads this and skips the host on subsequent ticks.
func TestRecordFailure_ReachesThreshold_SetsSuppressUntil(t *testing.T) {
	t.Run("system-kensa-executor/AC-16", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		now := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
		exec := newTestExecutor(t, now)
		policy := DefaultBackoffPolicy(60 * time.Minute)

		// Three consecutive failures.
		var lastSuppress time.Time
		for i := 0; i < 3; i++ {
			_, suppress, err := exec.RecordFailure(context.Background(), pool, hostID, policy, ReasonKensaError)
			if err != nil {
				t.Fatalf("RecordFailure #%d: %v", i+1, err)
			}
			lastSuppress = suppress
		}

		// After the third failure, suppress_until should be now + 2h.
		want := now.Add(2 * time.Hour)
		if !lastSuppress.Equal(want) {
			t.Errorf("suppress_until after 3rd failure = %v, want %v", lastSuppress, want)
		}

		// Verify DB has the same value.
		var dbCount int
		var dbSuppressUntil time.Time
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := pool.QueryRow(ctx,
			`SELECT consecutive_failures, suppress_until
			   FROM host_backoff_state WHERE host_id = $1`,
			hostID).Scan(&dbCount, &dbSuppressUntil)
		if err != nil {
			t.Fatalf("read backoff: %v", err)
		}
		if dbCount != 3 {
			t.Errorf("consecutive_failures = %d, want 3", dbCount)
		}
		if !dbSuppressUntil.Equal(want) {
			t.Errorf("DB suppress_until = %v, want %v", dbSuppressUntil, want)
		}
	})
}

// @ac AC-16
// AC-16: a successful scan resets consecutive_failures to 0 and clears
// suppress_until. The scheduler resumes normal dispatch on the next tick.
func TestRecordSuccess_ResetsCountAndClearsSuppressUntil(t *testing.T) {
	t.Run("system-kensa-executor/AC-16", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		hostID := seedHost(t, pool, user)

		now := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
		exec := newTestExecutor(t, now)
		policy := DefaultBackoffPolicy(60 * time.Minute)

		// 4 consecutive failures → suppress_until set.
		for i := 0; i < 4; i++ {
			_, _, err := exec.RecordFailure(context.Background(), pool, hostID, policy, ReasonKensaError)
			if err != nil {
				t.Fatalf("RecordFailure #%d: %v", i+1, err)
			}
		}

		// Confirm the row is in the suppress-now state.
		var dbCount int
		var dbSuppressUntil *time.Time
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := pool.QueryRow(ctx,
			`SELECT consecutive_failures, suppress_until
			   FROM host_backoff_state WHERE host_id = $1`,
			hostID).Scan(&dbCount, &dbSuppressUntil); err != nil {
			t.Fatalf("read pre-reset: %v", err)
		}
		if dbCount != 4 {
			t.Fatalf("pre-reset count = %d, want 4 (test fixture broken)", dbCount)
		}
		if dbSuppressUntil == nil {
			t.Fatal("pre-reset suppress_until = NULL (test fixture broken)")
		}

		// Reset on success.
		if err := exec.RecordSuccess(context.Background(), pool, hostID); err != nil {
			t.Fatalf("RecordSuccess: %v", err)
		}

		// Post-reset DB state.
		var lastError *string
		if err := pool.QueryRow(ctx,
			`SELECT consecutive_failures, suppress_until, last_error_code
			   FROM host_backoff_state WHERE host_id = $1`,
			hostID).Scan(&dbCount, &dbSuppressUntil, &lastError); err != nil {
			t.Fatalf("read post-reset: %v", err)
		}
		if dbCount != 0 {
			t.Errorf("post-reset consecutive_failures = %d, want 0", dbCount)
		}
		if dbSuppressUntil != nil {
			t.Errorf("post-reset suppress_until = %v, want NULL", *dbSuppressUntil)
		}
		if lastError != nil {
			t.Errorf("post-reset last_error_code = %v, want NULL", *lastError)
		}
	})
}
