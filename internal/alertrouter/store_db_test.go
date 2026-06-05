// @spec system-alert-router
//
// AC traceability (this file):
//
//	AC-20  TestPgxStore_DuplicateDedupKeyOccurredAt_IdempotentInsert

package alertrouter

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/db"
	"github.com/Hanalyx/openwatch/internal/db/migrations"
	"github.com/google/uuid"
)

func storeTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OPENWATCH_TEST_DSN")
	if dsn == "" {
		t.Skip("set OPENWATCH_TEST_DSN to run alertrouter store integration tests")
	}
	return dsn
}

// @ac AC-20
// AC-20 (DB-side): PgxStore.Insert called twice with the same
// (dedup_key, occurred_at) returns the SAME id and does NOT create a
// second row. Defense-in-depth against router-restart scenarios where
// the in-memory dedup gate is empty.
func TestPgxStore_DuplicateDedupKeyOccurredAt_IdempotentInsert(t *testing.T) {
	t.Run("system-alert-router/AC-20", func(t *testing.T) {
		dsn := storeTestDSN(t)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)
		pool, err := db.NewPool(ctx, dsn, 5)
		if err != nil {
			t.Fatalf("NewPool: %v", err)
		}
		t.Cleanup(pool.Close)
		if err := migrations.Apply(ctx, pool); err != nil {
			t.Fatalf("migrations.Apply: %v", err)
		}
		_, _ = pool.Exec(ctx, "TRUNCATE TABLE alerts")

		store := NewPgxStore(pool)
		occurredAt := time.Now().UTC().Truncate(time.Microsecond)
		alert := Alert{
			Type:       AlertTypeHostUnreachable,
			Severity:   SeverityHigh,
			HostID:     uuid.Nil, // nullable
			RuleID:     "",
			OccurredAt: occurredAt,
			Title:      "host unreachable test",
			Body:       "test body",
			Tags:       map[string]string{"severity": "high"},
		}

		id1, err := store.Insert(ctx, alert)
		if err != nil {
			t.Fatalf("first insert: %v", err)
		}
		if id1 == uuid.Nil {
			t.Fatal("first insert returned nil id")
		}

		id2, err := store.Insert(ctx, alert)
		if err != nil {
			t.Fatalf("second insert: %v", err)
		}
		if id2 != id1 {
			t.Errorf("second insert returned %s, want same id as first (%s) — UNIQUE+ON CONFLICT recovery broken",
				id2, id1)
		}

		var count int
		err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts WHERE dedup_key = $1`,
			alert.DedupKey()).Scan(&count)
		if err != nil {
			t.Fatalf("count rows: %v", err)
		}
		if count != 1 {
			t.Errorf("rows for dedup_key = %d, want 1 (UNIQUE constraint violated)", count)
		}
	})
}
