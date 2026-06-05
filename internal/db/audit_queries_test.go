// @spec system-db
//
// AC traceability (DB integration tests; skipped without OPENWATCH_TEST_DSN):
// @ac AC-01  (AC-3, AC-4  TestInsertAndGetAuditEvent (pool + migrate idempotent))
// @ac AC-07  (AC-8        TestInsertAndGetAuditEvent (insert returns row; round-trip))
// @ac AC-09  (AC-10       TestListAuditEvents (newest-first ordering; cursor))
// @ac AC-11  (TestCountAuditEvents)
//   (AC-2 unreachable-host: not yet implemented as a test — Day 4 follow-up)
//   (AC-5, AC-6 schema: verified by migrate-and-read in TestInsertAndGetAuditEvent
//                       and TestCountAuditEvents; no dedicated schema test)
//   (AC-12 restart-survives: manual verification, see Day 3 acceptance log)

package db

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/db/migrations"
	"github.com/google/uuid"
)

// testDSN returns the integration-test DSN or skips the test. CI is
// expected to set OPENWATCH_TEST_DSN; local dev runs without it.
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OPENWATCH_TEST_DSN")
	if dsn == "" {
		t.Skip("set OPENWATCH_TEST_DSN to run db integration tests")
	}
	return dsn
}

// @ac AC-01  (AC-3, AC-4, AC-7, AC-8: pool ping, migrate apply + idempotent re-run)
// insert returns row, round-trip via GetAuditEventByID.
func TestInsertAndGetAuditEvent(t *testing.T) {
	t.Run("system-db/AC-01", func(t *testing.T) {

		dsn := testDSN(t)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		pool, err := NewPool(ctx, dsn, 5)
		if err != nil {
			t.Fatalf("NewPool: %v", err)
		}
		defer pool.Close()

		if err := migrations.Apply(ctx, pool); err != nil {
			t.Fatalf("migrations.Apply: %v", err)
		}
		_, _ = pool.Exec(ctx, "TRUNCATE TABLE audit_events")

		id := uuid.Must(uuid.NewV7())
		corr := "test-day3-001"
		detail, _ := json.Marshal(map[string]any{"reason": "integration test"})

		resourceType := "host"
		resourceID := "11111111-1111-1111-1111-111111111111"

		in := InsertAuditEventParams{
			ID:            id,
			CorrelationID: corr,
			ActorType:     "system",
			Action:        "auth.login.success",
			ResourceType:  &resourceType,
			ResourceID:    &resourceID,
			Detail:        detail,
		}

		got, err := InsertAuditEvent(ctx, pool, in)
		if err != nil {
			t.Fatalf("InsertAuditEvent: %v", err)
		}
		if got.ID != id {
			t.Errorf("ID = %v, want %v", got.ID, id)
		}
		if got.CorrelationID != corr {
			t.Errorf("CorrelationID = %q, want %q", got.CorrelationID, corr)
		}
		if got.Action != "auth.login.success" {
			t.Errorf("Action = %q, want auth.login.success", got.Action)
		}
		if got.ActorType != "system" {
			t.Errorf("ActorType = %q, want system", got.ActorType)
		}
		if got.OccurredAt.IsZero() {
			t.Error("OccurredAt should default to now()")
		}
		if got.ResourceType == nil || *got.ResourceType != "host" {
			t.Errorf("ResourceType = %v, want host", got.ResourceType)
		}

		// Read back via GetAuditEventByID.
		fetched, err := GetAuditEventByID(ctx, pool, id)
		if err != nil {
			t.Fatalf("GetAuditEventByID: %v", err)
		}
		if fetched.ID != id {
			t.Errorf("GetAuditEventByID returned ID %v, want %v", fetched.ID, id)
		}

		// Round-trip detail JSON.
		var rt map[string]any
		if err := json.Unmarshal(fetched.Detail, &rt); err != nil {
			t.Fatalf("unmarshal detail: %v", err)
		}
		if rt["reason"] != "integration test" {
			t.Errorf("detail.reason = %v, want 'integration test'", rt["reason"])
		}
	})

	// @ac AC-07
	// AC-07: InsertAuditEvent returns the same row with occurred_at populated.
	t.Run("system-db/AC-07", func(t *testing.T) {
		dsn := testDSN(t)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		pool, err := NewPool(ctx, dsn, 5)
		if err != nil {
			t.Fatalf("NewPool: %v", err)
		}
		defer pool.Close()
		if err := migrations.Apply(ctx, pool); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		_, _ = pool.Exec(ctx, "TRUNCATE TABLE audit_events")

		id := uuid.Must(uuid.NewV7())
		out, err := InsertAuditEvent(ctx, pool, InsertAuditEventParams{
			ID:            id,
			CorrelationID: "ac07-corr",
			ActorType:     "system",
			Action:        "system.startup",
		})
		if err != nil {
			t.Fatalf("Insert: %v", err)
		}
		if out.ID != id {
			t.Errorf("returned ID = %v, want %v", out.ID, id)
		}
		if out.OccurredAt.IsZero() {
			t.Error("OccurredAt should be populated by Insert")
		}
	})
}

// @ac AC-09  (AC-10: newest-first ordering; cursor returns only older rows.)
func TestListAuditEvents(t *testing.T) {
	t.Run("system-db/AC-09", func(t *testing.T) {

		dsn := testDSN(t)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		pool, err := NewPool(ctx, dsn, 5)
		if err != nil {
			t.Fatalf("NewPool: %v", err)
		}
		defer pool.Close()

		if err := migrations.Apply(ctx, pool); err != nil {
			t.Fatalf("migrations.Apply: %v", err)
		}
		_, _ = pool.Exec(ctx, "TRUNCATE TABLE audit_events")

		// Insert three events.
		for i := 0; i < 3; i++ {
			_, err := InsertAuditEvent(ctx, pool, InsertAuditEventParams{
				ID:            uuid.Must(uuid.NewV7()),
				CorrelationID: "test-list",
				ActorType:     "system",
				Action:        "system.startup",
			})
			if err != nil {
				t.Fatalf("Insert %d: %v", i, err)
			}
			time.Sleep(2 * time.Millisecond) // ensure distinct timestamps
		}

		out, err := ListAuditEvents(ctx, pool, ListAuditEventsParams{Limit: 10})
		if err != nil {
			t.Fatalf("ListAuditEvents: %v", err)
		}
		if len(out) != 3 {
			t.Errorf("got %d rows, want 3", len(out))
		}
		// Newest-first ordering.
		for i := 1; i < len(out); i++ {
			if out[i-1].OccurredAt.Before(out[i].OccurredAt) {
				t.Errorf("rows not sorted newest-first at %d", i)
			}
		}

	})
}

// @ac AC-10  (Cursor returns only rows strictly older than Before.)
func TestListAuditEvents_CursorWithBefore(t *testing.T) {
	t.Run("system-db/AC-10", func(t *testing.T) {
		dsn := testDSN(t)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		pool, err := NewPool(ctx, dsn, 5)
		if err != nil {
			t.Fatalf("NewPool: %v", err)
		}
		defer pool.Close()
		if err := migrations.Apply(ctx, pool); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		_, _ = pool.Exec(ctx, "TRUNCATE TABLE audit_events")

		for i := 0; i < 3; i++ {
			if _, err := InsertAuditEvent(ctx, pool, InsertAuditEventParams{
				ID:            uuid.Must(uuid.NewV7()),
				CorrelationID: "ac10-cursor",
				ActorType:     "system",
				Action:        "system.startup",
			}); err != nil {
				t.Fatalf("Insert %d: %v", i, err)
			}
			time.Sleep(2 * time.Millisecond)
		}
		out, err := ListAuditEvents(ctx, pool, ListAuditEventsParams{Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(out) < 3 {
			t.Fatalf("seed inserts: got %d rows, want 3", len(out))
		}
		before := out[1].OccurredAt
		older, err := ListAuditEvents(ctx, pool, ListAuditEventsParams{Before: &before, Limit: 10})
		if err != nil {
			t.Fatalf("List (cursor): %v", err)
		}
		if len(older) != 1 {
			t.Errorf("cursor returned %d rows, want 1 (only strict-before)", len(older))
		}
		// All returned rows must be strictly before the cursor.
		for _, e := range older {
			if !e.OccurredAt.Before(before) {
				t.Errorf("row at %v not strictly before %v", e.OccurredAt, before)
			}
		}
	})
}

// @ac AC-11  (count matches inserted row total.)
func TestCountAuditEvents(t *testing.T) {
	t.Run("system-db/AC-11", func(t *testing.T) {

		dsn := testDSN(t)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		pool, err := NewPool(ctx, dsn, 5)
		if err != nil {
			t.Fatalf("NewPool: %v", err)
		}
		defer pool.Close()

		if err := migrations.Apply(ctx, pool); err != nil {
			t.Fatalf("migrations.Apply: %v", err)
		}
		_, _ = pool.Exec(ctx, "TRUNCATE TABLE audit_events")

		n0, err := CountAuditEvents(ctx, pool)
		if err != nil {
			t.Fatalf("Count: %v", err)
		}
		if n0 != 0 {
			t.Errorf("initial count = %d, want 0", n0)
		}

		for i := 0; i < 5; i++ {
			_, err := InsertAuditEvent(ctx, pool, InsertAuditEventParams{
				ID:            uuid.Must(uuid.NewV7()),
				CorrelationID: "test-count",
				ActorType:     "system",
				Action:        "system.startup",
			})
			if err != nil {
				t.Fatalf("Insert %d: %v", i, err)
			}
		}

		n5, err := CountAuditEvents(ctx, pool)
		if err != nil {
			t.Fatalf("Count: %v", err)
		}
		if n5 != 5 {
			t.Errorf("count after 5 inserts = %d, want 5", n5)
		}
	})
}
