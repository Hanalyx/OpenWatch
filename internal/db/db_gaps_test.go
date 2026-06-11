// @spec system-db
//
// Coverage closers for AC-02 (unreachable host), AC-03/04 (Apply runs +
// idempotent), AC-05/06 (schema shape), AC-08 (round-trip JSON-equivalent),
// AC-12 (data survives pool close/reopen). All require OPENWATCH_TEST_DSN
// for the migrate+query path; AC-02 deliberately points at an unreachable
// DSN and must NOT require a real DB.

package db

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/db/migrations"
	"github.com/google/uuid"
)

// @ac AC-02
// AC-02: NewPool against an unreachable host returns an error within the
// 5s budget (does not block forever). Uses a TCP port nothing listens on.
func TestNewPool_UnreachableHost(t *testing.T) {
	t.Run("system-db/AC-02", func(t *testing.T) {
		// RFC 6890 reserved address; guaranteed not to route.
		dsn := "postgres://nobody:secret@192.0.2.1:5432/nodb?sslmode=disable&connect_timeout=3"
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()

		start := time.Now()
		pool, err := NewPool(ctx, dsn, 1)
		elapsed := time.Since(start)
		if err == nil {
			pool.Close()
			t.Fatal("NewPool returned nil error for unreachable host")
		}
		if elapsed > 6*time.Second {
			t.Errorf("NewPool took %v, want < 6s (budgeted 5s + ctx slack)", elapsed)
		}
	})
}

// @ac AC-03
// AC-03: Apply() runs every embedded migration in order; goose_db_version
// reflects the highest applied version after a fresh run.
func TestApply_RunsAllMigrations(t *testing.T) {
	t.Run("system-db/AC-03", func(t *testing.T) {
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

		var highest int64
		err = pool.QueryRow(ctx,
			"SELECT MAX(version_id) FROM goose_db_version WHERE version_id > 0",
		).Scan(&highest)
		if err != nil {
			t.Fatalf("query goose_db_version: %v", err)
		}
		if highest < 1 {
			t.Errorf("highest applied version = %d, want >= 1", highest)
		}
	})
}

// @ac AC-04
// AC-04: Apply() against an already-migrated DB is a no-op and returns nil.
func TestApply_IsIdempotent(t *testing.T) {
	t.Run("system-db/AC-04", func(t *testing.T) {
		dsn := testDSN(t)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		pool, err := NewPool(ctx, dsn, 5)
		if err != nil {
			t.Fatalf("NewPool: %v", err)
		}
		defer pool.Close()
		if err := migrations.Apply(ctx, pool); err != nil {
			t.Fatalf("first Apply: %v", err)
		}

		var versionBefore int64
		_ = pool.QueryRow(ctx, "SELECT MAX(version_id) FROM goose_db_version").Scan(&versionBefore)

		if err := migrations.Apply(ctx, pool); err != nil {
			t.Errorf("second Apply (idempotent): %v", err)
		}

		var versionAfter int64
		_ = pool.QueryRow(ctx, "SELECT MAX(version_id) FROM goose_db_version").Scan(&versionAfter)
		if versionAfter != versionBefore {
			t.Errorf("version changed on re-run: %d → %d", versionBefore, versionAfter)
		}
	})
}

// @ac AC-05
// AC-05: audit_events schema includes id (UUID PK), correlation_id (NOT
// NULL), actor_type (NOT NULL), action (NOT NULL), occurred_at.
func TestSchema_AuditEvents(t *testing.T) {
	t.Run("system-db/AC-05", func(t *testing.T) {
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

		rows, err := pool.Query(ctx, `
			SELECT column_name, is_nullable, data_type
			FROM information_schema.columns
			WHERE table_name = 'audit_events'
			ORDER BY ordinal_position`)
		if err != nil {
			t.Fatalf("info schema: %v", err)
		}
		defer rows.Close()
		cols := map[string]struct {
			Nullable string
			Type     string
		}{}
		for rows.Next() {
			var name, nullable, dtype string
			if err := rows.Scan(&name, &nullable, &dtype); err != nil {
				t.Fatalf("scan: %v", err)
			}
			cols[name] = struct {
				Nullable string
				Type     string
			}{nullable, dtype}
		}
		mustHave := map[string]string{
			"id":             "NO",
			"correlation_id": "NO",
			"actor_type":     "NO",
			"action":         "NO",
			"occurred_at":    "NO",
		}
		for name, wantNullable := range mustHave {
			c, ok := cols[name]
			if !ok {
				t.Errorf("column %q missing from audit_events", name)
				continue
			}
			if c.Nullable != wantNullable {
				t.Errorf("audit_events.%s is_nullable = %q, want %q", name, c.Nullable, wantNullable)
			}
		}
		if c, ok := cols["id"]; ok && c.Type != "uuid" {
			t.Errorf("audit_events.id type = %q, want uuid", c.Type)
		}
	})
}

// @ac AC-06
// AC-06: idempotency_keys schema includes key (TEXT PK), request_hash,
// response_status, response_body (JSONB), expires_at.
func TestSchema_IdempotencyKeys(t *testing.T) {
	t.Run("system-db/AC-06", func(t *testing.T) {
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

		rows, err := pool.Query(ctx, `
			SELECT column_name, data_type
			FROM information_schema.columns
			WHERE table_name = 'idempotency_keys'`)
		if err != nil {
			t.Fatalf("info schema: %v", err)
		}
		defer rows.Close()
		cols := map[string]string{}
		for rows.Next() {
			var name, dtype string
			if err := rows.Scan(&name, &dtype); err != nil {
				t.Fatalf("scan: %v", err)
			}
			cols[name] = dtype
		}
		want := map[string]string{
			"key":             "text",
			"request_hash":    "text",
			"response_status": "integer",
			"response_body":   "jsonb",
			"expires_at":      "timestamp with time zone",
		}
		for name, wantType := range want {
			got, ok := cols[name]
			if !ok {
				t.Errorf("idempotency_keys.%s missing", name)
				continue
			}
			if got != wantType {
				t.Errorf("idempotency_keys.%s type = %q, want %q", name, got, wantType)
			}
		}
	})
}

// @ac AC-08
// AC-08: Insert → GetByID round-trips detail JSON byte-for-byte equivalent
// (JSON-equal after JSONB normalization).
func TestRoundTrip_DetailJSON(t *testing.T) {
	t.Run("system-db/AC-08", func(t *testing.T) {
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

		id := uuid.Must(uuid.NewV7())
		detailIn, _ := json.Marshal(map[string]any{
			"nested": map[string]any{"k": "v", "n": 42},
			"list":   []int{1, 2, 3},
		})
		_, err = InsertAuditEvent(ctx, pool, InsertAuditEventParams{
			ID:            id,
			CorrelationID: "roundtrip-test",
			ActorType:     "system",
			Action:        "system.startup",
			Detail:        detailIn,
		})
		if err != nil {
			t.Fatalf("Insert: %v", err)
		}
		got, err := GetAuditEventByID(ctx, pool, id)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		var a, b map[string]any
		_ = json.Unmarshal(detailIn, &a)
		_ = json.Unmarshal(got.Detail, &b)
		if !jsonEqual(a, b) {
			t.Errorf("detail mismatch:\n in  = %s\n out = %s", detailIn, got.Detail)
		}
	})
}

// @ac AC-12
// AC-12: Data persists across binary restart. Simulated here by closing
// the pool, reopening it, and re-running Apply() idempotently — the row
// must still be readable. A true binary-restart test is reserved for the
// Stage-0 acceptance walkthrough.
func TestPersistsAcrossPoolReopen(t *testing.T) {
	t.Run("system-db/AC-12", func(t *testing.T) {
		dsn := testDSN(t)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		pool1, err := NewPool(ctx, dsn, 5)
		if err != nil {
			t.Fatalf("NewPool(1): %v", err)
		}
		if err := migrations.Apply(ctx, pool1); err != nil {
			pool1.Close()
			t.Fatalf("Apply(1): %v", err)
		}
		_, _ = pool1.Exec(ctx, "TRUNCATE TABLE audit_events")

		id := uuid.Must(uuid.NewV7())
		_, err = InsertAuditEvent(ctx, pool1, InsertAuditEventParams{
			ID:            id,
			CorrelationID: "persistence-test",
			ActorType:     "system",
			Action:        "system.startup",
		})
		if err != nil {
			pool1.Close()
			t.Fatalf("Insert: %v", err)
		}
		pool1.Close()

		// Reopen — simulates a binary restart against the same DB.
		pool2, err := NewPool(ctx, dsn, 5)
		if err != nil {
			t.Fatalf("NewPool(2): %v", err)
		}
		defer pool2.Close()
		// Apply is idempotent — required because real restarts run it.
		if err := migrations.Apply(ctx, pool2); err != nil {
			t.Fatalf("Apply(2): %v", err)
		}
		got, err := GetAuditEventByID(ctx, pool2, id)
		if err != nil {
			t.Fatalf("Get post-reopen: %v", err)
		}
		if got.CorrelationID != "persistence-test" {
			t.Errorf("CorrelationID = %q, want persistence-test", got.CorrelationID)
		}
	})
}

// jsonEqual is a depth-first JSON value comparator (handles maps, slices,
// scalars). Used to assert detail round-trips without depending on key
// ordering.
func jsonEqual(a, b any) bool {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, v := range av {
			if !jsonEqual(v, bv[k]) {
				return false
			}
		}
		return true
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !jsonEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}
