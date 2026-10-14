// @spec system-discovery-scheduler
//
// Migration 0066 adds a unique index allowing one active discovery job per
// host. Duplicates already queued would stop it from building, so the
// migration first retires all but one per host (bugs/OW-120).
package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
)

// @ac AC-14
// AC-14: existing duplicates are retired, one active job per host is kept,
// nothing is deleted, and the index then exists.
func TestMigration0066_RetiresDuplicateDiscoveryJobs(t *testing.T) {
	t.Run("system-discovery-scheduler/AC-14", func(t *testing.T) {
		ctx := context.Background()
		pool, sqlDB := freshDBAt(t, 65)

		hostA, hostB := uuid.NewString(), uuid.NewString()
		now := time.Now().UTC()
		type seed struct {
			name, jobType, host, status string
			created                     time.Duration
			locked                      *time.Duration
		}
		ago := func(d time.Duration) *time.Duration { return &d }
		seeds := []seed{
			{"a-proc-old", "host.discovery", hostA, "processing", 4 * time.Hour, ago(2 * time.Hour)},
			{"a-proc-new", "host.discovery", hostA, "processing", 4 * time.Hour, ago(1 * time.Hour)},
			{"a-pend-old", "host.discovery", hostA, "pending", 3 * time.Hour, nil},
			{"a-pend-new", "host.discovery", hostA, "pending", 1 * time.Hour, nil},
			{"b-pend-old", "host.discovery", hostB, "pending", 2 * time.Hour, nil},
			{"b-pend-new", "host.discovery", hostB, "pending", 1 * time.Hour, nil},
			{"a-done", "host.discovery", hostA, "completed", 5 * time.Hour, ago(5 * time.Hour)},
			{"other-1", "diagnostics.test_job", hostA, "pending", 2 * time.Hour, nil},
			{"other-2", "diagnostics.test_job", hostA, "pending", 1 * time.Hour, nil},
		}
		ids := map[string]uuid.UUID{}
		for _, s := range seeds {
			id := uuid.New()
			ids[s.name] = id
			var locked *time.Time
			if s.locked != nil {
				v := now.Add(-*s.locked)
				locked = &v
			}
			if _, err := pool.Exec(ctx, `
				INSERT INTO job_queue (id, job_type, payload, correlation_id, status, created_at, locked_at)
				VALUES ($1, $2, jsonb_build_object('host_id', $3::text), 'mig66', $4, $5, $6)`,
				id, s.jobType, s.host, s.status, now.Add(-s.created), locked); err != nil {
				t.Fatalf("seed %s: %v", s.name, err)
			}
		}

		if err := goose.UpToContext(ctx, sqlDB, ".", 66); err != nil {
			t.Fatalf("migrate to 66: %v", err)
		}

		const retired = "host.discovery: retired as a duplicate by migration 0066"
		want := map[string]string{
			"a-proc-new": "processing",
			"a-proc-old": "failed",
			"a-pend-old": "failed",
			"a-pend-new": "failed",
			"b-pend-old": "pending",
			"b-pend-new": "failed",
			"a-done":     "completed",
			"other-1":    "pending",
			"other-2":    "pending",
		}
		for name, wantStatus := range want {
			var status, lastErr string
			if err := pool.QueryRow(ctx, `SELECT status, COALESCE(last_error, '') FROM job_queue WHERE id = $1`,
				ids[name]).Scan(&status, &lastErr); err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			if status != wantStatus {
				t.Errorf("%s: status %q, want %q", name, status, wantStatus)
			}
			if wantStatus == "failed" && lastErr != retired {
				t.Errorf("%s: last_error %q, want %q", name, lastErr, retired)
			}
			if wantStatus != "failed" && lastErr != "" {
				t.Errorf("%s: last_error %q, want none", name, lastErr)
			}
		}
		var rows int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM job_queue`).Scan(&rows); err != nil {
			t.Fatalf("count: %v", err)
		}
		if rows != len(seeds) {
			t.Errorf("rows after migration = %d, want %d (nothing deleted)", rows, len(seeds))
		}
		var indexed bool
		if err := pool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM pg_indexes
			 WHERE tablename = 'job_queue' AND indexname = 'uq_job_queue_discovery_active')`).Scan(&indexed); err != nil {
			t.Fatalf("index lookup: %v", err)
		}
		if !indexed {
			t.Fatalf("unique index uq_job_queue_discovery_active missing after migration")
		}
		// The index now refuses a second active job for host B.
		if _, err := pool.Exec(ctx, `
			INSERT INTO job_queue (id, job_type, payload, correlation_id, status)
			VALUES ($1, 'host.discovery', jsonb_build_object('host_id', $2::text), 'mig66', 'pending')`,
			uuid.New(), hostB); err == nil {
			t.Fatalf("a second active discovery job for host B was accepted")
		}
	})
}
