// @spec system-scan-runs
//
// AC traceability (DB integration tests; skipped without OPENWATCH_TEST_DSN):
//
//	AC-01  TestInsert_QueuedRow / TestInsert_EmptyTrigger_Errors
//	AC-02  TestMarkRunning_FlipsAndUpserts
//	AC-03  TestMarkCompleted_RecordsCounts
//	AC-04  TestMarkFailed_RecordsReason (worker pairing: see worker test)
//	AC-05  TestTerminalStates_NeverOverwritten
//	AC-06  TestLatestForHost_And_ActiveCount
//	AC-07  TestHostDelete_RestrictedByRuns
//	AC-08  TestActiveByHostIDs
package scanruns

import (
	"context"
	"errors"
	"testing"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	for _, stmt := range []string{
		"TRUNCATE TABLE scan_runs CASCADE",
		"TRUNCATE TABLE hosts CASCADE",
		"TRUNCATE TABLE users CASCADE",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Logf("truncate (ok if benign): %v", err)
		}
	}
	return pool
}

func seedUser(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, username, email, password_hash)
		 VALUES ($1, $2, $3, $4)`,
		id, "runs-user", "runs@example.com", "argon2id$dummy") // pragma: allowlist secret
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func seedHost(t *testing.T, pool *pgxpool.Pool, createdBy uuid.UUID) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO hosts (id, hostname, ip_address, created_by)
		 VALUES ($1, $2, $3::inet, $4)`,
		id, "host-"+id.String(), "192.0.2.20", createdBy)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return id
}

// @ac AC-01
func TestInsert_QueuedRow(t *testing.T) {
	t.Run("system-scan-runs/AC-01", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		host := seedHost(t, pool, user)

		id, _ := uuid.NewV7()
		err := Insert(context.Background(), pool, Run{
			ID: id, HostID: host,
			TriggerSource: TriggerOnDemand,
			RequestedBy:   &user,
			PolicyVersion: "1.7.0",
			CorrelationID: "corr-123",
		})
		if err != nil {
			t.Fatalf("Insert: %v", err)
		}

		got, err := Get(context.Background(), pool, id)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Status != StatusQueued {
			t.Errorf("status = %s, want queued", got.Status)
		}
		if got.TriggerSource != TriggerOnDemand {
			t.Errorf("trigger_source = %s, want on_demand", got.TriggerSource)
		}
		if got.RequestedBy == nil || *got.RequestedBy != user {
			t.Errorf("requested_by = %v, want %s", got.RequestedBy, user)
		}
		if got.PolicyVersion != "1.7.0" || got.CorrelationID != "corr-123" {
			t.Errorf("policy/corr = %q/%q", got.PolicyVersion, got.CorrelationID)
		}
		if got.QueuedAt.IsZero() {
			t.Error("queued_at not defaulted")
		}
		if got.StartedAt != nil || got.FinishedAt != nil || got.Counts != nil {
			t.Error("queued row must not carry started/finished/counts")
		}
	})
}

// @ac AC-01
func TestInsert_EmptyTrigger_Errors(t *testing.T) {
	t.Run("system-scan-runs/AC-01", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		host := seedHost(t, pool, user)
		id, _ := uuid.NewV7()
		if err := Insert(context.Background(), pool, Run{ID: id, HostID: host}); err == nil {
			t.Error("Insert with empty TriggerSource must error")
		}
	})
}

// @ac AC-02
func TestMarkRunning_FlipsAndUpserts(t *testing.T) {
	t.Run("system-scan-runs/AC-02", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		host := seedHost(t, pool, user)
		ctx := context.Background()

		// Inserted row: flips to running, keeps its trigger.
		id1, _ := uuid.NewV7()
		_ = Insert(ctx, pool, Run{ID: id1, HostID: host, TriggerSource: TriggerOnDemand, RequestedBy: &user})
		if err := MarkRunning(ctx, pool, id1, host, "1.7.0"); err != nil {
			t.Fatalf("MarkRunning: %v", err)
		}
		got, _ := Get(ctx, pool, id1)
		if got.Status != StatusRunning || got.StartedAt == nil {
			t.Errorf("inserted row: status=%s started=%v; want running + started_at", got.Status, got.StartedAt)
		}
		if got.TriggerSource != TriggerOnDemand {
			t.Errorf("trigger flipped to %s; UPSERT must not overwrite the enqueuer's attribution", got.TriggerSource)
		}

		// Row-less job: UPSERT creates one attributed to 'scheduled'.
		id2, _ := uuid.NewV7()
		if err := MarkRunning(ctx, pool, id2, host, "1.7.0"); err != nil {
			t.Fatalf("MarkRunning (upsert): %v", err)
		}
		got2, err := Get(ctx, pool, id2)
		if err != nil {
			t.Fatalf("Get upserted: %v", err)
		}
		if got2.TriggerSource != TriggerScheduled || got2.Status != StatusRunning {
			t.Errorf("upserted row = %s/%s, want scheduled/running", got2.TriggerSource, got2.Status)
		}
	})
}

// @ac AC-03
func TestMarkCompleted_RecordsCounts(t *testing.T) {
	t.Run("system-scan-runs/AC-03", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		host := seedHost(t, pool, user)
		ctx := context.Background()

		id, _ := uuid.NewV7()
		_ = MarkRunning(ctx, pool, id, host, "")
		if err := MarkCompleted(ctx, pool, id, Counts{Pass: 400, Fail: 100, Skipped: 30, Error: 9}); err != nil {
			t.Fatalf("MarkCompleted: %v", err)
		}
		got, _ := Get(ctx, pool, id)
		if got.Status != StatusCompleted || got.FinishedAt == nil {
			t.Errorf("status=%s finished=%v; want completed + finished_at", got.Status, got.FinishedAt)
		}
		if got.Counts == nil || *got.Counts != (Counts{Pass: 400, Fail: 100, Skipped: 30, Error: 9}) {
			t.Errorf("counts = %+v, want 400/100/30/9", got.Counts)
		}
	})
}

// @ac AC-04
func TestMarkFailed_RecordsReason(t *testing.T) {
	t.Run("system-scan-runs/AC-04", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		host := seedHost(t, pool, user)
		ctx := context.Background()

		id, _ := uuid.NewV7()
		_ = MarkRunning(ctx, pool, id, host, "")
		if err := MarkFailed(ctx, pool, id, "host_key_unknown"); err != nil {
			t.Fatalf("MarkFailed: %v", err)
		}
		got, _ := Get(ctx, pool, id)
		if got.Status != StatusFailed || got.FailureReason != "host_key_unknown" || got.FinishedAt == nil {
			t.Errorf("got %s/%q/finished=%v; want failed/host_key_unknown/finished_at set",
				got.Status, got.FailureReason, got.FinishedAt)
		}
	})
}

// @ac AC-05
func TestTerminalStates_NeverOverwritten(t *testing.T) {
	t.Run("system-scan-runs/AC-05", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		host := seedHost(t, pool, user)
		ctx := context.Background()

		// completed -> MarkFailed is a no-op.
		id1, _ := uuid.NewV7()
		_ = MarkRunning(ctx, pool, id1, host, "")
		_ = MarkCompleted(ctx, pool, id1, Counts{Pass: 1})
		_ = MarkFailed(ctx, pool, id1, "late_failure")
		got, _ := Get(ctx, pool, id1)
		if got.Status != StatusCompleted || got.FailureReason != "" {
			t.Errorf("completed run mutated by late MarkFailed: %s/%q", got.Status, got.FailureReason)
		}

		// failed -> MarkCompleted is a no-op.
		id2, _ := uuid.NewV7()
		_ = MarkRunning(ctx, pool, id2, host, "")
		_ = MarkFailed(ctx, pool, id2, "timeout")
		_ = MarkCompleted(ctx, pool, id2, Counts{Pass: 9})
		got2, _ := Get(ctx, pool, id2)
		if got2.Status != StatusFailed || got2.Counts != nil {
			t.Errorf("failed run mutated by late MarkCompleted: %s counts=%v", got2.Status, got2.Counts)
		}

		// And MarkRunning must not resurrect a terminal run.
		_ = MarkRunning(ctx, pool, id2, host, "")
		got3, _ := Get(ctx, pool, id2)
		if got3.Status != StatusFailed {
			t.Errorf("terminal run resurrected to %s by MarkRunning", got3.Status)
		}
	})
}

// @ac AC-06
func TestLatestForHost_And_ActiveCount(t *testing.T) {
	t.Run("system-scan-runs/AC-06", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		host := seedHost(t, pool, user)
		other := seedHost(t, pool, user)
		ctx := context.Background()

		if _, err := LatestForHost(ctx, pool, host); !errors.Is(err, ErrNotFound) {
			t.Errorf("LatestForHost on never-scanned host = %v, want ErrNotFound", err)
		}

		early, _ := uuid.NewV7()
		_ = Insert(ctx, pool, Run{ID: early, HostID: host, TriggerSource: TriggerScheduled})
		_, _ = pool.Exec(ctx, // force distinct, older queued_at
			`UPDATE scan_runs SET queued_at = now() - interval '1 hour' WHERE id = $1`, early)
		_ = MarkCompleted(ctx, pool, early, Counts{})

		latest, _ := uuid.NewV7()
		_ = Insert(ctx, pool, Run{ID: latest, HostID: host, TriggerSource: TriggerOnDemand, RequestedBy: &user})

		otherRun, _ := uuid.NewV7()
		_ = MarkRunning(ctx, pool, otherRun, other, "")

		got, err := LatestForHost(ctx, pool, host)
		if err != nil {
			t.Fatalf("LatestForHost: %v", err)
		}
		if got.ID != latest {
			t.Errorf("LatestForHost = %s, want %s (newest by queued_at)", got.ID, latest)
		}

		// Active = the queued on-demand run + the running other-host run;
		// the completed early run is excluded.
		n, err := ActiveCount(ctx, pool)
		if err != nil {
			t.Fatalf("ActiveCount: %v", err)
		}
		if n != 2 {
			t.Errorf("ActiveCount = %d, want 2", n)
		}
	})
}

// @ac AC-08
// AC-08: ActiveByHostIDs returns the queued-or-running status per host in
// one grouped query; completed/never-scanned hosts are absent from the map;
// when a host has both a queued and a running row, 'running' wins.
func TestActiveByHostIDs(t *testing.T) {
	t.Run("system-scan-runs/AC-08", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		queuedHost := seedHost(t, pool, user)
		runningHost := seedHost(t, pool, user)
		completedHost := seedHost(t, pool, user)
		bothHost := seedHost(t, pool, user)
		neverHost := seedHost(t, pool, user)
		ctx := context.Background()

		// queuedHost: a single queued run.
		qID, _ := uuid.NewV7()
		_ = Insert(ctx, pool, Run{ID: qID, HostID: queuedHost, TriggerSource: TriggerScheduled})

		// runningHost: a single running run.
		rID, _ := uuid.NewV7()
		_ = MarkRunning(ctx, pool, rID, runningHost, "")

		// completedHost: only a completed run — must be absent.
		cID, _ := uuid.NewV7()
		_ = Insert(ctx, pool, Run{ID: cID, HostID: completedHost, TriggerSource: TriggerScheduled})
		_ = MarkCompleted(ctx, pool, cID, Counts{})

		// bothHost: a queued AND a running run — running must win.
		bQ, _ := uuid.NewV7()
		_ = Insert(ctx, pool, Run{ID: bQ, HostID: bothHost, TriggerSource: TriggerScheduled})
		bR, _ := uuid.NewV7()
		_ = MarkRunning(ctx, pool, bR, bothHost, "")

		ids := []uuid.UUID{queuedHost, runningHost, completedHost, bothHost, neverHost}
		got, err := ActiveByHostIDs(ctx, pool, ids)
		if err != nil {
			t.Fatalf("ActiveByHostIDs: %v", err)
		}

		if got[queuedHost] != StatusQueued {
			t.Errorf("queuedHost = %q, want %q", got[queuedHost], StatusQueued)
		}
		if got[runningHost] != StatusRunning {
			t.Errorf("runningHost = %q, want %q", got[runningHost], StatusRunning)
		}
		if _, ok := got[completedHost]; ok {
			t.Errorf("completedHost present (%q), want absent", got[completedHost])
		}
		if _, ok := got[neverHost]; ok {
			t.Errorf("neverHost present (%q), want absent", got[neverHost])
		}
		if got[bothHost] != StatusRunning {
			t.Errorf("bothHost = %q, want %q (running wins over queued)", got[bothHost], StatusRunning)
		}

		// Empty ids → empty map, no query.
		empty, err := ActiveByHostIDs(ctx, pool, nil)
		if err != nil {
			t.Fatalf("ActiveByHostIDs(nil): %v", err)
		}
		if len(empty) != 0 {
			t.Errorf("ActiveByHostIDs(nil) = %v, want empty", empty)
		}
	})
}

// @ac AC-07
func TestHostDelete_RestrictedByRuns(t *testing.T) {
	t.Run("system-scan-runs/AC-07", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		host := seedHost(t, pool, user)
		ctx := context.Background()

		id, _ := uuid.NewV7()
		_ = MarkRunning(ctx, pool, id, host, "")

		if _, err := pool.Exec(ctx, `DELETE FROM hosts WHERE id = $1`, host); err == nil {
			t.Error("host delete with extant scan_runs must fail (ON DELETE RESTRICT)")
		}
	})
}
