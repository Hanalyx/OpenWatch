// @spec system-activity
//
// AC traceability (this file):
//
//	AC-01  TestList_EmptyDB
//	AC-02  TestList_AllSources_FullPermissions
//	AC-03  TestList_MissingAlertRead_HiddenCount
//	AC-04  TestList_MissingHostRead_HiddenCount
//	AC-05  TestList_SourceFilter
//	AC-06  TestList_SeverityFilter
//	AC-07  TestList_TimeRangeFilter
//	AC-08  TestList_CursorPagination

package activity

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/alertrouter"
	"github.com/Hanalyx/openwatch/internal/db"
	"github.com/Hanalyx/openwatch/internal/db/migrations"
	"github.com/Hanalyx/openwatch/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func activityTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OPENWATCH_TEST_DSN")
	if dsn == "" {
		t.Skip("set OPENWATCH_TEST_DSN to run activity integration tests")
	}
	return dsn
}

func freshDB(t *testing.T) (*pgxpool.Pool, uuid.UUID) {
	t.Helper()
	dsn := activityTestDSN(t)
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
	// TRUNCATE…CASCADE delegates child cleanup to the schema. The
	// hosts row has 11 FK-referencing children (alerts, credentials,
	// host_intelligence_events, transactions, …); a hand-rolled list
	// rotted every time a new FK was added.
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE hosts CASCADE")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE audit_events")
	_, _ = pool.Exec(ctx, "TRUNCATE TABLE users CASCADE")
	creator, _ := uuid.NewV7()
	hash, _ := identity.HashPassword("seed-pw-12345-aa")
	_, _ = pool.Exec(ctx,
		`INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4)`,
		creator, "act-creator", "act@example.com", hash)
	return pool, creator
}

func seedHost(t *testing.T, pool *pgxpool.Pool, creator uuid.UUID) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO hosts (id, hostname, ip_address, created_by)
		 VALUES ($1, $2, $3::inet, $4)`,
		id, "act-"+id.String(), "192.0.2.40", creator)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return id
}

func seedAllSources(t *testing.T, pool *pgxpool.Pool, host uuid.UUID, base time.Time) {
	t.Helper()
	store := alertrouter.NewPgxStore(pool)
	_, err := store.Insert(context.Background(), alertrouter.Alert{
		Type: alertrouter.AlertTypeHostUnreachable, Severity: alertrouter.SeverityHigh,
		HostID: host, OccurredAt: base.Add(-3 * time.Minute),
		Title: "alert seed", Tags: map[string]string{"severity": "high"},
	})
	if err != nil {
		t.Fatalf("seed alert: %v", err)
	}

	txnID, _ := uuid.NewV7()
	scanID, _ := uuid.NewV7()
	_, err = pool.Exec(context.Background(),
		`INSERT INTO transactions (id, host_id, rule_id, scan_id, status, severity,
		                           change_kind, evidence, framework_refs, occurred_at)
		 VALUES ($1, $2, $3, $4, 'fail', 'medium', 'state_changed', '{}'::jsonb, '{}'::jsonb, $5)`,
		txnID, host, "rule-xyz", scanID, base.Add(-2*time.Minute))
	if err != nil {
		t.Fatalf("seed txn: %v", err)
	}

	intelID, _ := uuid.NewV7()
	_, err = pool.Exec(context.Background(),
		`INSERT INTO host_intelligence_events
		   (id, host_id, event_code, severity, detail, occurred_at, detected_at, correlation_id)
		 VALUES ($1, $2, 'system.package.updated', 'medium', '{}'::jsonb, $3, $3, 'seed-corr')`,
		intelID, host, base.Add(-1*time.Minute))
	if err != nil {
		t.Fatalf("seed intel: %v", err)
	}

	auditID, _ := uuid.NewV7()
	_, err = pool.Exec(context.Background(),
		`INSERT INTO audit_events (id, correlation_id, actor_type, action, severity, occurred_at, detail)
		 VALUES ($1, 'seed-corr', 'user', 'auth.login.success', 'info', $2, '{}'::jsonb)`,
		auditID, base.Add(-30*time.Second))
	if err != nil {
		t.Fatalf("seed audit: %v", err)
	}
}

// @ac AC-01
func TestList_EmptyDB(t *testing.T) {
	t.Run("system-activity/AC-01", func(t *testing.T) {
		pool, _ := freshDB(t)
		svc := NewService(pool)
		rows, hidden, cursor, err := svc.List(context.Background(),
			Filter{Limit: 50},
			Caller{CanReadAlerts: true, CanReadHosts: true, CanReadAudit: true})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(rows) != 0 {
			t.Errorf("rows=%d, want 0", len(rows))
		}
		if hidden != 0 || cursor != "" {
			t.Errorf("hidden=%d cursor=%q, want 0 + empty", hidden, cursor)
		}
	})
}

// @ac AC-02
func TestList_AllSources_FullPermissions(t *testing.T) {
	t.Run("system-activity/AC-02", func(t *testing.T) {
		pool, creator := freshDB(t)
		host := seedHost(t, pool, creator)
		seedAllSources(t, pool, host, time.Now().UTC())

		svc := NewService(pool)
		rows, hidden, _, err := svc.List(context.Background(),
			Filter{Limit: 50},
			Caller{CanReadAlerts: true, CanReadHosts: true, CanReadAudit: true})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(rows) != 4 {
			t.Errorf("rows=%d, want 4 (alert+txn+intel+audit)", len(rows))
		}
		if hidden != 0 {
			t.Errorf("hidden=%d, want 0 (full permissions)", hidden)
		}
		// Verify all sources represented.
		sources := map[Source]bool{}
		for _, r := range rows {
			sources[r.Source] = true
		}
		for _, want := range []Source{SourceAlert, SourceTransaction, SourceIntelligence, SourceAudit} {
			if !sources[want] {
				t.Errorf("source %q missing from result", want)
			}
		}
	})
}

// @ac AC-03
func TestList_MissingAlertRead_HiddenCount(t *testing.T) {
	t.Run("system-activity/AC-03", func(t *testing.T) {
		pool, creator := freshDB(t)
		host := seedHost(t, pool, creator)
		seedAllSources(t, pool, host, time.Now().UTC())

		svc := NewService(pool)
		rows, hidden, _, err := svc.List(context.Background(),
			Filter{Limit: 50},
			Caller{CanReadAlerts: false, CanReadHosts: true, CanReadAudit: true})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(rows) != 3 {
			t.Errorf("rows=%d, want 3 (no alerts)", len(rows))
		}
		if hidden != 1 {
			t.Errorf("hidden=%d, want 1 (the suppressed alert)", hidden)
		}
		for _, r := range rows {
			if r.Source == SourceAlert {
				t.Errorf("alert row leaked into rows: %v", r)
			}
		}
	})
}

// @ac AC-04
func TestList_MissingHostRead_HiddenCount(t *testing.T) {
	t.Run("system-activity/AC-04", func(t *testing.T) {
		pool, creator := freshDB(t)
		host := seedHost(t, pool, creator)
		seedAllSources(t, pool, host, time.Now().UTC())

		svc := NewService(pool)
		rows, hidden, _, err := svc.List(context.Background(),
			Filter{Limit: 50},
			Caller{CanReadAlerts: true, CanReadHosts: false, CanReadAudit: true})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		// alerts + audit visible (2); transactions + intelligence hidden (2).
		if len(rows) != 2 {
			t.Errorf("rows=%d, want 2 (alerts + audit only)", len(rows))
		}
		if hidden != 2 {
			t.Errorf("hidden=%d, want 2 (txn + intel suppressed)", hidden)
		}
	})
}

// @ac AC-05
func TestList_SourceFilter(t *testing.T) {
	t.Run("system-activity/AC-05", func(t *testing.T) {
		pool, creator := freshDB(t)
		host := seedHost(t, pool, creator)
		seedAllSources(t, pool, host, time.Now().UTC())

		svc := NewService(pool)
		rows, _, _, err := svc.List(context.Background(),
			Filter{Limit: 50, Source: string(SourceAlert)},
			Caller{CanReadAlerts: true, CanReadHosts: true, CanReadAudit: true})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(rows) != 1 {
			t.Errorf("rows=%d, want 1 (source=alert)", len(rows))
		}
		if len(rows) > 0 && rows[0].Source != SourceAlert {
			t.Errorf("rows[0].Source=%q, want alert", rows[0].Source)
		}
	})
}

// @ac AC-06
func TestList_SeverityFilter(t *testing.T) {
	t.Run("system-activity/AC-06", func(t *testing.T) {
		pool, creator := freshDB(t)
		host := seedHost(t, pool, creator)
		seedAllSources(t, pool, host, time.Now().UTC())

		svc := NewService(pool)
		rows, _, _, err := svc.List(context.Background(),
			Filter{Limit: 50, Severity: "high"},
			Caller{CanReadAlerts: true, CanReadHosts: true, CanReadAudit: true})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		// Only the alert (severity=high) matches.
		if len(rows) != 1 {
			t.Errorf("rows=%d, want 1 (severity=high)", len(rows))
		}
	})
}

// @ac AC-07
func TestList_TimeRangeFilter(t *testing.T) {
	t.Run("system-activity/AC-07", func(t *testing.T) {
		pool, creator := freshDB(t)
		host := seedHost(t, pool, creator)
		base := time.Now().UTC()
		seedAllSources(t, pool, host, base)

		svc := NewService(pool)
		since := base.Add(-2*time.Minute - 30*time.Second)
		until := base.Add(-45 * time.Second)
		rows, _, _, err := svc.List(context.Background(),
			Filter{Limit: 50, Since: &since, Until: &until},
			Caller{CanReadAlerts: true, CanReadHosts: true, CanReadAudit: true})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		// Within window: txn (-2m), intel (-1m). Outside: alert (-3m, before since), audit (-30s, ≥ until).
		if len(rows) != 2 {
			t.Errorf("rows=%d, want 2 (txn + intel in window)", len(rows))
		}
	})
}

// @ac AC-08
func TestList_CursorPagination(t *testing.T) {
	t.Run("system-activity/AC-08", func(t *testing.T) {
		pool, creator := freshDB(t)
		host := seedHost(t, pool, creator)
		base := time.Now().UTC()
		// Seed 6 alert rows so the union has exactly 6 candidates.
		store := alertrouter.NewPgxStore(pool)
		for i := 0; i < 6; i++ {
			_, err := store.Insert(context.Background(), alertrouter.Alert{
				Type:       alertrouter.AlertTypeDriftMinor,
				Severity:   alertrouter.SeverityLow,
				HostID:     host,
				OccurredAt: base.Add(-time.Duration(i) * time.Minute),
				Title:      "drift",
				Tags:       map[string]string{"i": stringFromInt(i)},
			})
			if err != nil {
				t.Fatalf("seed alert %d: %v", i, err)
			}
		}

		svc := NewService(pool)
		r1, _, c1, err := svc.List(context.Background(),
			Filter{Limit: 2},
			Caller{CanReadAlerts: true})
		if err != nil {
			t.Fatalf("page1: %v", err)
		}
		if len(r1) != 2 || c1 == "" {
			t.Fatalf("page1 len=%d cursor=%q", len(r1), c1)
		}
		r2, _, c2, err := svc.List(context.Background(),
			Filter{Limit: 2, Cursor: c1},
			Caller{CanReadAlerts: true})
		if err != nil {
			t.Fatalf("page2: %v", err)
		}
		if len(r2) != 2 || c2 == "" {
			t.Fatalf("page2 len=%d cursor=%q", len(r2), c2)
		}
		r3, _, c3, err := svc.List(context.Background(),
			Filter{Limit: 2, Cursor: c2},
			Caller{CanReadAlerts: true})
		if err != nil {
			t.Fatalf("page3: %v", err)
		}
		if len(r3) != 2 {
			t.Errorf("page3 len=%d, want 2", len(r3))
		}
		if c3 != "" {
			t.Errorf("page3 cursor=%q, want empty (terminal page)", c3)
		}
	})
}

// @ac AC-13
// Regression: an earlier version of commonWhere passed hostCol="''"
// for the audit leg and emitted `'' = $hostPH` when host_id was set.
// pgx encodes the parameter as a uuid, so Postgres tried to cast ''
// to uuid and the whole UNION crashed with
// `invalid input syntax for type uuid: ""`. The host-filtered list
// MUST now succeed and include rows from sources that DO have a
// host_id column (alert + transaction + intelligence) while excluding
// audit rows (host-agnostic source).
func TestList_HostIDFilter_ExcludesAuditWithoutCrashing(t *testing.T) {
	t.Run("system-activity/AC-13", func(t *testing.T) {
		pool, creator := freshDB(t)
		hostA := seedHost(t, pool, creator)
		base := time.Now().UTC()
		seedAllSources(t, pool, hostA, base)

		// A second host with its own alert — must NOT appear under
		// hostA's filter.
		hostB := seedHost(t, pool, creator)
		store := alertrouter.NewPgxStore(pool)
		if _, err := store.Insert(context.Background(), alertrouter.Alert{
			Type: alertrouter.AlertTypeHostUnreachable, Severity: alertrouter.SeverityLow,
			HostID: hostB, OccurredAt: base.Add(-90 * time.Second),
			Title: "hostB alert", Tags: map[string]string{"severity": "low"},
		}); err != nil {
			t.Fatalf("seed hostB alert: %v", err)
		}

		svc := NewService(pool)
		rows, _, _, err := svc.List(context.Background(),
			Filter{Limit: 50, HostID: &hostA},
			Caller{CanReadAlerts: true, CanReadHosts: true, CanReadAudit: true})
		if err != nil {
			t.Fatalf("List: %v (regression: '' = $uuid crash)", err)
		}
		// Expect 3 rows: alert + transaction + intelligence for hostA.
		// Audit MUST be excluded (no host_id column). hostB's alert
		// MUST be excluded (different host).
		if len(rows) != 3 {
			t.Fatalf("rows=%d, want 3 (alert+txn+intel for hostA)", len(rows))
		}
		seen := map[Source]bool{}
		for _, r := range rows {
			seen[r.Source] = true
			if r.HostID == nil || *r.HostID != hostA {
				t.Errorf("row source=%s host_id=%v, want hostA=%v", r.Source, r.HostID, hostA)
			}
		}
		if !seen[SourceAlert] || !seen[SourceTransaction] || !seen[SourceIntelligence] {
			t.Errorf("missing source(s): %v", seen)
		}
		if seen[SourceAudit] {
			t.Errorf("audit rows leaked into host-filtered result")
		}
	})
}

// stringFromInt avoids importing strconv just for a tiny helper.
func stringFromInt(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// referenced so the package compiles when json import is otherwise unused.
var _ = json.Marshal
