// @spec system-notifications
//
// AC traceability (this file):
//
//	AC-12  TestProjector_GroupsRegressionsPerHost — one grouped row per recipient, severity-ranked
//	AC-13  TestProjector_FirstScanSuppressed — baseline first_seen does not flood; first_seen critical counts only with prior history
//	AC-14  TestProjector_NoRegressionNoOp — nothing to report writes nothing; re-scan collapses + re-surfaces
//
// Skipped without OPENWATCH_TEST_DSN (uses the shared per-package isolated DB).
//
// Isolation note: dbtest.Pool is shared across this package's tests and
// notifyfeed.RecordFanout writes one row per user in the WHOLE users table, so
// these tests use per-call-unique usernames and assert on rows scoped to each
// test's own (unique) host id rather than on the recipient's total list length.
package notifyfeed

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
)

// uniq returns a per-call-unique token so seeded usernames/hostnames never
// collide on the shared per-package test DB (not reset between test functions).
// Uses the trailing random bytes of a v7 uuid — the LEADING bytes are the
// millisecond timestamp and are identical across a fast test run.
func uniq() string {
	id, _ := uuid.NewV7()
	return id.String()[24:]
}

func seedHost(t *testing.T, pool *pgxpool.Pool, creator uuid.UUID, hostname, displayName string) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO hosts (id, hostname, ip_address, display_name, created_by)
		 VALUES ($1, $2, '10.0.0.9', $3, $4)`,
		id, hostname, nullIfEmpty(displayName), creator); err != nil {
		t.Fatalf("seed host %s: %v", hostname, err)
	}
	return id
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func seedTxn(t *testing.T, pool *pgxpool.Pool, hostID, scanID uuid.UUID, ruleID, status, severity, changeKind string, at time.Time) {
	t.Helper()
	id, _ := uuid.NewV7()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO transactions
			(id, host_id, rule_id, scan_id, status, severity, change_kind, evidence, occurred_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, '{}'::jsonb, $8)`,
		id, hostID, ruleID, scanID, status, nullIfEmpty(severity), changeKind, at); err != nil {
		t.Fatalf("seed txn %s/%s: %v", ruleID, changeKind, err)
	}
}

// notifsForHost returns the user's notifications scoped to one host id, so
// fan-out rows from other tests on the shared DB don't perturb the assertion.
func notifsForHost(t *testing.T, s *Store, user, host uuid.UUID) []Notification {
	t.Helper()
	all, err := s.List(context.Background(), user, false, 200)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var out []Notification
	for _, n := range all {
		if n.HostID != nil && *n.HostID == host {
			out = append(out, n)
		}
	}
	return out
}

// @ac AC-12
func TestProjector_GroupsRegressionsPerHost(t *testing.T) {
	t.Run("system-notifications/AC-12", func(t *testing.T) {
		pool := dbtest.Pool(t)
		ctx := context.Background()
		s := NewStore(pool)
		p := NewProjector(s)

		u1 := seedUser(t, pool, "alice-"+uniq())
		u2 := seedUser(t, pool, "bob-"+uniq())
		creator := seedUser(t, pool, "creator-"+uniq())
		host := seedHost(t, pool, creator, "web-"+uniq(), "Web One")

		now := time.Now().UTC()
		scan, _ := uuid.NewV7()
		// Three rules flipped to fail (1 critical, 2 high). Noise that must NOT
		// count: a fail->pass recovery and a severity_changed row.
		seedTxn(t, pool, host, scan, "rule.crit", "fail", "critical", "state_changed", now)
		seedTxn(t, pool, host, scan, "rule.hi1", "fail", "high", "state_changed", now)
		seedTxn(t, pool, host, scan, "rule.hi2", "fail", "high", "state_changed", now)
		seedTxn(t, pool, host, scan, "rule.fixed", "pass", "high", "state_changed", now) // recovery
		seedTxn(t, pool, host, scan, "rule.sev", "fail", "medium", "severity_changed", now)

		if err := p.ProjectScan(ctx, scan, host); err != nil {
			t.Fatalf("ProjectScan: %v", err)
		}

		for _, u := range []uuid.UUID{u1, u2} {
			list := notifsForHost(t, s, u, host)
			if len(list) != 1 {
				t.Fatalf("user %s: want 1 host notification, got %d", u, len(list))
			}
			n := list[0]
			if n.Kind != "rule_regression" {
				t.Errorf("kind = %q, want rule_regression", n.Kind)
			}
			if n.Severity != "critical" {
				t.Errorf("severity = %q, want critical (highest of the group)", n.Severity)
			}
			if want := "Web One: 3 rules regressed (1 critical)"; n.Title != want {
				t.Errorf("title = %q, want %q", n.Title, want)
			}
			if n.Link != "/hosts/"+host.String() {
				t.Errorf("link = %q, want /hosts/<host>", n.Link)
			}
		}
	})
}

// @ac AC-13
func TestProjector_FirstScanSuppressed(t *testing.T) {
	t.Run("system-notifications/AC-13", func(t *testing.T) {
		pool := dbtest.Pool(t)
		ctx := context.Background()
		s := NewStore(pool)
		p := NewProjector(s)

		u := seedUser(t, pool, "alice-"+uniq())
		creator := seedUser(t, pool, "creator-"+uniq())
		hostname := "db-" + uniq()
		host := seedHost(t, pool, creator, hostname, "") // no display name → title uses hostname

		now := time.Now().UTC()
		// First scan: every fail is first_seen (baseline), including a critical.
		firstScan, _ := uuid.NewV7()
		seedTxn(t, pool, host, firstScan, "rule.a", "fail", "critical", "first_seen", now)
		seedTxn(t, pool, host, firstScan, "rule.b", "fail", "high", "first_seen", now)

		if err := p.ProjectScan(ctx, firstScan, host); err != nil {
			t.Fatalf("ProjectScan first: %v", err)
		}
		if list := notifsForHost(t, s, u, host); len(list) != 0 {
			t.Fatalf("first scan must not notify (baseline), got %d", len(list))
		}

		// A later scan now has prior history, so a NEW critical first_seen
		// finding is bell-worthy (a new high first_seen is not).
		secondScan, _ := uuid.NewV7()
		seedTxn(t, pool, host, secondScan, "rule.newcrit", "fail", "critical", "first_seen", now.Add(time.Hour))
		seedTxn(t, pool, host, secondScan, "rule.newhi", "fail", "high", "first_seen", now.Add(time.Hour))

		if err := p.ProjectScan(ctx, secondScan, host); err != nil {
			t.Fatalf("ProjectScan second: %v", err)
		}
		list := notifsForHost(t, s, u, host)
		if len(list) != 1 {
			t.Fatalf("second scan: want 1 notification, got %d", len(list))
		}
		// Only the critical first_seen counts → "1 rule regressed (1 critical)".
		if want := hostname + ": 1 rule regressed (1 critical)"; list[0].Title != want {
			t.Errorf("title = %q, want %q (hostname fallback; new high suppressed)", list[0].Title, want)
		}
	})
}

// @ac AC-14
func TestProjector_NoRegressionNoOp(t *testing.T) {
	t.Run("system-notifications/AC-14", func(t *testing.T) {
		pool := dbtest.Pool(t)
		ctx := context.Background()
		s := NewStore(pool)
		p := NewProjector(s)

		u := seedUser(t, pool, "alice-"+uniq())
		creator := seedUser(t, pool, "creator-"+uniq())
		host := seedHost(t, pool, creator, "app-"+uniq(), "App One")

		now := time.Now().UTC()
		// A scan with only a recovery + severity churn → nothing to report.
		quiet, _ := uuid.NewV7()
		seedTxn(t, pool, host, quiet, "rule.ok", "pass", "high", "state_changed", now)
		seedTxn(t, pool, host, quiet, "rule.sev", "fail", "low", "severity_changed", now)
		if err := p.ProjectScan(ctx, quiet, host); err != nil {
			t.Fatalf("ProjectScan quiet: %v", err)
		}
		if list := notifsForHost(t, s, u, host); len(list) != 0 {
			t.Fatalf("quiet scan must not notify, got %d", len(list))
		}

		// Two scans that each regress collapse onto ONE per-host row (group_key
		// is per host); the second re-surfaces it UNREAD.
		scanA, _ := uuid.NewV7()
		seedTxn(t, pool, host, scanA, "rule.x", "fail", "high", "state_changed", now)
		if err := p.ProjectScan(ctx, scanA, host); err != nil {
			t.Fatalf("ProjectScan A: %v", err)
		}
		if _, err := s.MarkAllRead(ctx, u); err != nil {
			t.Fatalf("mark read: %v", err)
		}

		scanB, _ := uuid.NewV7()
		seedTxn(t, pool, host, scanB, "rule.y", "fail", "critical", "state_changed", now.Add(time.Hour))
		if err := p.ProjectScan(ctx, scanB, host); err != nil {
			t.Fatalf("ProjectScan B: %v", err)
		}

		list := notifsForHost(t, s, u, host)
		if len(list) != 1 {
			t.Fatalf("two regressing scans must collapse to 1 row, got %d", len(list))
		}
		if list[0].ReadAt != nil {
			t.Errorf("second regression must re-surface the row unread")
		}
		if list[0].Severity != "critical" {
			t.Errorf("collapsed row should reflect latest scan severity critical, got %q", list[0].Severity)
		}
	})
}
