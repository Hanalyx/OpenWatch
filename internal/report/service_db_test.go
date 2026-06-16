// @spec api-reports
//
// DB-backed service AC coverage (DSN-gated). The content-shaping and
// rounding contracts are covered without a DB in service_test.go; these
// exercise the real schema (migration 0028 plus hosts / host_rule_state)
// against a Postgres reachable via OPENWATCH_TEST_DSN:
//
//	AC-04  TestGenerate_ComputesPostureFromState (Generate samples live posture, freezes it)
//	AC-05  TestGenerate_UnscannedFleet           (no evaluated rows -> nil compliance, empty top list)
//	AC-06  TestListAndGet_RoundTripAndNotFound    (List newest-first, Get by id, ErrNotFound)
//
// The endpoint RBAC + status mapping (host:read / host:write, 404, 503)
// lives in internal/server alongside the handlers.

package report

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	for _, stmt := range []string{
		"TRUNCATE TABLE reports CASCADE",
		"TRUNCATE TABLE host_rule_state CASCADE",
		"TRUNCATE TABLE hosts CASCADE",
		"TRUNCATE TABLE users CASCADE",
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Logf("truncate (ok if benign): %v", err)
		}
	}
	return pool
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func seedUser(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, username, email, password_hash)
		 VALUES ($1, $2, $3, $4)`,
		id, "rpt-"+id.String(), id.String()+"@example.com", "argon2id$dummy") // pragma: allowlist secret
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

// seedHost inserts an active host. deleted soft-deletes it after insert.
func seedHost(t *testing.T, pool *pgxpool.Pool, createdBy uuid.UUID, deleted bool) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO hosts (id, hostname, ip_address, os_family, created_by)
		 VALUES ($1, $2, '192.0.2.40'::inet, 'rhel', $3)`,
		id, "host-"+id.String(), createdBy)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	if deleted {
		if _, err := pool.Exec(context.Background(),
			`UPDATE hosts SET deleted_at = now() WHERE id = $1`, id); err != nil {
			t.Fatalf("soft-delete host: %v", err)
		}
	}
	return id
}

func seedRuleState(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status, severity string) {
	t.Helper()
	now := time.Now()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO host_rule_state
		   (host_id, rule_id, current_status, severity, last_checked_at,
		    last_scan_id, first_seen_at, last_changed_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $5, $5)`,
		hostID, ruleID, status, nullIfEmpty(severity), now, uuid.New())
	if err != nil {
		t.Fatalf("seed rule_state: %v", err)
	}
}

// @ac AC-04
// Generate samples the live fleet posture and freezes it into a report
// row. Posture: 2 active hosts, one soft-deleted host (excluded from the
// host count), 4 passing + 2 failing rule_state rows, one of the failures
// critical. rule-x fails on both hosts so it leads the top-failing list.
func TestGenerate_ComputesPostureFromState(t *testing.T) {
	t.Run("api-reports/AC-04", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)
		owner := seedUser(t, pool)

		h1 := seedHost(t, pool, owner, false)
		h2 := seedHost(t, pool, owner, false)
		seedHost(t, pool, owner, true) // soft-deleted: excluded from host_count

		// h1: 2 pass. h2: 1 pass, 2 fail (one critical). rule-x fails on both.
		seedRuleState(t, pool, h1, "rule-x", "fail", "critical")
		seedRuleState(t, pool, h1, "rule-y", "pass", "medium")
		seedRuleState(t, pool, h2, "rule-x", "fail", "medium")
		seedRuleState(t, pool, h2, "rule-z", "pass", "medium")
		seedRuleState(t, pool, h2, "rule-w", "pass", "low")
		seedRuleState(t, pool, h2, "rule-v", "fail", "high")

		before := time.Now().UTC().Add(-time.Second)
		rep, err := svc.Generate(ctx, "alice@example.com")
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}

		// Row metadata: fixed identity + recorded actor + sampling instant.
		if rep.Title != executiveTitle || rep.Kind != KindExecutive ||
			rep.ScopeLabel != executiveScope || rep.Format != "json" {
			t.Errorf("report metadata = %+v", rep)
		}
		if rep.GeneratedBy != "alice@example.com" {
			t.Errorf("generated_by = %q, want alice@example.com", rep.GeneratedBy)
		}
		if rep.DataAsOf.Before(before) {
			t.Errorf("data_as_of %v predates generation start %v", rep.DataAsOf, before)
		}
		if rep.ID == uuid.Nil {
			t.Errorf("report id is nil")
		}

		// Re-fetch and decode the frozen content; it must reflect the posture.
		got, err := svc.Get(ctx, rep.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		c := decodeContent(t, got)
		if c.HostCount != 2 {
			t.Errorf("host_count = %d, want 2 (soft-deleted excluded)", c.HostCount)
		}
		if c.PassingRules != 3 || c.FailingRules != 3 {
			t.Errorf("passing/failing = %d/%d, want 3/3", c.PassingRules, c.FailingRules)
		}
		if c.CriticalIssues != 1 {
			t.Errorf("critical_issues = %d, want 1", c.CriticalIssues)
		}
		// 3 pass / 6 evaluated = 50%.
		if c.CompliancePct == nil || *c.CompliancePct != 50 {
			t.Errorf("compliance_pct = %v, want 50", c.CompliancePct)
		}
		// rule-x fails on 2 hosts and must lead; rule-v fails on 1.
		if len(c.TopFailingRules) != 2 {
			t.Fatalf("top_failing_rules = %d entries, want 2: %+v", len(c.TopFailingRules), c.TopFailingRules)
		}
		if c.TopFailingRules[0].RuleID != "rule-x" || c.TopFailingRules[0].FailingHostCount != 2 {
			t.Errorf("top failing[0] = %+v, want rule-x x2", c.TopFailingRules[0])
		}
		if c.TopFailingRules[1].RuleID != "rule-v" || c.TopFailingRules[1].FailingHostCount != 1 {
			t.Errorf("top failing[1] = %+v, want rule-v x1", c.TopFailingRules[1])
		}
	})
}

// @ac AC-05
// A fleet with hosts but no evaluated rule_state rows reports nil
// compliance (never scanned, not 0%) and an empty (non-null) top-failing
// list, so the document and its later renderer never see a JSON null slice.
func TestGenerate_UnscannedFleet(t *testing.T) {
	t.Run("api-reports/AC-05", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)
		owner := seedUser(t, pool)
		seedHost(t, pool, owner, false)
		seedHost(t, pool, owner, false)

		rep, err := svc.Generate(ctx, "system")
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		c := decodeContent(t, rep)
		if c.HostCount != 2 {
			t.Errorf("host_count = %d, want 2", c.HostCount)
		}
		if c.PassingRules != 0 || c.FailingRules != 0 || c.CriticalIssues != 0 {
			t.Errorf("counts = %+v, want all zero", c)
		}
		if c.CompliancePct != nil {
			t.Errorf("compliance_pct = %v, want nil (unscanned)", *c.CompliancePct)
		}
		if c.TopFailingRules == nil {
			t.Errorf("top_failing_rules is nil, want empty slice")
		}
		if len(c.TopFailingRules) != 0 {
			t.Errorf("top_failing_rules = %+v, want empty", c.TopFailingRules)
		}
	})
}

// @ac AC-06
// List returns reports newest-first; Get fetches by id; an unknown id
// returns ErrNotFound. Reports are immutable, so two generations yield two
// distinct rows ordered by creation time.
func TestListAndGet_RoundTripAndNotFound(t *testing.T) {
	t.Run("api-reports/AC-06", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)
		owner := seedUser(t, pool)
		seedHost(t, pool, owner, false)

		if empty, err := svc.List(ctx); err != nil || len(empty) != 0 {
			t.Fatalf("List on empty = %v, %v; want [] nil", empty, err)
		}

		first, err := svc.Generate(ctx, "alice@example.com")
		if err != nil {
			t.Fatalf("Generate first: %v", err)
		}
		// Ensure created_at ordering is unambiguous.
		time.Sleep(10 * time.Millisecond)
		second, err := svc.Generate(ctx, "bob@example.com")
		if err != nil {
			t.Fatalf("Generate second: %v", err)
		}
		if first.ID == second.ID {
			t.Fatalf("two generations share an id: %s", first.ID)
		}

		list, err := svc.List(ctx)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(list) != 2 {
			t.Fatalf("List = %d rows, want 2", len(list))
		}
		// Newest first.
		if list[0].ID != second.ID || list[1].ID != first.ID {
			t.Errorf("List order = [%s, %s], want newest (%s) first",
				list[0].ID, list[1].ID, second.ID)
		}

		got, err := svc.Get(ctx, first.ID)
		if err != nil {
			t.Fatalf("Get(first): %v", err)
		}
		if got.ID != first.ID || got.GeneratedBy != "alice@example.com" {
			t.Errorf("Get(first) = %+v", got)
		}

		if _, err := svc.Get(ctx, uuid.New()); err != ErrNotFound {
			t.Errorf("Get(unknown) err = %v, want ErrNotFound", err)
		}
	})
}

// decodeContent unmarshals a report's frozen JSON content into the typed
// executive shape, failing the test on malformed content.
func decodeContent(t *testing.T, rep Report) ExecutiveContent {
	t.Helper()
	var c ExecutiveContent
	if err := json.Unmarshal(rep.Content, &c); err != nil {
		t.Fatalf("decode content: %v", err)
	}
	return c
}
