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
	"errors"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/group"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	for _, stmt := range []string{
		"TRUNCATE TABLE report_snapshots CASCADE",
		"TRUNCATE TABLE groups CASCADE",
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

func ptrUUID(u uuid.UUID) *uuid.UUID { return &u }

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
		rep, err := svc.Generate(ctx, "alice@example.com", GenerateRequest{})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}

		// Row metadata: fixed identity + recorded actor + sampling instant.
		if rep.Title != executiveTitle || rep.Kind != KindExecutive ||
			rep.ScopeLabel != allHostsLabel || rep.Format != "json" {
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
		// Coverage: both active hosts were checked just now -> fresh; the
		// soft-deleted host is out of scope; none have a liveness row.
		if c.Coverage.HostsTotal != 2 || c.Coverage.HostsFresh != 2 ||
			c.Coverage.HostsStale != 0 || c.Coverage.HostsUnreachable != 0 {
			t.Errorf("coverage = %+v, want total=2 fresh=2 stale=0 unreachable=0", c.Coverage)
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

		rep, err := svc.Generate(ctx, "system", GenerateRequest{})
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
		// Coverage: hosts exist but were never scanned -> all stale.
		if c.Coverage.HostsTotal != 2 || c.Coverage.HostsFresh != 0 || c.Coverage.HostsStale != 2 {
			t.Errorf("coverage = %+v, want total=2 fresh=0 stale=2", c.Coverage)
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

		first, err := svc.Generate(ctx, "alice@example.com", GenerateRequest{})
		if err != nil {
			t.Fatalf("Generate first: %v", err)
		}
		// Ensure created_at ordering is unambiguous.
		time.Sleep(10 * time.Millisecond)
		second, err := svc.Generate(ctx, "bob@example.com", GenerateRequest{})
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

// @ac AC-11
// Generate stores the snapshot content-addressed: content_sha256 is a
// 64-char hex SHA-256 over the canonical content. Identical fleet posture
// yields identical content and therefore an identical hash across two
// distinct snapshots (content addressing); a posture change produces a
// different hash.
func TestGenerate_ContentAddressed(t *testing.T) {
	t.Run("api-reports/AC-11", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)
		owner := seedUser(t, pool)
		h := seedHost(t, pool, owner, false)
		seedRuleState(t, pool, h, "r1", "pass", "low")

		a, err := svc.Generate(ctx, "alice@example.com", GenerateRequest{})
		if err != nil {
			t.Fatalf("Generate a: %v", err)
		}
		b, err := svc.Generate(ctx, "alice@example.com", GenerateRequest{})
		if err != nil {
			t.Fatalf("Generate b: %v", err)
		}
		if len(a.ContentSHA256) != 64 {
			t.Errorf("content_sha256 = %q, want 64 hex chars", a.ContentSHA256)
		}
		if a.ID == b.ID {
			t.Fatalf("two generations share an id: %s", a.ID)
		}
		// Same posture -> same content -> same hash (content addressing).
		if a.ContentSHA256 != b.ContentSHA256 {
			t.Errorf("identical posture gave different hashes: %s vs %s", a.ContentSHA256, b.ContentSHA256)
		}

		// Change the posture: a new failing rule -> different content -> hash.
		seedRuleState(t, pool, h, "r2", "fail", "high")
		c, err := svc.Generate(ctx, "alice@example.com", GenerateRequest{})
		if err != nil {
			t.Fatalf("Generate c: %v", err)
		}
		if c.ContentSHA256 == a.ContentSHA256 {
			t.Errorf("posture change did not change the content hash: %s", c.ContentSHA256)
		}
	})
}

// seedRuleStateAt is seedRuleState with an explicit last_checked_at, so
// the coverage freshness window (fresh vs stale) can be exercised.
func seedRuleStateAt(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status, severity string, checkedAt time.Time) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO host_rule_state
		   (host_id, rule_id, current_status, severity, last_checked_at,
		    last_scan_id, first_seen_at, last_changed_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $5, $5)`,
		hostID, ruleID, status, nullIfEmpty(severity), checkedAt, uuid.New())
	if err != nil {
		t.Fatalf("seed rule_state at: %v", err)
	}
}

// seedLiveness inserts a host_liveness row with the given reachability.
func seedLiveness(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, reachability string) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO host_liveness (host_id, reachability_status) VALUES ($1, $2)`,
		hostID, reachability)
	if err != nil {
		t.Fatalf("seed liveness: %v", err)
	}
}

// @ac AC-10
// Coverage discloses how much of the in-scope fleet the report reflects.
// Seeded: a fresh host (recent check, reachable), a stale host (old check,
// reachable), and a never-scanned + unreachable host. Coverage must read
// total 3, fresh 1, stale 2 (old + never-scanned), unreachable 1; the
// unscanned host counts as stale, and a host with no liveness row is not
// counted unreachable.
func TestGenerate_Coverage(t *testing.T) {
	t.Run("api-reports/AC-10", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)
		owner := seedUser(t, pool)

		fresh := seedHost(t, pool, owner, false)
		stale := seedHost(t, pool, owner, false)
		never := seedHost(t, pool, owner, false)

		seedRuleStateAt(t, pool, fresh, "r1", "pass", "low", time.Now().Add(-1*time.Hour))
		seedRuleStateAt(t, pool, stale, "r1", "pass", "low", time.Now().Add(-48*time.Hour))
		// `never` has no host_rule_state at all -> stale.
		seedLiveness(t, pool, fresh, "reachable")
		seedLiveness(t, pool, never, "unreachable")
		// `stale` has no liveness row -> not counted unreachable (unknown).

		rep, err := svc.Generate(ctx, "alice@example.com", GenerateRequest{})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		c := decodeContent(t, rep)
		cov := c.Coverage
		if cov.HostsTotal != 3 {
			t.Errorf("hosts_total = %d, want 3", cov.HostsTotal)
		}
		if cov.HostsFresh != 1 {
			t.Errorf("hosts_fresh = %d, want 1 (only the recent check)", cov.HostsFresh)
		}
		if cov.HostsStale != 2 {
			t.Errorf("hosts_stale = %d, want 2 (old check + never scanned)", cov.HostsStale)
		}
		if cov.HostsUnreachable != 1 {
			t.Errorf("hosts_unreachable = %d, want 1", cov.HostsUnreachable)
		}
		// host_count is derived from coverage's total.
		if c.HostCount != cov.HostsTotal {
			t.Errorf("host_count %d != coverage.hosts_total %d", c.HostCount, cov.HostsTotal)
		}
	})
}

// seedRuleStateFW is seedRuleState plus a framework_refs JSONB, so the
// framework lens (framework_refs ? key) can be exercised.
func seedRuleStateFW(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status, severity, frameworkRefs string) {
	t.Helper()
	now := time.Now()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO host_rule_state
		   (host_id, rule_id, current_status, severity, framework_refs, last_checked_at,
		    last_scan_id, first_seen_at, last_changed_at)
		 VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $6, $6)`,
		hostID, ruleID, status, nullIfEmpty(severity), frameworkRefs, now, uuid.New())
	if err != nil {
		t.Fatalf("seed rule_state fw: %v", err)
	}
}

// @ac AC-08
// A group-scoped generate computes the posture over ONLY the group's
// member hosts: the report's scope echoes the group, scope_label is the
// group name, and the counts reflect the in-group host alone (the
// out-of-group host's passing rules do not inflate the numbers). An
// unknown group id surfaces group.ErrNotFound (the handler maps it to a
// 400 invalid-scope).
func TestGenerate_GroupScoped(t *testing.T) {
	t.Run("api-reports/AC-08", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		groupSvc := group.NewService(pool)
		svc := NewService(pool).WithGroups(groupSvc)
		owner := seedUser(t, pool)

		hIn := seedHost(t, pool, owner, false)
		hOut := seedHost(t, pool, owner, false)
		// In-group host: 1 pass, 1 critical fail. Out-of-group host: 2 pass
		// (would push compliance up and host_count to 2 if not scoped out).
		seedRuleState(t, pool, hIn, "r1", "pass", "medium")
		seedRuleState(t, pool, hIn, "r2", "fail", "critical")
		seedRuleState(t, pool, hOut, "r3", "pass", "low")
		seedRuleState(t, pool, hOut, "r4", "pass", "low")

		g, err := groupSvc.Create(ctx, group.CreateInput{
			Name: "Production", Kind: group.KindSite, Membership: group.MembershipManual,
		})
		if err != nil {
			t.Fatalf("create group: %v", err)
		}
		if err := groupSvc.AddMember(ctx, g.ID, hIn); err != nil {
			t.Fatalf("add member: %v", err)
		}

		rep, err := svc.Generate(ctx, "alice@example.com", GenerateRequest{GroupID: &g.ID})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if rep.ScopeLabel != "Production" {
			t.Errorf("scope_label = %q, want Production", rep.ScopeLabel)
		}
		if rep.Scope.GroupID == nil || *rep.Scope.GroupID != g.ID {
			t.Errorf("scope.group_id = %v, want %s", rep.Scope.GroupID, g.ID)
		}
		if rep.Scope.GroupName != "Production" {
			t.Errorf("scope.group_name = %q, want Production", rep.Scope.GroupName)
		}

		c := decodeContent(t, rep)
		if c.HostCount != 1 {
			t.Errorf("host_count = %d, want 1 (group member only)", c.HostCount)
		}
		if c.PassingRules != 1 || c.FailingRules != 1 {
			t.Errorf("passing/failing = %d/%d, want 1/1 (in-group host only)", c.PassingRules, c.FailingRules)
		}
		if c.CriticalIssues != 1 {
			t.Errorf("critical_issues = %d, want 1", c.CriticalIssues)
		}
		if c.CompliancePct == nil || *c.CompliancePct != 50 {
			t.Errorf("compliance_pct = %v, want 50", c.CompliancePct)
		}
		if len(c.TopFailingRules) != 1 || c.TopFailingRules[0].RuleID != "r2" {
			t.Errorf("top_failing_rules = %+v, want [r2]", c.TopFailingRules)
		}

		// Unknown group id -> group.ErrNotFound (handler maps to 400).
		if _, err := svc.Generate(ctx, "alice@example.com", GenerateRequest{GroupID: ptrUUID(uuid.New())}); !errors.Is(err, group.ErrNotFound) {
			t.Errorf("unknown group err = %v, want group.ErrNotFound", err)
		}
	})
}

// @ac AC-09
// A framework-scoped generate counts only rules whose framework_refs
// contain the lens key: the scope echoes the framework, scope_label
// carries the family ("All hosts · CIS"), and a critical fail tagged only
// to a different framework is excluded from every count.
func TestGenerate_FrameworkScoped(t *testing.T) {
	t.Run("api-reports/AC-09", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)
		owner := seedUser(t, pool)
		h := seedHost(t, pool, owner, false)

		seedRuleStateFW(t, pool, h, "c1", "pass", "medium", `{"cis_rhel9_v2.0.0": ["1.1"]}`)
		seedRuleStateFW(t, pool, h, "c2", "fail", "high", `{"cis_rhel9_v2.0.0": ["1.2"]}`)
		// STIG-only critical fail: must be excluded by the CIS lens.
		seedRuleStateFW(t, pool, h, "s1", "fail", "critical", `{"stig_rhel9_v2r7": ["V-1"]}`)

		rep, err := svc.Generate(ctx, "alice@example.com", GenerateRequest{Framework: "cis_rhel9_v2.0.0"})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if rep.ScopeLabel != "All hosts · CIS" {
			t.Errorf("scope_label = %q, want \"All hosts · CIS\"", rep.ScopeLabel)
		}
		if rep.Scope.Framework != "cis_rhel9_v2.0.0" {
			t.Errorf("scope.framework = %q, want cis_rhel9_v2.0.0", rep.Scope.Framework)
		}

		c := decodeContent(t, rep)
		if c.PassingRules != 1 || c.FailingRules != 1 {
			t.Errorf("passing/failing = %d/%d, want 1/1 (CIS rules only)", c.PassingRules, c.FailingRules)
		}
		if c.CriticalIssues != 0 {
			t.Errorf("critical_issues = %d, want 0 (STIG critical excluded by lens)", c.CriticalIssues)
		}
		if c.CompliancePct == nil || *c.CompliancePct != 50 {
			t.Errorf("compliance_pct = %v, want 50", c.CompliancePct)
		}
		if len(c.TopFailingRules) != 1 || c.TopFailingRules[0].RuleID != "c2" {
			t.Errorf("top_failing_rules = %+v, want [c2]", c.TopFailingRules)
		}
	})
}

// @ac AC-17
// Frameworks returns the distinct framework_refs keys present in the
// fleet, each counted by DISTINCT rule_id (not row), ordered by count
// desc then key asc. Seeded: cis on r1 (two hosts) + r3, stig on r2, nist
// on r3 -> cis=2 distinct rules, stig=1, nist=1.
func TestFrameworks_FleetCatalog(t *testing.T) {
	t.Run("api-reports/AC-17", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)
		owner := seedUser(t, pool)
		h1 := seedHost(t, pool, owner, false)
		h2 := seedHost(t, pool, owner, false)

		seedRuleStateFW(t, pool, h1, "r1", "pass", "low", `{"cis_rhel9_v2.0.0": ["1.1"]}`)
		seedRuleStateFW(t, pool, h2, "r1", "pass", "low", `{"cis_rhel9_v2.0.0": ["1.1"]}`)
		seedRuleStateFW(t, pool, h1, "r2", "fail", "high", `{"stig_rhel9_v2r7": ["V-1"]}`)
		seedRuleStateFW(t, pool, h2, "r3", "pass", "low", `{"cis_rhel9_v2.0.0": ["1.2"], "nist_800_53_r5": ["AC-1"]}`)

		fws, err := svc.Frameworks(ctx)
		if err != nil {
			t.Fatalf("Frameworks: %v", err)
		}
		want := []FrameworkCount{
			{Framework: "cis_rhel9_v2.0.0", RuleCount: 2},
			{Framework: "nist_800_53_r5", RuleCount: 1},
			{Framework: "stig_rhel9_v2r7", RuleCount: 1},
		}
		if len(fws) != len(want) {
			t.Fatalf("frameworks = %+v, want %+v", fws, want)
		}
		for i, w := range want {
			if fws[i] != w {
				t.Errorf("frameworks[%d] = %+v, want %+v", i, fws[i], w)
			}
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
