// Package corpustest seeds host_rule_state rows that are actually IN a
// host's current corpus.
//
// Why this exists. Nearly every compliance test in the tree seeds
// host_rule_state directly, bypassing transactionlog.Writer, with a random
// last_scan_id and no scan_runs row at all. That was harmless while the table
// and the corpus were the same set. They are not: host_rule_state_current
// keeps only rows whose last_scan_id names the host's most recent COMPLETED
// scan_runs row, so a directly seeded row belongs to no corpus and every
// score over it is empty.
//
// An empty corpus is not a loud failure. Counts come back zero, ratios come
// back nil, and a whole suite can go green asserting nothing against nothing.
// So the seed and the completed run have to be produced together, by one
// helper, rather than remembered separately at each call site.
//
// It is a package rather than a copied local function because test files are
// not importable, which is the same reason internal/db/dbtest is a package.
//
// A test that MEANS to exercise a host with no current corpus asks for it:
// use SeedRun with a non-completed status, or seed host_rule_state by hand.
// Wanting an empty corpus is a fine thing to want. Getting one by accident is
// not.
//
// Spec: system-current-corpus C-14.
package corpustest

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Rule is one rule outcome to seed. Only RuleID and Status are required.
type Rule struct {
	RuleID string
	// Status is pass, fail, skipped or error. Defaults to pass.
	Status string
	// Severity is critical, high, medium, low, or empty for NULL.
	Severity string
	// FrameworkRefs is the raw framework_refs JSON. Defaults to "{}".
	//
	// It must be a JSON OBJECT. The scalar null passes the column's NOT
	// NULL constraint and then breaks every jsonb_object_keys read over
	// it, including posture.Rollup, which is one statement over the whole
	// fleet. Seeding one is how you fail a test in a different package.
	FrameworkRefs string
}

// SeedRun inserts one scan_runs row for the host and returns its id.
//
// status is the scan_runs status: only 'completed' defines a corpus. Pass
// 'failed', 'running' or 'queued' to build a host that has scan history but
// no current corpus. finishedAt is written NULL when zero.
func SeedRun(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, status string, queuedAt, finishedAt time.Time) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("corpustest: new run id: %v", err)
	}
	var fin any
	if !finishedAt.IsZero() {
		fin = finishedAt
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO scan_runs
			(id, host_id, trigger_source, status, queued_at, started_at, finished_at)
		VALUES ($1, $2, 'scheduled', $3, $4, $4, $5)`,
		id, hostID, status, queuedAt, fin); err != nil {
		t.Fatalf("corpustest: seed scan_run (%s): %v", status, err)
	}
	return id
}

// SeedRules writes one host_rule_state row per rule, all stamped with scanID.
// Use it when a test needs several scans on one host and therefore has to
// choose which run each row belongs to.
func SeedRules(t *testing.T, pool *pgxpool.Pool, hostID, scanID uuid.UUID, rules ...Rule) {
	t.Helper()
	now := time.Now().UTC()
	for _, r := range rules {
		status := r.Status
		if status == "" {
			status = "pass"
		}
		refs := r.FrameworkRefs
		if refs == "" {
			refs = "{}"
		}
		var severity any
		if r.Severity != "" {
			severity = r.Severity
		}
		if _, err := pool.Exec(context.Background(), `
			INSERT INTO host_rule_state
				(host_id, rule_id, current_status, severity, last_checked_at,
				 check_count, last_scan_id, framework_refs,
				 first_seen_at, last_changed_at)
			VALUES ($1,$2,$3,$4,$5,1,$6,$7::jsonb,$5,$5)
			ON CONFLICT (host_id, rule_id) DO UPDATE SET
				current_status = EXCLUDED.current_status,
				severity       = EXCLUDED.severity,
				last_scan_id   = EXCLUDED.last_scan_id,
				framework_refs = EXCLUDED.framework_refs`,
			hostID, r.RuleID, status, severity, now, scanID, refs); err != nil {
			t.Fatalf("corpustest: seed rule state %s: %v", r.RuleID, err)
		}
	}
}

// SeedScanned is the one most tests want: a completed scan_runs row plus its
// rules, so the rows land IN the host's current corpus. It returns the scan
// id for a test that needs to name the run.
//
// The run is stamped as finished one hour ago rather than now, so a test
// adding a second, newer run does not have to fight a timestamp tie.
func SeedScanned(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, rules ...Rule) uuid.UUID {
	t.Helper()
	finished := time.Now().UTC().Add(-time.Hour)
	scanID := SeedRun(t, pool, hostID, "completed", finished.Add(-time.Minute), finished)
	SeedRules(t, pool, hostID, scanID, rules...)
	return scanID
}

// CurrentRun returns the host's most recent completed run, creating one if it
// has none. Use it from a package whose fixtures seed rules ONE CALL AT A
// TIME and so cannot hand SeedScanned the whole set at once: have the
// existing per-rule seeder call this for its last_scan_id and nothing else
// about the call sites has to change.
//
// The created run is backdated an hour. That matters more than it looks. A
// run stamped at now() outranks a run a test seeds for itself, and the test
// then asserts against this helper's run instead of its own. It cost one
// real failure that way: the compliance lens duration test seeds a run 85
// seconds long and got 0, because a helper-created run finished later and
// won LatestCompletedForHost. Backdating keeps a test's own runs on top.
//
// The lookup uses the same ordering as the host_rule_state_current view and
// scanruns.LatestCompletedForHost, so it returns the run the corpus will
// actually resolve to.
func CurrentRun(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(context.Background(), `
		SELECT id FROM scan_runs
		 WHERE host_id = $1 AND status = 'completed'
		 ORDER BY finished_at DESC NULLS LAST, id DESC
		 LIMIT 1`, hostID).Scan(&id)
	if err == nil {
		return id
	}
	finished := time.Now().UTC().Add(-time.Hour)
	return SeedRun(t, pool, hostID, "completed", finished.Add(-time.Minute), finished)
}
