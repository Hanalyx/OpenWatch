// @spec system-current-corpus
//
// AC traceability (DSN-gated):
//
//	AC-23  TestRepair_RecoversFrameworkRefsWithoutTouchingAnythingElse
//
// The repair for rows an earlier synthetic write damaged. It lives in
// this package because the criterion that matters is a posture.Rollup
// before-and-after pair, and Rollup is what the damage breaks.

package posture

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// repairStatements returns the two UPDATE statements migration 0060
// carries, read FROM THE MIGRATION rather than copied into this file.
//
// A copy would drift, and worse, it would pass while the shipped
// statement was broken: the test would be validating the copy. Reading
// the file means the assertions below are about what actually runs.
func repairStatements(t *testing.T) []string {
	t.Helper()
	path := filepath.Join("..", "db", "migrations", "0060_host_rule_state_current.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	body := string(raw)
	// The repair is everything after the index and before the Down block.
	start := strings.Index(body, "-- Repair rows an earlier remediation corrupted.")
	if start < 0 {
		t.Fatal("migration 0060 no longer contains the repair section; this test is reading " +
			"for a marker that moved, and a test that silently finds nothing proves nothing")
	}
	end := strings.Index(body, "-- +goose Down")
	if end < 0 || end < start {
		t.Fatal("migration 0060 has no Down marker after the repair")
	}
	section := body[start:end]
	// Strip line comments so the split below sees only SQL.
	section = regexp.MustCompile(`(?m)^\s*--.*$`).ReplaceAllString(section, "")

	var out []string
	for _, stmt := range strings.Split(section, ";") {
		if strings.TrimSpace(stmt) != "" {
			out = append(out, stmt)
		}
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 repair statements in migration 0060, parsed %d. The recovery and "+
			"the floor are both required and the order between them matters", len(out))
	}
	return out
}

func applyRepair(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for i, stmt := range repairStatements(t) {
		if _, err := pool.Exec(context.Background(), stmt); err != nil {
			t.Fatalf("repair statement %d: %v", i+1, err)
		}
	}
}

// seedRun inserts a scan_runs row with an explicit finished_at.
func seedRun(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, finishedAt time.Time) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO scan_runs (id, host_id, trigger_source, status, queued_at, started_at, finished_at)
		VALUES ($1, $2, 'scheduled', 'completed', $3, $3, $3)`, id, hostID, finishedAt)
	if err != nil {
		t.Fatalf("seed scan_run: %v", err)
	}
	return id
}

// seedScanResult records what a scan observed for one rule. This is the
// audit memory the repair recovers from.
func seedScanResult(t *testing.T, pool *pgxpool.Pool, scanID, hostID uuid.UUID, ruleID, refs string, severity any) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO scan_results (scan_id, host_id, rule_id, status, severity, framework_refs)
		VALUES ($1, $2, $3, 'fail', $4, $5::jsonb)`,
		scanID, hostID, ruleID, severity, refs)
	if err != nil {
		t.Fatalf("seed scan_result %s: %v", ruleID, err)
	}
}

// seedRuleStateRaw writes a host_rule_state row with an exact
// framework_refs value, including the JSON scalar null the defect wrote.
func seedRuleStateRaw(t *testing.T, pool *pgxpool.Pool, hostID, scanID uuid.UUID, ruleID, refs string, severity any) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO host_rule_state
			(host_id, rule_id, current_status, severity, last_checked_at,
			 check_count, last_scan_id, framework_refs, first_seen_at, last_changed_at)
		VALUES ($1, $2, 'fail', $3, now(), 1, $4, $5::jsonb, now(), now())`,
		hostID, ruleID, severity, scanID, refs)
	if err != nil {
		t.Fatalf("seed rule state %s: %v", ruleID, err)
	}
}

// rowState is compared by VALUE, so Severity is a normalized string
// rather than a *string. Holding the pointer made the idempotency check
// compare addresses: two reads of an unchanged row are never equal, so
// it reported every row as changed and printed hex addresses instead of
// severities.
type rowState struct {
	RefsType string
	Refs     string
	Severity string // "NULL" when the column is NULL
}

func readRow(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID string) rowState {
	t.Helper()
	var r rowState
	var sevPtr *string
	err := pool.QueryRow(context.Background(), `
		SELECT jsonb_typeof(framework_refs), framework_refs::text, severity
		  FROM host_rule_state WHERE host_id = $1 AND rule_id = $2`,
		hostID, ruleID).Scan(&r.RefsType, &r.Refs, &sevPtr)
	if err != nil {
		t.Fatalf("read row %s: %v", ruleID, err)
	}
	r.Severity = sev(sevPtr)
	return r
}

// hoursAgo is a timestamp n hours in the past.
func hoursAgo(n int) time.Time {
	return time.Now().UTC().Add(-time.Duration(n) * time.Hour)
}

func sev(p *string) string {
	if p == nil {
		return "NULL"
	}
	return *p
}

// @ac AC-23
// AC-23: the repair recovers what a scan recorded, falls back where
// nothing did, and touches nothing else.
//
// The before-and-after posture.Rollup pair is the criterion that
// matters. Rollup is ONE statement over every live host, so a single row
// holding the JSON scalar null aborts it and no host gets a snapshot.
// That is what makes this a fleet-wide outage rather than a tidy-up of
// one column, and asserting the abort BEFORE the repair is what proves
// the repair fixed something real.
func TestRepair_RecoversFrameworkRefsWithoutTouchingAnythingElse(t *testing.T) {
	t.Run("system-current-corpus/AC-23", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool)
		host := seedHost(t, pool, user)

		const realRefs = `{"cis": ["1.1"]}`
		const otherRefs = `{"stig_rhel9": ["V-1"]}`

		// (a) Damaged, with a scan_results row holding refs and severity.
		runA := seedRun(t, pool, host, hoursAgo(3))
		seedScanResult(t, pool, runA, host, "a-recovered", realRefs, "high")
		seedRuleStateRaw(t, pool, host, runA, "a-recovered", "null", nil)

		// (b) Damaged, with TWO scan_results rows from runs that finished
		// OUT OF ORDER. The values must come from the run that finished
		// LAST, which pins the ordering rule rather than a rowid accident.
		// The later-finishing run is inserted FIRST, so a query taking
		// whichever it meets first gets the wrong one.
		lateFinisher := seedRun(t, pool, host, hoursAgo(1))
		earlyFinisher := seedRun(t, pool, host, hoursAgo(2))
		seedScanResult(t, pool, lateFinisher, host, "b-ordered", realRefs, "critical")
		seedScanResult(t, pool, earlyFinisher, host, "b-ordered", otherRefs, "low")
		seedRuleStateRaw(t, pool, host, lateFinisher, "b-ordered", "null", nil)

		// (c) Damaged, no scan_results row at all: the pre-0029 case.
		seedRuleStateRaw(t, pool, host, runA, "c-floored", "null", nil)

		// (d) Undamaged, real object and real severity: unchanged.
		seedScanResult(t, pool, runA, host, "d-untouched", otherRefs, "low")
		seedRuleStateRaw(t, pool, host, runA, "d-untouched", realRefs, "medium")

		// (e) Undamaged, real object and a LEGITIMATELY empty severity,
		// with a scan_results row carrying a non-empty one. This is the
		// case that fails a recovery keyed on empty severity instead of
		// on the damaged framework_refs: such a recovery would overwrite
		// a real, current NULL with a value from history.
		seedScanResult(t, pool, runA, host, "e-empty-severity", otherRefs, "critical")
		seedRuleStateRaw(t, pool, host, runA, "e-empty-severity", realRefs, nil)

		// BEFORE: the rollup aborts and writes nothing.
		//
		// The assertion is that it ABORTS and writes nothing, not that it
		// aborts with a particular message. Rollup is a UNION ALL and
		// Postgres is free to surface either arm's failure first, so
		// pinning the text would make this test depend on a plan choice.
		// What attributes the abort to the damaged rows is the after-half
		// below: the repair touches framework_refs and severity and
		// nothing else, and the same statement then succeeds.
		if _, err := Rollup(ctx, pool, time.Now()); err == nil {
			t.Fatal("posture.Rollup succeeded with a JSON-null framework_refs row present. " +
				"If it no longer aborts, the outage this repair exists to end is gone by some " +
				"other route and this test is measuring nothing")
		}
		var snapshots int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM posture_snapshots WHERE host_id = $1`, host).Scan(&snapshots); err != nil {
			t.Fatalf("count snapshots: %v", err)
		}
		if snapshots != 0 {
			t.Errorf("snapshots before repair = %d, want 0; the aborted statement must write nothing", snapshots)
		}

		applyRepair(t, pool)

		// (a) recovered to what the scan recorded, not to an empty object.
		if got := readRow(t, pool, host, "a-recovered"); got.RefsType != "object" ||
			got.Refs != realRefs || got.Severity != "high" {
			t.Errorf("(a) = %+v, want refs %s and severity high. Recovering to '{}' would be a "+
				"floor, not a recovery: the mapping was in scan_results the whole time",
				got, realRefs)
		}

		// (b) the values come from the run that finished LAST.
		if got := readRow(t, pool, host, "b-ordered"); got.Refs != realRefs || got.Severity != "critical" {
			t.Errorf("(b) = %+v, want refs %s and severity critical, from the run that finished "+
				"last. Taking the other run's values means the recovery is ordering by insertion "+
				"rather than by finished_at", got, realRefs)
		}

		// (c) floored, and severity left as the synthetic write left it.
		if got := readRow(t, pool, host, "c-floored"); got.RefsType != "object" || got.Refs != "{}" {
			t.Errorf("(c) = %+v, want the empty-object floor; there is no scan_results row to "+
				"recover from, and a fleet-wide rollup failure has to become a per-rule gap", got)
		} else if got.Severity != "NULL" {
			t.Errorf("(c) severity = %s, want NULL; the floor statement recovers nothing and "+
				"must not invent a severity", got.Severity)
		}

		// (d) untouched, asserted by value so a blanket overwrite fails here.
		if got := readRow(t, pool, host, "d-untouched"); got.Refs != realRefs || got.Severity != "medium" {
			t.Errorf("(d) = %+v, want refs %s and severity medium, unchanged. A repair that "+
				"rewrote every row from scan_results would land otherRefs here", got, realRefs)
		}

		// (e) the sharp one.
		if got := readRow(t, pool, host, "e-empty-severity"); got.Refs != realRefs {
			t.Errorf("(e) refs = %s, want %s unchanged", got.Refs, realRefs)
		} else if got.Severity != "NULL" {
			t.Errorf("(e) severity = %s, want NULL. This row was never damaged: its refs are a "+
				"real object and its empty severity is current and correct. A recovery keyed on "+
				"empty severity rather than on the damaged framework_refs overwrites it with a "+
				"stale value from history", got.Severity)
		}

		// AFTER: the rollup completes and writes a snapshot for the host.
		if _, err := Rollup(ctx, pool, time.Now()); err != nil {
			t.Fatalf("posture.Rollup still fails after the repair: %v", err)
		}
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM posture_snapshots WHERE host_id = $1 AND framework = ''`,
			host).Scan(&snapshots); err != nil {
			t.Fatalf("count snapshots after: %v", err)
		}
		if snapshots != 1 {
			t.Errorf("all-rules snapshots after repair = %d, want 1", snapshots)
		}
		// Attribution. Rows with a NULL severity SURVIVE the repair, and
		// the rollup now completes with them present, so the abort was
		// caused by the JSON-scalar framework_refs and not by the missing
		// severities that came with it. Without this the before-and-after
		// pair would be consistent with either cause.
		var nullSeverities int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM host_rule_state WHERE host_id = $1 AND severity IS NULL`,
			host).Scan(&nullSeverities); err != nil {
			t.Fatalf("count null severities: %v", err)
		}
		if nullSeverities == 0 {
			t.Error("no NULL-severity rows survived the repair, so this run cannot show that a " +
				"NULL severity is harmless to the rollup")
		}

		// Idempotent: applying twice changes nothing.
		before := map[string]rowState{}
		for _, r := range []string{"a-recovered", "b-ordered", "c-floored", "d-untouched", "e-empty-severity"} {
			before[r] = readRow(t, pool, host, r)
		}
		applyRepair(t, pool)
		for r, want := range before {
			if got := readRow(t, pool, host, r); got != want {
				t.Errorf("re-running the repair changed %s: %+v -> %+v. A migration has to be "+
					"safe to re-run", r, want, got)
			}
		}
	})
}
