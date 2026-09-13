// @spec system-compliance-scoring
//
// What a current score is allowed to read.
//
// host_rule_state is only ever upserted and nothing prunes it, so a rule
// that left the corpus keeps its last verdict forever. A failing row that
// no scan re-evaluates and no remediation can reach still votes, which is
// why a current score reads the view and never the bare table.
package server

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/db/corpustest"
	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// seedRuleStateForRun writes rule states bound to a SPECIFIC run, rather
// than to whichever run corpustest calls current.
func seedRuleStateForRun(t *testing.T, pool *pgxpool.Pool, hostID, runID uuid.UUID,
	status string, n int, at time.Time) {
	t.Helper()
	for i := 0; i < n; i++ {
		_, err := pool.Exec(t.Context(), `
			INSERT INTO host_rule_state
				(host_id, rule_id, current_status, severity, last_checked_at,
				 check_count, last_scan_id, framework_refs,
				 first_seen_at, last_changed_at)
			VALUES ($1, $2, $3, 'medium', $4, 1, $5, '{}'::jsonb, $4, $4)`,
			hostID, status+"-"+uuid.NewString(), status, at, runID)
		if err != nil {
			t.Fatalf("seed rule state: %v", err)
		}
	}
}

// @ac AC-28
// AC-28: a current score uses only the latest completed scan corpus, so rule
// state left behind by a superseded scan cannot vote.
func TestCurrentCorpus_SupersededScanRowsDoNotVote(t *testing.T) {
	t.Run("system-compliance-scoring/AC-28", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-28")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		now := time.Now().UTC().Truncate(time.Second)

		// The superseded run finished FIRST. Its rows stay in the table
		// forever; nothing prunes them and no rescan clears them.
		old := in.Map("superseded_scan_rows")
		oldRun := corpustest.SeedRun(t, pool, hostID, "completed",
			now.Add(-4*time.Hour), now.Add(-3*time.Hour))
		seedRuleStateForRun(t, pool, hostID, oldRun, "fail", old.Int("fail"), now.Add(-3*time.Hour))
		old.AllConsumed()

		latest := in.Map("latest_scan_counts")
		newRun := corpustest.SeedRun(t, pool, hostID, "completed",
			now.Add(-2*time.Hour), now.Add(-time.Hour))
		seedRuleStateForRun(t, pool, hostID, newRun, "pass", latest.Int("pass"), now)
		seedRuleStateForRun(t, pool, hostID, newRun, "fail", latest.Int("fail"), now)
		latest.AllConsumed()

		s := getLensSummary(t, url, hostID, "").Summary
		if s.ScorePct == nil {
			t.Fatal("score_pct is null although the latest scan produced ten verdicts")
		}
		if *s.ScorePct != exp.Num("score_pct") {
			t.Errorf("score_pct = %v, want %v", *s.ScorePct, exp.Num("score_pct"))
		}
		// The named wrong answer: eight passes over fifty rows, where forty of
		// them belong to a scan this host has already replaced. A rule that was
		// failing when it left the corpus would hold the host down forever.
		if *s.ScorePct == exp.Num("forbidden_score_pct") {
			t.Errorf("score_pct = %v, which counts the superseded scan's rows; they are "+
				"unreachable by every mechanism that could change them and still vote",
				exp.Num("forbidden_score_pct"))
		}
		// The rows are still there. This criterion is about what the score
		// READS, not about deleting history, so a test that passed because the
		// old rows were gone would be testing something else.
		var remaining int
		if err := pool.QueryRow(t.Context(),
			`SELECT count(*)::int FROM host_rule_state WHERE last_scan_id = $1`,
			oldRun).Scan(&remaining); err != nil {
			t.Fatalf("count superseded rows: %v", err)
		}
		if remaining != in.Map("superseded_scan_rows").Int("fail") {
			t.Errorf("superseded rows in the table = %d; they must still exist and simply "+
				"not be read", remaining)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-29
// AC-29: a scan-level failure fabricates nothing. It writes no rule outcome
// rows and leaves the stored score untouched.
//
// Design invariant 7 requires preservation only. It previously also required
// the score to be marked stale, which OpenWatch has no observable for, so
// asserting staleness here would assert something the product cannot show.
func TestScanFailure_PreservesTheStoredScore(t *testing.T) {
	t.Run("system-compliance-scoring/AC-29", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-29")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		now := time.Now().UTC().Truncate(time.Second)

		// A good scan first, giving the stored score the fixture names.
		goodRun := corpustest.SeedRun(t, pool, hostID, "completed",
			now.Add(-3*time.Hour), now.Add(-2*time.Hour))
		seedRuleStateForRun(t, pool, hostID, goodRun, "pass", 8, now.Add(-2*time.Hour))
		seedRuleStateForRun(t, pool, hostID, goodRun, "fail", 2, now.Add(-2*time.Hour))

		before := getLensSummary(t, url, hostID, "").Summary
		if before.ScorePct == nil || *before.ScorePct != in.Num("pre_failure_stored_score_pct") {
			t.Fatalf("stored score = %v, want %v before the failure",
				before.ScorePct, in.Num("pre_failure_stored_score_pct"))
		}

		// Then a run that aborts before evaluating any rule. It writes no
		// outcome rows, which is the whole of what "fabricates nothing" means.
		if in.Str("scan_outcome") != "aborted_before_rule_evaluation" {
			t.Fatalf("fixture outcome %q; this test drives the pre-evaluation abort",
				in.Str("scan_outcome"))
		}
		failedRun := corpustest.SeedRun(t, pool, hostID, "failed",
			now.Add(-time.Hour), now.Add(-30*time.Minute))

		var written int
		if err := pool.QueryRow(t.Context(),
			`SELECT count(*)::int FROM host_rule_state WHERE last_scan_id = $1`,
			failedRun).Scan(&written); err != nil {
			t.Fatalf("count rows for the failed run: %v", err)
		}
		if written != exp.Int("rule_outcome_rows_written") {
			t.Errorf("the failed run wrote %d rule outcome rows, want %d; a scan that "+
				"evaluated nothing has nothing to record",
				written, exp.Int("rule_outcome_rows_written"))
		}

		after := getLensSummary(t, url, hostID, "").Summary
		if after.ScorePct == nil {
			t.Fatal("the score became null after a failed scan; the last good measurement " +
				"is still the last good measurement, and dropping it turns an infrastructure " +
				"failure into a compliance verdict")
		}
		if *after.ScorePct != exp.Num("stored_score_pct") {
			t.Errorf("score_pct = %v after the failure, want %v",
				*after.ScorePct, exp.Num("stored_score_pct"))
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}
