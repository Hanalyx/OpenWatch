// @spec system-current-corpus
//
// AC traceability (DSN-gated):
//
//	AC-02  TestCorpus_SelectsTheMostRecentCompletedRun
//	AC-03  TestCorpus_OnlyACompletedRunCounts
//	AC-04  TestCorpus_RowsButNoCompletedRunReadEmpty
//	AC-09  TestCorpus_PostApplyWindowInvertsTheAnswer
//	AC-19  TestCorpus_BothKensaGatingBehaviorsStayHonest
//
// These exercise the corpus definition directly, against a real
// database. The only honest test of "which rows still count" is which
// rows Postgres returns. The per-surface tests check that each read site
// USES the definition; these check that the definition is right.
//
// Every read here goes through the single inCorpus helper, so a test
// cannot accidentally rewrite the predicate by hand and then pass
// against its own copy of it. When C-01's host_rule_state_current view
// lands, that helper's FROM clause is the one line that changes.

package corpus

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/scanruns"
)

func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	for _, stmt := range []string{
		"TRUNCATE TABLE host_rule_state CASCADE",
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
		id, "corpus-"+id.String(), "corpus-"+id.String()+"@example.com",
		"argon2id$dummy") // pragma: allowlist secret
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
		 VALUES ($1, $2, '192.0.2.30'::inet, $3)`,
		id, "corpus-"+id.String(), createdBy)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return id
}

// seedRun inserts one scan_runs row. queuedAt and finishedAt are set
// independently so a test can make the two orderings disagree on
// purpose. A zero finishedAt writes SQL NULL.
func seedRun(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, status string, queuedAt, finishedAt time.Time) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	var fin any
	if !finishedAt.IsZero() {
		fin = finishedAt
	}
	_, err := pool.Exec(context.Background(), `
		INSERT INTO scan_runs
			(id, host_id, trigger_source, status, queued_at, started_at, finished_at)
		VALUES ($1, $2, 'scheduled', $3, $4, $4, $5)`,
		id, hostID, status, queuedAt, fin)
	if err != nil {
		t.Fatalf("seed scan_run (%s): %v", status, err)
	}
	return id
}

// seedRuleState writes one host_rule_state row attributed to scanID.
func seedRuleState(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status string, scanID uuid.UUID) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO host_rule_state
			(host_id, rule_id, current_status, severity, last_checked_at,
			 check_count, last_scan_id, framework_refs, first_seen_at, last_changed_at)
		VALUES ($1, $2, $3, 'medium', now(), 1, $4, '{"cis":["1.1"]}'::jsonb, now(), now())`,
		hostID, ruleID, status, scanID)
	if err != nil {
		t.Fatalf("seed rule state %s: %v", ruleID, err)
	}
	return
}

// inCorpus returns the rule ids the current corpus keeps for one host,
// sorted. It reads the host_rule_state_current view, which is the single
// definition C-01 requires, and it is deliberately the ONLY way these
// tests reach it. A test that rewrote the condition by hand would pass
// against its own copy rather than against the thing that ships.
func inCorpus(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT rule_id FROM host_rule_state_current
			  WHERE host_id = $1
			  ORDER BY rule_id`, hostID)
	if err != nil {
		t.Fatalf("query current corpus: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan rule id: %v", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate corpus rows: %v", err)
	}
	return out
}

// allRuleIDs returns every host_rule_state rule id for a host, ignoring
// the predicate. Used to assert that scoping a READ never deleted a ROW.
func allRuleIDs(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT rule_id FROM host_rule_state WHERE host_id = $1 ORDER BY rule_id`, hostID)
	if err != nil {
		t.Fatalf("query all rule state: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan rule id: %v", err)
		}
		out = append(out, id)
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// @ac AC-19
// AC-19: Kensa's two gating behaviors both stay honest, and neither
// produces a pass for a rule Kensa did not check.
//
// Under v0.9.0 a gated rule VANISHES from scan output. Its row keeps the
// previous scan id, so it leaves the corpus silently. That is also the
// story's own shape: a rule the newest scan did not evaluate keeps its
// last verdict forever and must stop counting, while staying on disk,
// because the audit argument for scoping reads instead of pruning the
// table is precisely that nothing is destroyed.
//
// Under v0.10.0 the same rule is reported SKIPPED. It gets a row
// carrying the current scan id, so it stays in the corpus, visibly
// needing configuration rather than silently absent.
func TestCorpus_BothKensaGatingBehaviorsStayHonest(t *testing.T) {
	t.Run("system-current-corpus/AC-19", func(t *testing.T) {
		t.Run("v0.9.0 shape: a gated rule is absent and leaves the corpus", func(t *testing.T) {
			pool := freshPool(t)
			user := seedUser(t, pool)
			host := seedHost(t, pool, user)

			old := seedRun(t, pool, host, "completed", hoursAgo(3), hoursAgo(3))
			recent := seedRun(t, pool, host, "completed", hoursAgo(1), hoursAgo(1))

			// retired-rule was evaluated by the old scan and is absent
			// from the newer one, so nothing rewrote its row.
			seedRuleState(t, pool, host, "retired-rule", "fail", old)
			seedRuleState(t, pool, host, "kept-rule", "fail", recent)
			seedRuleState(t, pool, host, "passing-rule", "pass", recent)

			got := inCorpus(t, pool, host)
			want := []string{"kept-rule", "passing-rule"}
			if !equal(got, want) {
				t.Errorf("current corpus = %v, want %v. A rule the most recent completed scan "+
					"did not evaluate must not contribute to the current score", got, want)
			}

			// The row is still there. This is the assertion the whole
			// audit argument rests on, so it checks presence directly
			// rather than inferring it from a count.
			if all := allRuleIDs(t, pool, host); !equal(all, []string{"kept-rule", "passing-rule", "retired-rule"}) {
				t.Errorf("host_rule_state rows = %v, want all three including retired-rule. "+
					"Scoping the READ must never remove the record of what a host used to be "+
					"measured against", all)
			}
			var status string
			var retiredScan uuid.UUID
			if err := pool.QueryRow(context.Background(),
				`SELECT current_status, last_scan_id FROM host_rule_state
				  WHERE host_id = $1 AND rule_id = 'retired-rule'`, host).Scan(&status, &retiredScan); err != nil {
				t.Fatalf("read retired row: %v", err)
			}
			if status != "fail" || retiredScan != old {
				t.Errorf("retired row = (%s, %s), want (fail, %s); its historical verdict and "+
					"provenance must survive untouched", status, retiredScan, old)
			}
			// No pass is recorded for it anywhere. A gated rule that
			// quietly became a pass would be the worst outcome of the
			// three, so it is asserted rather than assumed.
			if status == "pass" {
				t.Error("the gated rule reads pass; Kensa never checked it")
			}
		})

		t.Run("v0.10.0 shape: a gated rule is skipped and stays in the corpus", func(t *testing.T) {
			pool := freshPool(t)
			user := seedUser(t, pool)
			host := seedHost(t, pool, user)

			run := seedRun(t, pool, host, "completed", hoursAgo(1), hoursAgo(1))
			seedRuleState(t, pool, host, "pass-rule", "pass", run)
			seedRuleState(t, pool, host, "skipped-rule", "skipped", run)
			seedRuleState(t, pool, host, "error-rule", "error", run)

			got := inCorpus(t, pool, host)
			want := []string{"error-rule", "pass-rule", "skipped-rule"}
			if !equal(got, want) {
				t.Errorf("current corpus = %v, want %v. Skipping is a verdict: a skipped rule "+
					"was evaluated by the current scan and is in the corpus by construction. "+
					"Whether a surface counts it toward a score is that surface's rule, not the "+
					"corpus definition's", got, want)
			}
			// Evaluated, and not passing. Those are different claims and
			// the failure worth catching is the second collapsing into
			// the first.
			var skippedStatus string
			if err := pool.QueryRow(context.Background(),
				`SELECT current_status FROM host_rule_state
				  WHERE host_id = $1 AND rule_id = 'skipped-rule'`, host).Scan(&skippedStatus); err != nil {
				t.Fatalf("read skipped row: %v", err)
			}
			if skippedStatus != "skipped" {
				t.Errorf("skipped rule reads %q, want skipped; it is counted as evaluated but "+
					"must never be counted as passing", skippedStatus)
			}
		})
	})
}

// @ac AC-03
// AC-03: only a COMPLETED run defines a corpus. For a host with one
// completed run plus a NEWER run in each of the queued, running and
// failed states, the corpus stays the completed run's rows in all three.
//
// The running case is the one worth having. Rows land while the run is
// still running, so they are present in the table and must be absent
// from the corpus until MarkCompleted lands. That is what stops scores
// flickering mid-scan, and marking the run completed then moves the
// corpus in one step.
func TestCorpus_OnlyACompletedRunCounts(t *testing.T) {
	t.Run("system-current-corpus/AC-03", func(t *testing.T) {
		for _, state := range []string{"queued", "running", "failed"} {
			t.Run("newer run is "+state, func(t *testing.T) {
				pool := freshPool(t)
				user := seedUser(t, pool)
				host := seedHost(t, pool, user)

				done := seedRun(t, pool, host, "completed", hoursAgo(3), hoursAgo(3))
				seedRuleState(t, pool, host, "settled-rule", "pass", done)

				var finished time.Time
				if state == "failed" {
					finished = hoursAgo(1)
				}
				newer := seedRun(t, pool, host, state, hoursAgo(1), finished)

				// The real mid-scan state: a running scan has already
				// written rows under its own id.
				if state == "running" {
					seedRuleState(t, pool, host, "in-flight-rule", "fail", newer)
				}

				got := inCorpus(t, pool, host)
				if !equal(got, []string{"settled-rule"}) {
					t.Errorf("with a newer %s run, current corpus = %v, want [settled-rule]. "+
						"A %s run has not completed, so it must not change any score", state, got, state)
				}

				if state != "running" {
					return
				}
				// Rows written by the running scan exist on disk and are
				// simply not current yet.
				if all := allRuleIDs(t, pool, host); !equal(all, []string{"in-flight-rule", "settled-rule"}) {
					t.Errorf("host_rule_state rows = %v, want both; the in-flight rows are "+
						"persisted, just not current", all)
				}
				// Completing the run moves the corpus in one step.
				if _, err := pool.Exec(context.Background(),
					`UPDATE scan_runs SET status = 'completed', finished_at = now() WHERE id = $1`,
					newer); err != nil {
					t.Fatalf("mark newer run completed: %v", err)
				}
				if got := inCorpus(t, pool, host); !equal(got, []string{"in-flight-rule"}) {
					t.Errorf("after marking the run completed, current corpus = %v, want "+
						"[in-flight-rule]; completing a run is what makes its rows current", got)
				}
			})
		}
	})
}

// @ac AC-04
// AC-04: a host with rows but NO completed run has an empty corpus, and
// the base table still holds every row.
//
// The second case is the one that matters. A host with no rows anywhere
// usually works by accident. A host that HAS rule state but no completed
// scan is where an empty numerator over an empty denominator silently
// renders as zero percent, and zero percent is a statement about the
// host that nothing measured.
func TestCorpus_RowsButNoCompletedRunReadEmpty(t *testing.T) {
	t.Run("system-current-corpus/AC-04", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)

		t.Run("rows whose last_scan_id names no scan_runs row at all", func(t *testing.T) {
			host := seedHost(t, pool, user)
			orphan, _ := uuid.NewV7()
			seedRuleState(t, pool, host, "some-rule", "fail", orphan)
			seedRuleState(t, pool, host, "other-rule", "pass", orphan)

			if got := inCorpus(t, pool, host); len(got) != 0 {
				t.Errorf("current corpus = %v, want empty. These rows name a scan that does not "+
					"exist, so nothing measured this host and it must read as no data", got)
			}
			if all := allRuleIDs(t, pool, host); !equal(all, []string{"other-rule", "some-rule"}) {
				t.Errorf("host_rule_state rows = %v, want both still present; only the read is "+
					"scoped and nothing is deleted", all)
			}
		})

		t.Run("never scanned at all", func(t *testing.T) {
			host := seedHost(t, pool, user)
			if got := inCorpus(t, pool, host); len(got) != 0 {
				t.Errorf("current corpus = %v, want empty", got)
			}
		})

		t.Run("rule state but only a failed run", func(t *testing.T) {
			host := seedHost(t, pool, user)
			failed := seedRun(t, pool, host, "failed", hoursAgo(1), hoursAgo(1))
			seedRuleState(t, pool, host, "some-rule", "fail", failed)
			seedRuleState(t, pool, host, "other-rule", "pass", failed)
			if got := inCorpus(t, pool, host); len(got) != 0 {
				t.Errorf("current corpus = %v, want empty. A failed run is not a completed scan, "+
					"so a scan that died halfway cannot shrink this host's score to whatever it "+
					"managed to write", got)
			}
			if all := allRuleIDs(t, pool, host); len(all) != 2 {
				t.Errorf("host_rule_state rows = %v, want both still present", all)
			}
		})
	})
}

// @ac AC-02
// AC-02: the corpus selects the most recent completed run, by ONE
// ordering rule.
//
// The first case is the plain one. The second is the case that separates
// the two candidate rules, and it is a disagreement rather than an edge
// case.
//
// scanruns.LatestCompletedForHost orders by finished_at DESC NULLS LAST
// and backs the compliance lens scan_context, the line telling an
// operator WHICH scan the score in front of them describes. The corpus
// decides which rows that score is computed over. Where the two
// disagree the consequence is not cosmetic: rows are written by
// whichever scan finished LAST, so last_scan_id follows finished_at, and
// a corpus ordered by queued_at matches nothing at all.
//
// The out-of-order shape is reachable with two workers. Dequeue orders
// by available_at then created_at, so the older scan job is claimed
// first, but each worker then takes a BLOCKING pg_advisory_xact_lock
// keyed on the host (internal/worker/scan_worker.go:324). Nothing makes
// the worker holding the older job win that race.
func TestCorpus_SelectsTheMostRecentCompletedRun(t *testing.T) {
	t.Run("system-current-corpus/AC-02", func(t *testing.T) {
		t.Run("two completed runs, later one wins", func(t *testing.T) {
			pool := freshPool(t)
			user := seedUser(t, pool)
			host := seedHost(t, pool, user)

			earlier := seedRun(t, pool, host, "completed", hoursAgo(4), hoursAgo(4))
			later := seedRun(t, pool, host, "completed", hoursAgo(2), hoursAgo(2))
			seedRuleState(t, pool, host, "old-rule", "fail", earlier)
			seedRuleState(t, pool, host, "new-rule", "pass", later)

			if got := inCorpus(t, pool, host); !equal(got, []string{"new-rule"}) {
				t.Errorf("current corpus = %v, want [new-rule]", got)
			}
		})

		t.Run("completed with no finished_at still counts", func(t *testing.T) {
			// finished_at is nullable and nothing enforces that a
			// completed row has one. LatestCompletedForHost says NULLS
			// LAST, so the corpus needs the same answer.
			pool := freshPool(t)
			user := seedUser(t, pool)
			host := seedHost(t, pool, user)

			run := seedRun(t, pool, host, "completed", hoursAgo(1), time.Time{})
			seedRuleState(t, pool, host, "only-rule", "pass", run)

			if got := inCorpus(t, pool, host); !equal(got, []string{"only-rule"}) {
				t.Errorf("current corpus = %v, want [only-rule]. A completed scan with no "+
					"recorded finished_at still scanned the host, so its rows must count", got)
			}
		})

		t.Run("queued first, finished last", testOutOfOrderRuns)
	})
}

// testOutOfOrderRuns asserts the corpus and the surface that names the
// scan pick the SAME run, in the case where the two candidate ordering
// rules disagree.
//
// Asserting both in one test is the point. Either rule alone looks
// self-consistent; only comparing them catches a drift that leaves the
// header naming a scan the score was not computed over.
func testOutOfOrderRuns(t *testing.T) {
	pool := freshPool(t)
	user := seedUser(t, pool)
	host := seedHost(t, pool, user)

	// Queued first, finished last: this is the scan that wrote the rows.
	wroteTheRows := seedRun(t, pool, host, "completed", hoursAgo(3), hoursAgo(1))
	// Queued second, finished first.
	queuedLater := seedRun(t, pool, host, "completed", hoursAgo(2), hoursAgo(2))

	seedRuleState(t, pool, host, "rule-a", "pass", wroteTheRows)
	seedRuleState(t, pool, host, "rule-b", "fail", wroteTheRows)

	// What the operator is told the score describes.
	shown, err := scanruns.LatestCompletedForHost(context.Background(), pool, host)
	if err != nil {
		t.Fatalf("LatestCompletedForHost: %v", err)
	}
	if shown.ID != wroteTheRows {
		t.Fatalf("fixture is not describing the case under test: the surface names scan %s, "+
			"but the rows were written by %s", shown.ID, wroteTheRows)
	}

	got := inCorpus(t, pool, host)
	if !equal(got, []string{"rule-a", "rule-b"}) {
		t.Errorf("current corpus = %v, want [rule-a rule-b].\n"+
			"The compliance lens names scan %s as the one the score describes, and that scan "+
			"wrote both rows. The predicate ordered by queued_at instead and selected %s, which "+
			"wrote nothing, so the corpus is empty and a freshly scanned host reads as no data.\n"+
			"The two definitions of \"most recent completed scan\" have to be the same definition.",
			got, wroteTheRows, queuedLater)
	}
}

func hoursAgo(n int) time.Time {
	return time.Now().Add(-time.Duration(n) * time.Hour).UTC()
}

// @ac AC-09
// AC-09: the post-Apply window inverts the latest-completed answer.
//
// The scan worker runs writer.Apply, then scanResults.Persist, then
// scanruns.MarkCompleted. Inside that window host_rule_state already
// carries the NEW scan id on every rule the scan evaluated, while the
// latest COMPLETED run is still the PREVIOUS one. So the rows the view
// matches there are exactly the rules the new scan did NOT evaluate.
//
// That is not a slightly stale answer. It is the retired set and nothing
// else, presented as the host's current state. Nothing in the shape of
// the code announces it, which is why this is pinned as an observation
// about the DATA rather than about any caller: it holds for the
// post-scan hook nobody has written yet, not only for drift.
//
// The two halves are asserted by rule id rather than by count. A count
// of two against a count of two would pass with the sets swapped, which
// is the exact failure this criterion exists to catch.
func TestCorpus_PostApplyWindowInvertsTheAnswer(t *testing.T) {
	t.Run("system-current-corpus/AC-09", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool)
		host := seedHost(t, pool, user)

		// The previous run, completed. It is still the latest completed
		// one throughout the window.
		previous := seedRun(t, pool, host, "completed", hoursAgo(3), hoursAgo(3))
		// The new run: started, rows written, NOT yet marked completed.
		current := seedRun(t, pool, host, "running", hoursAgo(1), time.Time{})

		// Rules the new scan evaluated now carry its id (writer.Apply
		// has already run for them).
		seedRuleState(t, pool, host, "evaluated-a", "pass", current)
		seedRuleState(t, pool, host, "evaluated-b", "fail", current)
		// Rules it did not evaluate still carry the previous run's id.
		seedRuleState(t, pool, host, "not-evaluated", "fail", previous)

		latest, err := scanruns.LatestCompletedForHost(ctx, pool, host)
		if err != nil {
			t.Fatalf("LatestCompletedForHost: %v", err)
		}
		if latest.ID != previous {
			t.Fatalf("fixture is not in the window under test: latest completed is %s, want the "+
				"previous run %s. The new run must not be completed yet", latest.ID, previous)
		}

		// The view returns EXACTLY the rules the new scan did not evaluate.
		if got := inCorpus(t, pool, host); !equal(got, []string{"not-evaluated"}) {
			t.Errorf("in the post-Apply window the view returns %v, want [not-evaluated].\n"+
				"This is the inversion C-04 exists to warn about: between writer.Apply and "+
				"MarkCompleted the view resolves to the PREVIOUS run, so it matches only the "+
				"rules the new scan retired and reports them as the host's current state.", got)
		}
		// The named-scan form returns exactly the rules it did.
		if got := atScan(t, pool, host, current); !equal(got, []string{"evaluated-a", "evaluated-b"}) {
			t.Errorf("the named-scan form returns %v, want [evaluated-a evaluated-b]. A read in "+
				"this window has to name its scan; that is the only form with the right answer here", got)
		}

		// Marking the run completed swaps the two, in one step.
		if _, err := pool.Exec(ctx,
			`UPDATE scan_runs SET status = 'completed', finished_at = now() WHERE id = $1`,
			current); err != nil {
			t.Fatalf("mark current run completed: %v", err)
		}
		if got := inCorpus(t, pool, host); !equal(got, []string{"evaluated-a", "evaluated-b"}) {
			t.Errorf("after MarkCompleted the view returns %v, want [evaluated-a evaluated-b]; "+
				"completing the run is what makes its rows current", got)
		}
		if got := atScan(t, pool, host, previous); !equal(got, []string{"not-evaluated"}) {
			t.Errorf("the previous scan's rows are %v, want [not-evaluated]; the two sets swap "+
				"and neither is destroyed", got)
		}
	})
}

// atScan returns the rule ids scoped to one NAMED scan, through the
// shared AtScanSQL helper. Like inCorpus, it is the only route these
// tests take to that form, so a test cannot pass against its own
// hand-written copy of the condition.
func atScan(t *testing.T, pool *pgxpool.Pool, hostID, scanID uuid.UUID) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT rule_id FROM host_rule_state
		  WHERE host_id = $1 AND `+AtScanSQL("host_rule_state", "$2")+`
		  ORDER BY rule_id`, hostID, scanID)
	if err != nil {
		t.Fatalf("query at-scan rows: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan rule id: %v", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate at-scan rows: %v", err)
	}
	return out
}
