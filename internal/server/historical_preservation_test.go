// @spec system-compliance-scoring
//
// What the formula change is not allowed to do to history.
//
// The migration adds nullable columns, so a legacy row is NOT byte-identical
// afterward and must not be asserted as such. What must not change is every
// pre-existing column value, and the bytes of anything already signed.
package server

import (
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// @ac AC-27
// AC-27: historical points keep their values, and a signed artifact keeps
// its bytes.
func TestHistorical_LegacyRowsAndSignedBytesArePreserved(t *testing.T) {
	t.Run("system-compliance-scoring/AC-27", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-27")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		_, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)

		// A row as it stood before the boundary: the counts and score it was
		// computed with, and none of the new provenance.
		pre := in.Map("pre_migration_snapshot")
		if _, err := pool.Exec(t.Context(), `
			INSERT INTO posture_snapshots
				(host_id, snapshot_date, passing, failing, skipped, error, total,
				 score_pct, has_critical_findings)
			VALUES ($1, current_date - 30, $2, $3, $4, $5, $2::int + $3::int + $4::int + $5::int,
			        $6, false)`,
			hostID, pre.Int("passing"), pre.Int("failing"), pre.Int("skipped"),
			pre.Int("error"), pre.Num("score_pct")); err != nil {
			t.Fatalf("seed legacy snapshot: %v", err)
		}
		pre.AllConsumed()

		want := exp.Map("legacy_column_values_unchanged")
		var (
			score                           float64
			passing, failing, skipped, errs int
			formulaVersion                  *int
			aggregation, corpusStatus       *string
			corpusVersion, corpusDigest     *string
		)
		if err := pool.QueryRow(t.Context(), `
			SELECT score_pct, passing, failing, skipped, error,
			       formula_version, aggregation_method, corpus_identity_status,
			       corpus_version, corpus_digest
			  FROM posture_snapshots
			 WHERE host_id = $1 AND snapshot_date = current_date - 30`, hostID).
			Scan(&score, &passing, &failing, &skipped, &errs, &formulaVersion,
				&aggregation, &corpusStatus, &corpusVersion, &corpusDigest); err != nil {
			t.Fatalf("read legacy snapshot: %v", err)
		}

		// The legacy score stays 53.3. It was computed under formula 1 and
		// recomputing it under formula 2 would silently rewrite what the
		// product told an operator on that day.
		if score != want.Num("score_pct") {
			t.Errorf("score_pct = %v, want %v; a historical point is a record of what was "+
				"reported, not a value to recompute", score, want.Num("score_pct"))
		}
		for _, tc := range []struct {
			name string
			got  int
		}{{"passing", passing}, {"failing", failing}, {"skipped", skipped}, {"error", errs}} {
			if got, w := tc.got, want.Int(tc.name); got != w {
				t.Errorf("%s = %d, want %d", tc.name, got, w)
			}
		}
		want.AllConsumed()

		// The new columns are NULL on a legacy row, not defaulted to 1 or to
		// today's values. A defaulted formula_version would claim the row was
		// computed under a formula that did not exist when it was written.
		nulls := exp.Map("new_columns_on_legacy_rows")
		nulls.IsNull("formula_version")
		nulls.IsNull("aggregation_method")
		nulls.IsNull("corpus_identity_status")
		nulls.IsNull("corpus_version")
		nulls.IsNull("corpus_digest")
		nulls.AllConsumed()
		for _, tc := range []struct {
			name string
			null bool
		}{
			{"formula_version", formulaVersion == nil},
			{"aggregation_method", aggregation == nil},
			{"corpus_identity_status", corpusStatus == nil},
			{"corpus_version", corpusVersion == nil},
			{"corpus_digest", corpusDigest == nil},
		} {
			if !tc.null {
				t.Errorf("%s is set on a legacy row; it must stay null, because any value "+
					"there asserts provenance nobody recorded", tc.name)
			}
		}

		// A row written after the boundary carries the version, which is what
		// makes the null above mean "before" rather than "never populated".
		if _, err := pool.Exec(t.Context(), `
			INSERT INTO posture_snapshots
				(host_id, snapshot_date, passing, failing, skipped, error, total,
				 score_pct, has_critical_findings, formula_version, aggregation_method)
			VALUES ($1, current_date, 8, 2, 0, 0, 10, 80.0, false, $2, 'none')`,
			hostID, exp.Int("post_boundary_formula_version")); err != nil {
			t.Fatalf("seed post-boundary snapshot: %v", err)
		}
		var postVersion *int
		if err := pool.QueryRow(t.Context(),
			`SELECT formula_version FROM posture_snapshots
			  WHERE host_id = $1 AND snapshot_date = current_date`, hostID).
			Scan(&postVersion); err != nil {
			t.Fatalf("read post-boundary snapshot: %v", err)
		}
		if postVersion == nil || *postVersion != exp.Int("post_boundary_formula_version") {
			t.Errorf("post-boundary formula_version = %v, want %d",
				postVersion, exp.Int("post_boundary_formula_version"))
		}

		// Signed bytes. The criterion pins one artifact's hash across the
		// boundary, so the two fixture values must be the same value.
		before := in.Str("pre_migration_signed_artifact_sha256")
		after := exp.Str("signed_artifact_sha256_after_migration")
		if before != after {
			t.Errorf("the fixture's signed artifact hashes to %q before and %q after; an "+
				"artifact whose bytes change is a different artifact and its signature no "+
				"longer verifies", before, after)
		}

		// And the mechanism behind that claim: a stored artifact's content
		// address still matches its own content.
		content := `{"kind":"executive","score_pct":53.3}`
		reportID := uuid.New()
		if _, err := pool.Exec(t.Context(), `
			INSERT INTO report_snapshots
				(id, title, kind, scope_label, scope, data_as_of, generated_by,
				 format, content, content_sha256)
			VALUES ($1, 'legacy', 'executive', 'fleet', '{}'::jsonb, now(), $2,
			        'json', $3::jsonb,
			        encode(sha256(convert_to($3::jsonb::text, 'UTF8')), 'hex'))`,
			reportID, firstSeededUserID(t, pool), content); err != nil {
			t.Fatalf("seed report snapshot: %v", err)
		}
		// Recomputed from the row's OWN content, which is what a rewrite would
		// break. Comparing the column to a constant computed here would only
		// prove this test can hash a string.
		var storedSum, recomputed string
		if err := pool.QueryRow(t.Context(), `
			SELECT content_sha256,
			       encode(sha256(convert_to(content::text, 'UTF8')), 'hex')
			  FROM report_snapshots WHERE id = $1`, reportID).
			Scan(&storedSum, &recomputed); err != nil {
			t.Fatalf("read report snapshot: %v", err)
		}
		if storedSum != recomputed {
			t.Errorf("stored artifact no longer matches its content address: the row carries "+
				"%s but its content hashes to %s, so the signature over those bytes no "+
				"longer verifies", storedSum, recomputed)
		}
		assertNoMigrationRewritesSignedContent(t)
		assertNoMigrationRewritesHistoricalScores(t)

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// assertNoMigrationRewritesSignedContent checks that the migrations adding
// the provenance columns issue no write against stored signed artifacts.
//
// This is what makes "the bytes are unchanged" structural rather than
// observed once. A migration that rewrote report content would break every
// signature already issued, and the break would only surface at verification
// time on a customer's machine.
func assertNoMigrationRewritesSignedContent(t *testing.T) {
	t.Helper()
	const dir = "../../internal/db/migrations"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	checked := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := os.ReadFile(dir + "/" + e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		lower := strings.ToLower(string(body))
		if !strings.Contains(lower, "report_snapshots") {
			continue
		}
		checked++
		// Only a write to CONTENT is forbidden. Migration 0042 legitimately
		// backfills content_sha256 from the content already stored, which
		// changes no bytes and breaks no signature, so a blanket ban on
		// UPDATE would fail on correct code and teach the next reader to add
		// an exemption.
		for _, stmt := range updatesTo(lower, "report_snapshots") {
			if strings.Contains(stmt, "set content ") || strings.Contains(stmt, "set content=") {
				t.Errorf("%s rewrites report_snapshots.content; the signature already issued "+
					"is over those exact bytes", e.Name())
			}
		}
		if strings.Contains(lower, "delete from report_snapshots") {
			t.Errorf("%s deletes stored artifacts; history that can be removed by a schema "+
				"change is not evidence", e.Name())
		}
	}
	if checked == 0 {
		t.Error("no migration mentions report_snapshots at all, so this scan proves nothing " +
			"about what migrations do to signed content")
	}
}

// updatesTo returns the text of each UPDATE statement against a table.
func updatesTo(sql, table string) []string {
	var out []string
	needle := "update " + table
	for i := 0; ; {
		j := strings.Index(sql[i:], needle)
		if j < 0 {
			return out
		}
		start := i + j
		end := strings.Index(sql[start:], ";")
		if end < 0 {
			out = append(out, sql[start:])
			return out
		}
		out = append(out, sql[start:start+end])
		i = start + end
	}
}

// assertNoMigrationRewritesHistoricalScores checks that no migration
// rewrites a historical score or its counts.
//
// A test that seeds its own legacy row cannot catch this. The row is created
// AFTER every migration has run, so a migration that recomputed history
// would leave that row untouched and the assertions above would pass. This
// was found by mutation: adding an UPDATE of score_pct to the provenance
// migration changed nothing the seeded-row test could see.
//
// No migration currently rewrites these columns. An earlier version of this
// guard carved out migration 0061 as a ratified score repair; 0061 repairs
// host_compliance_schedule.compliance_state and never touches a score, so
// the allowance covered nothing and would have quietly admitted a real
// rewrite later. Its own staleness check is what surfaced that.
func assertNoMigrationRewritesHistoricalScores(t *testing.T) {
	t.Helper()
	const dir = "../../internal/db/migrations"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	scoreCols := []string{"score_pct", "passing", "failing", "skipped", "error"}
	checked := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := os.ReadFile(dir + "/" + e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		lower := strings.ToLower(string(body))
		if !strings.Contains(lower, "posture_snapshots") {
			continue
		}
		checked++
		for _, stmt := range updatesTo(lower, "posture_snapshots") {
			for _, col := range scoreCols {
				if strings.Contains(stmt, "set "+col) || strings.Contains(stmt, ", "+col+" =") {
					t.Errorf("%s rewrites posture_snapshots.%s; a historical point records "+
						"what the product reported on that day, and recomputing it under a "+
						"formula that did not exist then rewrites the answer an operator "+
						"was given", e.Name(), col)
				}
			}
		}
	}
	if checked == 0 {
		t.Error("no migration mentions posture_snapshots, so this scan proves nothing")
	}
	// The scanner must be able to SEE an update it would allow. Without this,
	// a broken updatesTo would report nothing and read as clean.
	probe := "update posture_snapshots set score_pct = 1;"
	if len(updatesTo(probe, "posture_snapshots")) != 1 {
		t.Error("the statement scanner cannot see a plain UPDATE of posture_snapshots; its " +
			"clean result above means nothing")
	}
}
