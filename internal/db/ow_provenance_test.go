// @spec system-posture-snapshots
//
// Migration 0062 reserves nullable storage for the compliance-scoring redesign.
// These tests prove the two things a schema migration is easiest to get wrong:
// that it rewrote nothing, and that the shapes it forbids are actually
// unreachable rather than merely documented.
package db_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/specfixture"
)

func postureCriteria(t *testing.T) map[string]specfixture.Criterion {
	t.Helper()
	return specfixture.Load(t, "../../specs/system/posture-snapshots.spec.yaml", "system-posture-snapshots")
}

// insertSnapshot writes one row, returning the error so a test can assert that
// the schema refused it.
func insertSnapshot(ctx context.Context, pool *pgxpool.Pool, hostID uuid.UUID, day time.Time,
	score *float64, formula *int, status, version, digest *string) error {
	return insertSnapshotFull(ctx, pool, hostID, day, snapshotRow{
		score: score, formula: formula,
		aggregation: defaultAggregation(formula), engine: defaultEngine(formula),
		status: status, version: version, digest: digest,
	})
}

// snapshotRow is one row's worth of values, so a test seeds the counts and
// metadata its fixture names rather than zeros.
type snapshotRow struct {
	passing, failing, skipped, errored int
	score                              *float64
	formula                            *int
	aggregation, engine                *string
	status, version, digest            *string
}

// defaultAggregation and defaultEngine satisfy the all-or-nothing metadata rule
// for tests that are about CORPUS shape. A test about the metadata itself sets
// them explicitly.
func defaultAggregation(formula *int) *string {
	if formula == nil {
		return nil
	}
	return strp("none")
}

func defaultEngine(formula *int) *string {
	if formula == nil {
		return nil
	}
	return strp("v0.9.0")
}

func insertSnapshotFull(ctx context.Context, pool *pgxpool.Pool, hostID uuid.UUID, day time.Time, r snapshotRow) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO posture_snapshots
			(host_id, snapshot_date, passing, failing, skipped, error, total,
			 score_pct, formula_version, aggregation_method, engine_version,
			 corpus_identity_status, corpus_version, corpus_digest)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		hostID, day, r.passing, r.failing, r.skipped, r.errored,
		r.passing+r.failing+r.skipped+r.errored,
		r.score, r.formula, r.aggregation, r.engine, r.status, r.version, r.digest)
	return err
}

func strp(s string) *string { return &s }
func intp(i int) *int       { return &i }

// @ac AC-04
// AC-04: a pre-migration snapshot keeps its stored score and carries NULL for
// every new column.
func TestProvenance_LegacyRowUnchanged(t *testing.T) {
	t.Run("system-posture-snapshots/AC-04", func(t *testing.T) {
		ctx := context.Background()
		pool := dbtest.Pool(t)
		ac := specfixture.Get(t, postureCriteria(t), "AC-04")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		legacy := in.Map("legacy_row")
		host := seedOW024User(t, ctx, pool)
		hostID := seedProvenanceHost(t, ctx, pool, host)

		// Roll 0062 back so the row is seeded under the PREVIOUS schema, then
		// roll it forward. Inserting a row into the already-migrated schema and
		// checking the new columns are NULL proves nothing: a backfill UPDATE
		// inside 0062 would survive that, because it ran before the row existed.
		// The transition is the thing under test.
		applyMigrationSection(t, ctx, pool, "-- +goose Down", "")
		score := legacy.Num("score_pct")
		if _, err := pool.Exec(ctx, `
			INSERT INTO posture_snapshots
				(host_id, snapshot_date, passing, failing, skipped, error, total, score_pct)
			VALUES ($1, CURRENT_DATE, $2, $3, $4, $5, $6, $7)`,
			hostID, legacy.Int("passing"), legacy.Int("failing"), legacy.Int("skipped"),
			legacy.Int("error"), legacy.Int("passing")+legacy.Int("failing")+legacy.Int("skipped")+legacy.Int("error"),
			score); err != nil {
			t.Fatalf("seed legacy row: %v", err)
		}
		legacy.AllConsumed()

		applyMigrationSection(t, ctx, pool, "-- +goose Up", "-- +goose Down")

		var gotScore *float64
		var formula *int
		var aggregation, engine, status, version, digest *string
		if err := pool.QueryRow(ctx, `
			SELECT score_pct, formula_version, aggregation_method, engine_version,
			       corpus_identity_status, corpus_version, corpus_digest
			  FROM posture_snapshots WHERE host_id = $1`, hostID).
			Scan(&gotScore, &formula, &aggregation, &engine, &status, &version, &digest); err != nil {
			t.Fatalf("read back: %v", err)
		}

		if gotScore == nil || float64(int(*gotScore*10+0.5))/10 != exp.Num("score_pct") {
			t.Errorf("score_pct = %v, want %v unchanged", gotScore, exp.Num("score_pct"))
		}
		exp.IsNull("formula_version")
		if formula != nil {
			t.Errorf("formula_version = %v, want NULL; history is not relabelled", *formula)
		}
		for _, c := range []struct {
			key string
			got *string
		}{
			{"aggregation_method", aggregation}, {"engine_version", engine},
			{"corpus_identity_status", status}, {"corpus_version", version}, {"corpus_digest", digest},
		} {
			exp.IsNull(c.key)
			if c.got != nil {
				t.Errorf("%s = %q, want NULL; the migration backfills nothing", c.key, *c.got)
			}
		}
		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-05
// AC-05: a new snapshot tells an absent score from a genuine zero.
func TestProvenance_AbsentScoreVersusGenuineZero(t *testing.T) {
	t.Run("system-posture-snapshots/AC-05", func(t *testing.T) {
		ctx := context.Background()
		pool := dbtest.Pool(t)
		ac := specfixture.Get(t, postureCriteria(t), "AC-05")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		// Each fixture's counts and metadata are seeded, not zeroed. Writing
		// zeros while reading "failing: 5" from the spec would store a row that
		// contradicts the fixture it claims to test.
		readRow := func(f *specfixture.Fields) snapshotRow {
			r := snapshotRow{
				passing: f.Int("passing"), failing: f.Int("failing"), skipped: f.Int("skipped"),
				formula:     intp(f.Int("formula_version")),
				aggregation: strp(f.Str("aggregation_method")),
				engine:      strp(f.Str("engine_version")),
			}
			if f.IsNullable("score_pct") {
				f.IsNull("score_pct")
			} else {
				r.score = f64(f.Num("score_pct"))
			}
			f.AllConsumed()
			return r
		}

		user := seedOW024User(t, ctx, pool)
		absentHost := seedProvenanceHost(t, ctx, pool, user)
		zeroHost := seedProvenanceHost(t, ctx, pool, user)
		day := time.Now().UTC().Truncate(24 * time.Hour)

		absent := readRow(in.Map("absent"))
		zero := readRow(in.Map("genuine_zero"))

		if err := insertSnapshotFull(ctx, pool, absentHost, day, absent); err != nil {
			t.Fatalf("absent score rejected: %v", err)
		}
		if err := insertSnapshotFull(ctx, pool, zeroHost, day, zero); err != nil {
			t.Fatalf("genuine zero rejected: %v", err)
		}
		if !exp.Bool("both_rows_stored") {
			t.Fatal("fixture must claim both rows are stored")
		}

		assertStored := func(h uuid.UUID, want *specfixture.Fields, label string) {
			var score *float64
			var formula *int
			var passing, failing, skipped int
			if err := pool.QueryRow(ctx, `
				SELECT score_pct, formula_version, passing, failing, skipped
				  FROM posture_snapshots WHERE host_id = $1`, h).
				Scan(&score, &formula, &passing, &failing, &skipped); err != nil {
				t.Fatalf("%s read: %v", label, err)
			}
			if want.IsNullable("score_pct") {
				want.IsNull("score_pct")
				if score != nil {
					t.Errorf("%s score stored as %v, want NULL", label, *score)
				}
			} else if score == nil || float64(*score) != want.Num("score_pct") {
				t.Errorf("%s score stored as %v, want %v", label, score, want.Num("score_pct"))
			}
			if got, w := passing, want.Int("passing"); got != w {
				t.Errorf("%s passing = %d, want %d", label, got, w)
			}
			if got, w := failing, want.Int("failing"); got != w {
				t.Errorf("%s failing = %d, want %d; a row claiming failures must store them", label, got, w)
			}
			if got, w := skipped, want.Int("skipped"); got != w {
				t.Errorf("%s skipped = %d, want %d", label, got, w)
			}
			if formula == nil || *formula != want.Int("formula_version") {
				t.Errorf("%s formula_version = %v, want %d", label, formula, want.Int("formula_version"))
			}
			want.AllConsumed()
		}
		assertStored(absentHost, exp.Map("absent_stored"), "absent")
		assertStored(zeroHost, exp.Map("genuine_zero_stored"), "genuine-zero")

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-06
// AC-06: a curated corpus has a digest and no version; a version alone cannot
// exist.
func TestProvenance_CuratedCorpusAndVersionWithoutDigest(t *testing.T) {
	t.Run("system-posture-snapshots/AC-06", func(t *testing.T) {
		ctx := context.Background()
		pool := dbtest.Pool(t)
		ac := specfixture.Get(t, postureCriteria(t), "AC-06")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		user := seedOW024User(t, ctx, pool)
		day := time.Now().UTC().Truncate(24 * time.Hour)

		cur := in.Map("curated")
		curStatus := cur.Str("status")
		cur.IsNull("corpus_version")
		curDigest := cur.Str("corpus_digest")
		cur.AllConsumed()

		h1 := seedProvenanceHost(t, ctx, pool, user)
		err := insertSnapshot(ctx, pool, h1, day, nil, intp(2), strp(curStatus), nil, strp(curDigest))
		if (err == nil) != exp.Bool("curated_accepted") {
			t.Errorf("curated corpus: err = %v, want accepted = %v", err, exp.Bool("curated_accepted"))
		}

		bad := in.Map("version_without_digest")
		badStatus := bad.Str("status")
		badVersion := bad.Str("corpus_version")
		bad.IsNull("corpus_digest")
		bad.AllConsumed()

		h2 := seedProvenanceHost(t, ctx, pool, user)
		err = insertSnapshot(ctx, pool, h2, day, nil, intp(2), strp(badStatus), strp(badVersion), nil)
		if (err != nil) != exp.Bool("version_without_digest_rejected") {
			t.Errorf("version without digest: err = %v, want rejected = %v", err, exp.Bool("version_without_digest_rejected"))
		}

		// With status identified the row above is rejected by TWO rules, so it
		// cannot tell them apart. This one leaves the status null, so only the
		// version-needs-a-digest rule can reject it. Found by mutation: dropping
		// that rule left the first fixture still passing.
		bare := in.Map("version_without_digest_no_status")
		bare.IsNull("status")
		bareVersion := bare.Str("corpus_version")
		bare.IsNull("corpus_digest")
		bare.AllConsumed()

		h3 := seedProvenanceHost(t, ctx, pool, user)
		err = insertSnapshot(ctx, pool, h3, day, nil, intp(2), nil, strp(bareVersion), nil)
		if (err != nil) != exp.Bool("version_without_digest_no_status_rejected") {
			t.Errorf("version without digest or status: err = %v, want rejected = %v",
				err, exp.Bool("version_without_digest_no_status_rejected"))
		}
		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-07
// AC-07: an empty string is never a corpus value.
func TestProvenance_EmptyStringsRejected(t *testing.T) {
	t.Run("system-posture-snapshots/AC-07", func(t *testing.T) {
		ctx := context.Background()
		pool := dbtest.Pool(t)
		ac := specfixture.Get(t, postureCriteria(t), "AC-07")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		user := seedOW024User(t, ctx, pool)
		day := time.Now().UTC().Truncate(24 * time.Hour)

		ed := in.Map("empty_digest")
		edStatus, edDigest := ed.Str("status"), ed.Str("corpus_digest")
		ed.AllConsumed()
		h1 := seedProvenanceHost(t, ctx, pool, user)
		err := insertSnapshot(ctx, pool, h1, day, nil, intp(2), strp(edStatus), nil, strp(edDigest))
		if (err != nil) != exp.Bool("empty_digest_rejected") {
			t.Errorf("empty digest: err = %v, want rejected = %v", err, exp.Bool("empty_digest_rejected"))
		}

		ev := in.Map("empty_version")
		evStatus, evVersion, evDigest := ev.Str("status"), ev.Str("corpus_version"), ev.Str("corpus_digest")
		ev.AllConsumed()
		h2 := seedProvenanceHost(t, ctx, pool, user)
		err = insertSnapshot(ctx, pool, h2, day, nil, intp(2), strp(evStatus), strp(evVersion), strp(evDigest))
		if (err != nil) != exp.Bool("empty_version_rejected") {
			t.Errorf("empty version: err = %v, want rejected = %v", err, exp.Bool("empty_version_rejected"))
		}
		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-08
// AC-08: a per-host row cannot carry an aggregate corpus status.
func TestProvenance_AggregateStatusRejectedOnPerHostRow(t *testing.T) {
	t.Run("system-posture-snapshots/AC-08", func(t *testing.T) {
		ctx := context.Background()
		pool := dbtest.Pool(t)
		ac := specfixture.Get(t, postureCriteria(t), "AC-08")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		user := seedOW024User(t, ctx, pool)
		day := time.Now().UTC().Truncate(24 * time.Hour)

		tables := in.List("tables")
		if !exp.Bool("enforced_on_both_tables") || len(tables) != 2 {
			t.Fatal("AC-08 must cover both tables; removing one from the constraint loop would otherwise survive")
		}
		for _, tbl := range tables {
			table := tbl.(string)
			for _, raw := range in.List("rejected_statuses") {
				st := raw.(string)
				err := insertCorpusRow(ctx, pool, table, seedProvenanceHost(t, ctx, pool, user), day, strp(st), nil, strp("sha256-x"))
				if (err != nil) != exp.Bool("aggregate_statuses_rejected") {
					t.Errorf("%s status %q: err = %v, want rejected", table, st, err)
				}
			}
			for _, raw := range in.List("accepted_statuses") {
				st := raw.(string)
				var digest *string
				if st == "identified" {
					digest = strp("sha256-x")
				}
				err := insertCorpusRow(ctx, pool, table, seedProvenanceHost(t, ctx, pool, user), day, strp(st), nil, digest)
				if (err == nil) != exp.Bool("per_host_statuses_accepted") {
					t.Errorf("%s status %q: err = %v, want accepted", table, st, err)
				}
			}
		}
		in.AllConsumed()
		exp.AllConsumed()
	})
}

func seedProvenanceHost(t *testing.T, ctx context.Context, pool *pgxpool.Pool, createdBy uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO hosts (id, hostname, ip_address, created_by)
		VALUES ($1, $2, '127.0.0.1'::inet, $3)`, id, "prov-"+id.String(), createdBy); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return id
}

// applyMigrationSection runs one section of migration 0062 against the pool.
//
// It reads the shipped file rather than restating any statement, so a test
// cannot pass against a migration that differs from the one that ships. Passing
// an empty end marker reads to the end of the file.
func applyMigrationSection(t *testing.T, ctx context.Context, pool *pgxpool.Pool, start, end string) {
	t.Helper()
	for _, stmt := range migrationStatements(t, start, end) {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("apply %s statement: %v\n%s", start, err, stmt)
		}
	}
}

// migrationStatements returns one section's statements without running them, so
// a test can execute them inside its own transaction and inspect the failure.
func migrationStatements(t *testing.T, start, end string) []string {
	t.Helper()
	raw, err := os.ReadFile("migrations/0062_score_and_corpus_provenance.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	body := string(raw)
	i := strings.Index(body, start)
	if i < 0 {
		t.Fatalf("migration has no %q section", start)
	}
	section := body[i+len(start):]
	if end != "" {
		if j := strings.Index(section, end); j >= 0 {
			section = section[:j]
		}
	}
	return splitGooseStatements(section)
}

// splitGooseStatements yields executable statements, keeping StatementBegin
// blocks whole because they contain their own semicolons.
func splitGooseStatements(section string) []string {
	var out []string
	for {
		b := strings.Index(section, "-- +goose StatementBegin")
		if b < 0 {
			break
		}
		e := strings.Index(section, "-- +goose StatementEnd")
		if e < 0 {
			break
		}
		for _, s := range splitPlain(section[:b]) {
			out = append(out, s)
		}
		out = append(out, strings.TrimSpace(section[b+len("-- +goose StatementBegin"):e]))
		section = section[e+len("-- +goose StatementEnd"):]
	}
	return append(out, splitPlain(section)...)
}

// splitPlain strips comments, then splits on semicolons that are not inside a
// quoted string.
//
// Both halves were learned the hard way against this migration, and both looked
// right until they ran. Splitting before stripping turned the semicolon in the
// header prose ("no rule produced a verdict; 0 means ...") into a statement
// boundary. Splitting naively then broke the COMMENT ON statements, whose text
// also contains semicolons inside quotes. A statement separator is only a
// separator outside a string.
func splitPlain(s string) []string {
	src := stripSQLComments(s)
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '\'':
			// '' inside a string is an escaped quote, not a close.
			if inQuote && i+1 < len(src) && src[i+1] == '\'' {
				cur.WriteByte(c)
				i++
				cur.WriteByte(src[i])
				continue
			}
			inQuote = !inQuote
			cur.WriteByte(c)
		case c == ';' && !inQuote:
			if t := strings.TrimSpace(cur.String()); t != "" {
				out = append(out, t+";")
			}
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if t := strings.TrimSpace(cur.String()); t != "" {
		out = append(out, t+";")
	}
	return out
}

// @ac AC-09
// AC-09: a null corpus status forbids both corpus values, on both tables.
func TestProvenance_NullStatusForbidsValues(t *testing.T) {
	t.Run("system-posture-snapshots/AC-09", func(t *testing.T) {
		ctx := context.Background()
		pool := dbtest.Pool(t)
		ac := specfixture.Get(t, postureCriteria(t), "AC-09")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		user := seedOW024User(t, ctx, pool)
		day := time.Now().UTC().Truncate(24 * time.Hour)

		tables := in.List("tables")
		if !exp.Bool("enforced_on_both_tables") || len(tables) != 2 {
			t.Fatal("AC-09 must cover both tables")
		}

		wd := in.Map("null_status_with_digest")
		wd.IsNull("status")
		wdDigest := wd.Str("corpus_digest")
		wd.AllConsumed()

		wv := in.Map("null_status_with_version")
		wv.IsNull("status")
		wvVersion, wvDigest := wv.Str("corpus_version"), wv.Str("corpus_digest")
		wv.AllConsumed()

		for _, tbl := range tables {
			table := tbl.(string)
			err := insertCorpusRow(ctx, pool, table, seedProvenanceHost(t, ctx, pool, user), day, nil, nil, strp(wdDigest))
			if (err != nil) != exp.Bool("null_status_with_digest_rejected") {
				t.Errorf("%s null status with a digest: err = %v, want rejected", table, err)
			}
			err = insertCorpusRow(ctx, pool, table, seedProvenanceHost(t, ctx, pool, user), day, nil, strp(wvVersion), strp(wvDigest))
			if (err != nil) != exp.Bool("null_status_with_version_rejected") {
				t.Errorf("%s null status with a version: err = %v, want rejected", table, err)
			}
		}
		in.AllConsumed()
		exp.AllConsumed()
	})
}

// insertCorpusRow writes a corpus-provenance row into either table, so a
// constraint test covers both rather than assuming the loop that created them
// stayed intact.
func insertCorpusRow(ctx context.Context, pool *pgxpool.Pool, table string, hostID uuid.UUID,
	day time.Time, status, version, digest *string) error {
	switch table {
	case "posture_snapshots":
		return insertSnapshot(ctx, pool, hostID, day, nil, intp(2), status, version, digest)
	case "scan_runs":
		_, err := pool.Exec(ctx, `
			INSERT INTO scan_runs
				(id, host_id, trigger_source, status, queued_at,
				 corpus_identity_status, corpus_version, corpus_digest)
			VALUES ($1, $2, 'scheduled', 'completed', now(), $3, $4, $5)`,
			uuid.New(), hostID, status, version, digest)
		return err
	default:
		return fmt.Errorf("unknown table %q", table)
	}
}

// @ac AC-10
// AC-10: the downgrade refuses while a snapshot holds no score.
//
// The whole Down section runs, in order, inside one transaction. Running only
// the guard would prove nothing: the guard has to survive the column drops that
// precede it, and the abort has to leave the schema intact, which is true only
// because the section is transactional.
func TestProvenance_DowngradeRefusesWithNullScore(t *testing.T) {
	t.Run("system-posture-snapshots/AC-10", func(t *testing.T) {
		ctx := context.Background()
		pool := dbtest.Pool(t)
		ac := specfixture.Get(t, postureCriteria(t), "AC-10")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		if !in.Bool("seed_null_score") {
			t.Fatal("fixture must seed a null score; there is nothing to refuse otherwise")
		}
		user := seedOW024User(t, ctx, pool)
		host := seedProvenanceHost(t, ctx, pool, user)
		day := time.Now().UTC().Truncate(24 * time.Hour)
		if err := insertSnapshotFull(ctx, pool, host, day, snapshotRow{
			skipped: 7, formula: intp(2),
			aggregation: strp("none"), engine: strp("v0.9.0"),
		}); err != nil {
			t.Fatalf("seed null score: %v", err)
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()

		var refusal error
		for _, stmt := range migrationStatements(t, "-- +goose Down", "") {
			if _, err := tx.Exec(ctx, stmt); err != nil {
				refusal = err
				break
			}
		}
		if refusal == nil {
			t.Error("downgrade completed; it must refuse rather than write the null score to 0, " +
				"which is the fabricated verdict bugs/OW-023 and OW-024 are about")
		} else if !strings.Contains(refusal.Error(), "downgrade refused") {
			t.Errorf("downgrade failed with %v, want the explicit refusal", refusal)
		}
		if !exp.Bool("downgrade_rejected") {
			t.Fatal("fixture must claim the downgrade is rejected")
		}
		_ = tx.Rollback(ctx)

		// The abort must not have half-rolled-back. Both halves are asserted
		// because a non-transactional Down would drop the columns and restore
		// NOT NULL on a table that no longer holds the row it refused over.
		if !exp.Bool("score_pct_still_nullable") {
			t.Fatal("fixture must claim score_pct stays nullable")
		}
		var nullable string
		if err := pool.QueryRow(ctx, `
			SELECT is_nullable FROM information_schema.columns
			 WHERE table_name = 'posture_snapshots' AND column_name = 'score_pct'`).
			Scan(&nullable); err != nil {
			t.Fatalf("read column nullability: %v", err)
		}
		if nullable != "YES" {
			t.Errorf("score_pct is_nullable = %q, want YES; the refusal did not roll back", nullable)
		}

		if !exp.Bool("null_row_survives") {
			t.Fatal("fixture must claim the null row survives")
		}
		var n int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM posture_snapshots WHERE host_id = $1 AND score_pct IS NULL`, host).
			Scan(&n); err != nil {
			t.Fatalf("count null rows: %v", err)
		}
		if n != 1 {
			t.Errorf("%d null-score rows survive, want 1", n)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-11
// AC-11: scoring metadata is all-or-nothing and its values are pinned.
func TestProvenance_ScoringMetadataShape(t *testing.T) {
	t.Run("system-posture-snapshots/AC-11", func(t *testing.T) {
		ctx := context.Background()
		pool := dbtest.Pool(t)
		ac := specfixture.Get(t, postureCriteria(t), "AC-11")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		user := seedOW024User(t, ctx, pool)
		day := time.Now().UTC().Truncate(24 * time.Hour)

		// meta reads the three metadata fields, each of which the fixture may
		// state as null. A missing key and a null are different claims, so the
		// nullable branch consumes the key either way.
		meta := func(f *specfixture.Fields) (*int, *string, *string) {
			var formula *int
			var agg, eng *string
			if f.IsNullable("formula_version") {
				f.IsNull("formula_version")
			} else {
				formula = intp(f.Int("formula_version"))
			}
			if f.IsNullable("aggregation_method") {
				f.IsNull("aggregation_method")
			} else {
				agg = strp(f.Str("aggregation_method"))
			}
			if f.IsNullable("engine_version") {
				f.IsNull("engine_version")
			} else {
				eng = strp(f.Str("engine_version"))
			}
			return formula, agg, eng
		}
		insert := func(f *int, agg, eng *string, score *float64) error {
			host := seedProvenanceHost(t, ctx, pool, user)
			return insertSnapshotFull(ctx, pool, host, day, snapshotRow{
				passing: 1, score: score, formula: f, aggregation: agg, engine: eng,
			})
		}

		legacyF, legacyA, legacyE := meta(in.Map("legacy_all_null"))
		if err := insert(legacyF, legacyA, legacyE, f64(100)); err != nil {
			t.Errorf("legacy row rejected: %v; a pre-0062 row carries none of the three", err)
		}
		if !exp.Bool("legacy_accepted") {
			t.Fatal("fixture must accept the legacy row")
		}

		newF, newA, newE := meta(in.Map("valid_new"))
		if err := insert(newF, newA, newE, f64(100)); err != nil {
			t.Errorf("valid new row rejected: %v", err)
		}
		if !exp.Bool("valid_new_accepted") {
			t.Fatal("fixture must accept the valid new row")
		}

		for _, c := range in.MapList("rejected") {
			label := c.Str("case")
			f, a, e := meta(c)
			if err := insert(f, a, e, f64(100)); err == nil {
				t.Errorf("%s: accepted, want rejected; partial metadata describes half of "+
					"how the number was produced", label)
			}
			c.AllConsumed()
		}
		if !exp.Bool("partial_or_invalid_rejected") {
			t.Fatal("fixture must reject partial or invalid metadata")
		}

		for _, raw := range in.List("rejected_scores") {
			var score float64
			switch n := raw.(type) {
			case float64:
				score = n
			case int:
				score = float64(n)
			default:
				t.Fatalf("rejected_scores holds %T, want numbers", raw)
			}
			if err := insert(intp(2), strp("none"), strp("v0.9.0"), &score); err == nil {
				t.Errorf("score_pct %v accepted; a percentage of rules that passed cannot fall "+
					"outside 0 to 100", score)
			}
		}
		if !exp.Bool("out_of_range_scores_rejected") {
			t.Fatal("fixture must reject out-of-range scores")
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}
