// @spec system-posture-snapshots
//
// AC traceability (DSN-gated):
//
//	AC-01  TestRollup_UpsertCountsAndExclusions
//	AC-02  TestTrends_WindowOrderingAndFleetAggregates
//	AC-03  TestRollup_PerFamilyOSResolvedSeries
//	AC-12  TestRollup_UpsertRefreshesLegacyProvenance
package posture

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/db/corpustest"

	"github.com/Hanalyx/openwatch/internal/db/dbtest"
	"github.com/Hanalyx/openwatch/internal/specfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := dbtest.Pool(t)
	ctx := context.Background()
	for _, stmt := range []string{
		"TRUNCATE TABLE posture_snapshots CASCADE",
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

func seedUser(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, username, email, password_hash)
		 VALUES ($1, $2, $3, $4)`,
		id, "posture-test-user", "ptu@example.com", "argon2id$dummy") // pragma: allowlist secret
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
		 VALUES ($1, $2, '192.0.2.20'::inet, $3)`,
		id, "posture-"+id.String(), createdBy)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return id
}

func seedRuleState(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status string, severity any) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO host_rule_state
			(host_id, rule_id, current_status, severity, last_checked_at,
			 check_count, last_scan_id, first_seen_at, last_changed_at)
		VALUES ($1, $2, $3, $4, now(), 1, $5, now(), now())`,
		hostID, ruleID, status, severity, corpustest.CurrentRun(t, pool, hostID))
	if err != nil {
		t.Fatalf("seed rule state: %v", err)
	}
}

// seedSnapshot writes a snapshot row directly for trend-read tests.
// seedSnapshot writes one version-2 snapshot whose COUNTS produce the requested
// score exactly.
//
// The counts and the score cannot be given independently. A row saying 70 with
// ten passing and three failing rules is self-contradictory, and once FleetTrend
// aggregates version-2 rows from their counts, such a row makes a test assert
// one number while the product computes another. passing is derived so that
// passing / (passing + failing) is exactly the score asked for.
func seedSnapshot(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, daysAgo int,
	score float64, failing int, critical bool) {
	t.Helper()
	passing := passingFor(t, score, failing)
	seedSnapshotScore(t, pool, hostID, daysAgo, &score, passing, failing, critical)
}

// passingFor solves passing / (passing + failing) = score/100 for passing, and
// fails the test when the answer is not a whole number rather than silently
// seeding a row that means something else.
func passingFor(t *testing.T, score float64, failing int) int {
	t.Helper()
	if score == 0 {
		return 0
	}
	if score == 100 {
		if failing != 0 {
			t.Fatalf("score 100 with %d failing rules is impossible", failing)
		}
		return 1
	}
	exact := float64(failing) * score / (100 - score)
	rounded := math.Round(exact)
	if math.Abs(exact-rounded) > 1e-9 {
		t.Fatalf("score %v with %d failing needs %v passing rules, which is not a whole "+
			"number; pick counts that produce the score exactly", score, failing, exact)
	}
	return int(rounded)
}

// seedSnapshotScore seeds one snapshot whose score may be absent, so a test can
// build the host the equal-host mean has to omit.
func seedSnapshotScore(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, daysAgo int,
	score *float64, passing, failing int, critical bool) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO posture_snapshots
			(host_id, snapshot_date, passing, failing, skipped, error, total,
			 score_pct, has_critical_findings, formula_version, aggregation_method,
			 engine_version, corpus_identity_status)
		VALUES ($1, current_date - $2::int, $3, $4, 0, 0, $3::int + $4::int, $5, $6,
		        2, 'none', 'v0.9.0', 'unavailable')`,
		hostID, daysAgo, passing, failing, score, critical)
	if err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}
}

// postureCriteria loads this spec's fixtures once per test.
func postureCriteria(t *testing.T) map[string]specfixture.Criterion {
	t.Helper()
	return specfixture.Load(t, "../../specs/system/posture-snapshots.spec.yaml",
		"system-posture-snapshots")
}

// @ac AC-01
// AC-01: one row per scanned host, scored under the one formula, carrying the
// provenance that says how the number was produced.
func TestRollup_UpsertCountsAndExclusions(t *testing.T) {
	t.Run("system-posture-snapshots/AC-01", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool)
		ac := specfixture.Get(t, postureCriteria(t), "AC-01")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		// seedCounts builds a host holding exactly the fixture's outcome mix.
		// The severities are chosen so the first failing rule is critical,
		// which is what has_critical_findings is asserted on below.
		seedCounts := func(f *specfixture.Fields) uuid.UUID {
			h := seedHost(t, pool, user)
			n := 0
			next := func() string { n++; return fmt.Sprintf("r%d", n) }
			for i := 0; i < f.Int("passing"); i++ {
				seedRuleState(t, pool, h, next(), "pass", "low")
			}
			for i := 0; i < f.Int("failing"); i++ {
				seedRuleState(t, pool, h, next(), "fail", "critical")
			}
			for i := 0; i < f.Int("skipped"); i++ {
				seedRuleState(t, pool, h, next(), "skipped", nil)
			}
			f.AllConsumed()
			return h
		}

		mixed := seedCounts(in.Map("mixed_host_counts"))
		// The host nothing could assess. Its row must exist and hold no score.
		unassessable := seedCounts(in.Map("unassessable_host_counts"))

		excluded := in.List("excluded_hosts")
		if len(excluded) != 2 {
			t.Fatalf("fixture names %d excluded host kinds, want 2", len(excluded))
		}
		_ = seedHost(t, pool, user) // never scanned
		deleted := seedHost(t, pool, user)
		seedRuleState(t, pool, deleted, "d1", "fail", "high")
		if _, err := pool.Exec(ctx, `UPDATE hosts SET deleted_at = now() WHERE id = $1`, deleted); err != nil {
			t.Fatalf("soft delete: %v", err)
		}

		n, err := Rollup(ctx, pool, time.Now())
		if err != nil {
			t.Fatalf("Rollup: %v", err)
		}
		if want := exp.Int("rows_written"); n != want {
			t.Errorf("rollup rows = %d, want %d (never-scanned and soft-deleted excluded)", n, want)
		}

		type row struct {
			passing, failing, skipped, total int
			score                            *float64
			critical                         bool
			formula                          *int
			aggregation, engine              *string
			status, version, digest          *string
		}
		read := func(h uuid.UUID) row {
			var r row
			if err := pool.QueryRow(ctx, `
				SELECT passing, failing, skipped, total, score_pct, has_critical_findings,
				       formula_version, aggregation_method, engine_version,
				       corpus_identity_status, corpus_version, corpus_digest
				  FROM posture_snapshots
				 WHERE host_id = $1 AND snapshot_date = current_date AND framework = ''`, h).
				Scan(&r.passing, &r.failing, &r.skipped, &r.total, &r.score, &r.critical,
					&r.formula, &r.aggregation, &r.engine, &r.status, &r.version, &r.digest); err != nil {
				t.Fatalf("read snapshot: %v", err)
			}
			return r
		}

		got := read(mixed)
		if got.score == nil || *got.score != exp.Num("score_pct") {
			t.Errorf("score_pct = %v, want %v", *got.score, exp.Num("score_pct"))
		}
		// The discriminating assertion. Under the replaced formula these same
		// counts scored 50.0, because the skipped rule was counted as a failure.
		if bad := exp.Num("forbidden_score_pct"); got.score != nil && *got.score == bad {
			t.Errorf("score_pct = %v, the passing-over-all-statuses answer C-02 replaced", bad)
		}
		if got.total != exp.Int("total") {
			t.Errorf("total = %d, want %d; the raw counts still record every outcome",
				got.total, exp.Int("total"))
		}
		if got.critical != exp.Bool("has_critical_findings") {
			t.Errorf("has_critical_findings = %v, want %v", got.critical, exp.Bool("has_critical_findings"))
		}

		// Provenance. Without these the score is a number with no record of how
		// it was produced, which is what made the pre-0062 history unusable.
		if got.formula == nil || *got.formula != exp.Int("formula_version") {
			t.Errorf("formula_version = %v, want %d", got.formula, exp.Int("formula_version"))
		}
		if got.aggregation == nil || *got.aggregation != exp.Str("aggregation_method") {
			t.Errorf("aggregation_method = %v, want %q; a snapshot aggregates nothing",
				got.aggregation, exp.Str("aggregation_method"))
		}
		if !exp.Bool("engine_version_copied_from_scan_run") {
			t.Fatal("fixture must require the engine version to be copied from the scan run")
		}
		// COPIED from the run, not stamped by this process. They happen to
		// coincide here because the seeder stamps the same value a real worker
		// would; system-scan-runs AC-10 is where they are made to differ.
		if got.engine == nil || *got.engine != runEngineOf(t, ctx, pool, mixed) {
			t.Errorf("engine_version = %v, want the producing run's %q",
				got.engine, runEngineOf(t, ctx, pool, mixed))
		}
		if got.status == nil || *got.status != exp.Str("corpus_identity_status") {
			t.Errorf("corpus_identity_status = %v, want %q", got.status, exp.Str("corpus_identity_status"))
		}
		exp.IsNull("corpus_version")
		exp.IsNull("corpus_digest")
		if got.version != nil || got.digest != nil {
			t.Errorf("corpus version=%v digest=%v, want both NULL beside an unreadable identity",
				got.version, got.digest)
		}

		// The host nothing could assess stores no score, and specifically not
		// the zero that would place it at the bottom of every chart.
		none := read(unassessable)
		exp.IsNull("unassessable_score_pct")
		if none.score != nil {
			t.Errorf("unassessable host scored %v, want no score", *none.score)
		}
		_ = exp.Num("unassessable_forbidden_score_pct")

		// Same-day re-run after a fix: UPDATE, not a duplicate.
		fixed := in.Map("after_fix_counts")
		if _, err := pool.Exec(ctx, `
			UPDATE host_rule_state SET current_status = 'pass' WHERE host_id = $1 AND current_status = 'fail'`,
			mixed); err != nil {
			t.Fatalf("flip rule: %v", err)
		}
		if fixed.Int("failing") != 0 {
			t.Fatalf("after_fix fixture expects %d failures; the flip clears them all", fixed.Int("failing"))
		}
		_, _ = fixed.Int("passing"), fixed.Int("skipped")
		fixed.AllConsumed()
		if _, err := Rollup(ctx, pool, time.Now()); err != nil {
			t.Fatalf("second Rollup: %v", err)
		}
		var rows int
		var score2 *float64
		_ = pool.QueryRow(ctx, `
			SELECT COUNT(*), MAX(score_pct) FROM posture_snapshots WHERE host_id = $1 AND framework = ''`,
			mixed).Scan(&rows, &score2)
		if rows != exp.Int("after_fix_row_count") {
			t.Errorf("after re-run: rows = %d, want %d", rows, exp.Int("after_fix_row_count"))
		}
		if score2 == nil || *score2 != exp.Num("after_fix_score_pct") {
			t.Errorf("after re-run: score = %v, want %v", score2, exp.Num("after_fix_score_pct"))
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// seedRuleStateFW seeds a host_rule_state row with a framework_refs JSONB
// literal (e.g. `{"stig_rhel9":["V-1"]}`).
func seedRuleStateFW(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status, refs string) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO host_rule_state
			(host_id, rule_id, current_status, severity, last_checked_at,
			 check_count, last_scan_id, framework_refs, first_seen_at, last_changed_at)
		VALUES ($1, $2, $3, 'medium', now(), 1, $4, $5::jsonb, now(), now())`,
		hostID, ruleID, status, corpustest.CurrentRun(t, pool, hostID), refs)
	if err != nil {
		t.Fatalf("seed rule state fw: %v", err)
	}
}

// @ac AC-03
// AC-03: the rollup writes a per-FAMILY series, OS-RESOLVED — a RHEL 9
// host's "stig" row scores stig_rhel9 only (a stig_rhel10 rule it carries
// is excluded), OS-neutral families resolve via the bare key, and the ”
// all-rules series counts everything. HostTrend reads the requested lens
// series and normalizes a specific key to its family.
func TestRollup_PerFamilyOSResolvedSeries(t *testing.T) {
	t.Run("system-posture-snapshots/AC-03", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool)

		h := seedHost(t, pool, user)
		if _, err := pool.Exec(ctx,
			`UPDATE hosts SET os_family='rhel', os_version='9.6' WHERE id=$1`, h); err != nil {
			t.Fatalf("set os: %v", err)
		}
		// STIG: stig_rhel9 (1 pass, 1 fail) + stig_rhel10 (1 pass, wrong OS).
		seedRuleStateFW(t, pool, h, "s9.pass", "pass", `{"stig_rhel9":["V-1"]}`)
		seedRuleStateFW(t, pool, h, "s9.fail", "fail", `{"stig_rhel9":["V-2"]}`)
		seedRuleStateFW(t, pool, h, "s10.pass", "pass", `{"stig_rhel10":["V-1"]}`)
		// CIS (OS-specific) + NIST (OS-neutral).
		seedRuleStateFW(t, pool, h, "c9.pass", "pass", `{"cis_rhel9":["1.1"]}`)
		seedRuleStateFW(t, pool, h, "n.pass", "pass", `{"nist_800_53":["AC-1"]}`)

		if _, err := Rollup(ctx, pool, time.Now()); err != nil {
			t.Fatalf("Rollup: %v", err)
		}

		read := func(fw string) (passing, total int, score float64) {
			err := pool.QueryRow(ctx, `
				SELECT passing, total, score_pct FROM posture_snapshots
				 WHERE host_id=$1 AND snapshot_date=current_date AND framework=$2`,
				h, fw).Scan(&passing, &total, &score)
			if err != nil {
				t.Fatalf("read framework %q: %v", fw, err)
			}
			return
		}

		// STIG resolves to stig_rhel9 ONLY: 1 pass / 2 total (stig_rhel10 excluded).
		if p, tot, sc := read("stig"); p != 1 || tot != 2 || sc != 50.0 {
			t.Errorf("stig series = %d/%d score %v, want 1/2 50 (stig_rhel10 excluded)", p, tot, sc)
		}
		// CIS (cis_rhel9): 1/1. NIST (bare key): 1/1.
		if p, tot, _ := read("cis"); p != 1 || tot != 1 {
			t.Errorf("cis series = %d/%d, want 1/1", p, tot)
		}
		if p, tot, _ := read("nist_800_53"); p != 1 || tot != 1 {
			t.Errorf("nist_800_53 series = %d/%d, want 1/1", p, tot)
		}
		// All-rules ('' series): everything = 4 pass / 5 total.
		if p, tot, _ := read(""); p != 4 || tot != 5 {
			t.Errorf("all-rules series = %d/%d, want 4/5", p, tot)
		}

		// HostTrend reads the lens series; a specific key normalizes to family.
		// pct reads a trend point's score, failing the test when it is absent.
		// A helper returning 0 for an absent score would hide exactly the case
		// these assertions exist to distinguish.
		pct := func(label string, pts []DayPoint) float64 {
			t.Helper()
			if len(pts) != 1 {
				t.Fatalf("HostTrend(%s) returned %d points, want 1", label, len(pts))
			}
			v, ok := pts[0].Score.Rounded()
			if !ok {
				t.Fatalf("HostTrend(%s) point has no score", label)
			}
			return v
		}
		fam, err := HostTrend(ctx, pool, h, 30, "stig")
		if err != nil {
			t.Fatalf("HostTrend(stig): %v", err)
		}
		if got := pct("stig", fam); got != 50.0 {
			t.Errorf("HostTrend(stig) = %v, want 50", got)
		}
		key, _ := HostTrend(ctx, pool, h, 30, "stig_rhel9")
		if got := pct("stig_rhel9", key); got != 50.0 {
			t.Errorf("HostTrend(stig_rhel9) = %v, want the stig series (50)", got)
		}
		all, _ := HostTrend(ctx, pool, h, 30, "")
		if got := pct("all-rules", all); got != 80.0 {
			t.Errorf("HostTrend('') = %v, want all-rules (80)", got)
		}
	})
}

// @ac AC-02
// AC-02: trend reads window and order; the fleet average is the equal-host
// mean over the hosts that produced a score.
func TestTrends_WindowOrderingAndFleetAggregates(t *testing.T) {
	t.Run("system-posture-snapshots/AC-02", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool)
		ac := specfixture.Get(t, postureCriteria(t), "AC-02")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		a := seedHost(t, pool, user)
		seedSnapshot(t, pool, a, 1, 70, 3, true)
		seedSnapshot(t, pool, a, 40, 10, 27, true) // outside a 30-day window (3 of 30 pass)

		// Today's hosts come from the fixture, one snapshot each, so the mean
		// is over one row per host and the arithmetic is the equal-host mean.
		scored := in.List("day_host_scores")
		todayHosts := make([]uuid.UUID, 0, len(scored))
		for i, raw := range scored {
			var v float64
			switch n := raw.(type) {
			case float64:
				v = n
			case int:
				v = float64(n)
			default:
				t.Fatalf("day_host_scores[%d] is %T, want a number", i, raw)
			}
			h := a
			if i > 0 {
				h = seedHost(t, pool, user)
			}
			seedSnapshot(t, pool, h, 0, v, 2+2*i, false)
			todayHosts = append(todayHosts, h)
		}
		// The host that produced no verdict. It has a snapshot and no score.
		for i := 0; i < in.Int("day_unscored_hosts"); i++ {
			seedSnapshotScore(t, pool, seedHost(t, pool, user), 0, nil, 0, 0, false)
		}

		// Soft-deleted host's snapshots vanish from the fleet view.
		ghost := seedHost(t, pool, user)
		seedSnapshot(t, pool, ghost, 0, 0, 99, true)
		if _, err := pool.Exec(ctx, `UPDATE hosts SET deleted_at = now() WHERE id = $1`, ghost); err != nil {
			t.Fatalf("soft delete: %v", err)
		}

		points, err := HostTrend(ctx, pool, todayHosts[0], 30, "")
		if err != nil {
			t.Fatalf("HostTrend: %v", err)
		}
		if len(points) != 2 {
			t.Fatalf("host points = %d, want 2 (40-day-old row excluded)", len(points))
		}
		first, ok1 := points[0].Score.Rounded()
		second, ok2 := points[1].Score.Rounded()
		if !ok1 || !ok2 {
			t.Fatalf("trend point with no score: %v %v", points[0].Score, points[1].Score)
		}
		if !(first == 70 && second == 90) {
			t.Errorf("ordering wrong: %v then %v, want 70 then 90 (oldest first)", first, second)
		}

		fleet, err := FleetTrend(ctx, pool, 30, "")
		if err != nil {
			t.Fatalf("FleetTrend: %v", err)
		}
		if len(fleet) != 2 {
			t.Fatalf("fleet days = %d, want 2", len(fleet))
		}
		today := fleet[len(fleet)-1]
		avg, ok := today.Score.Rounded()
		if !ok {
			t.Fatal("today has no fleet score, but two hosts were scored")
		}
		if want := exp.Num("score_pct"); avg != want {
			t.Errorf("score_pct = %v, want %v (equal-host mean)", avg, want)
		}
		// The discriminating assertion: averaging the unscored host in as zero
		// gives the forbidden answer, which is the OW-023 defect one layer out.
		if bad := exp.Num("forbidden_score_pct"); avg == bad {
			t.Errorf("score_pct = %v, the answer produced by averaging the unscored host in as zero", bad)
		}
		if today.Hosts != exp.Int("hosts") {
			t.Errorf("hosts = %d, want %d", today.Hosts, exp.Int("hosts"))
		}
		if today.HostsScored != exp.Int("hosts_scored") {
			t.Errorf("hosts_scored = %d, want %d", today.HostsScored, exp.Int("hosts_scored"))
		}
		if today.HostsWithoutScore != exp.Int("hosts_without_score") {
			t.Errorf("hosts_without_score = %d, want %d; a mean reported without its "+
				"population cannot be told from a mean over every host",
				today.HostsWithoutScore, exp.Int("hosts_without_score"))
		}
		if today.CriticalHosts != 0 {
			t.Errorf("critical hosts = %d, want 0 (ghost dropped)", today.CriticalHosts)
		}

		yesterday := fleet[0]
		yAvg, _ := yesterday.Score.Rounded()
		if yesterday.Hosts != 1 || yAvg != 70.0 || yesterday.CriticalHosts != 1 {
			t.Errorf("yesterday = %+v avg %v, want hosts 1 avg 70 critical 1", yesterday, yAvg)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-12
// AC-12: an upsert refreshes provenance alongside the score.
//
// The row seeded here is the shape an older release wrote: a score under the
// replaced formula and no provenance at all. Running the rollup over it is what
// every upgraded deployment does on its first hourly tick, and the row must come
// out fully describing the number it now holds.
func TestRollup_UpsertRefreshesLegacyProvenance(t *testing.T) {
	t.Run("system-posture-snapshots/AC-12", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool)
		ac := specfixture.Get(t, postureCriteria(t), "AC-12")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		h := seedHost(t, pool, user)
		live := in.Map("live_counts")
		for i := 0; i < live.Int("passing"); i++ {
			seedRuleState(t, pool, h, fmt.Sprintf("p%d", i), "pass", "low")
		}
		for i := 0; i < live.Int("failing"); i++ {
			seedRuleState(t, pool, h, fmt.Sprintf("f%d", i), "fail", "critical")
		}
		for i := 0; i < live.Int("skipped"); i++ {
			seedRuleState(t, pool, h, fmt.Sprintf("s%d", i), "skipped", nil)
		}
		live.AllConsumed()

		legacy := in.Map("seeded_legacy_row")
		if _, err := pool.Exec(ctx, `
			INSERT INTO posture_snapshots
				(host_id, snapshot_date, framework, passing, failing, skipped, error, total,
				 score_pct, has_critical_findings)
			VALUES ($1, current_date, '', 2, 1, 1, 0, 4, $2, true)`,
			h, legacy.Num("score_pct")); err != nil {
			t.Fatalf("seed legacy row: %v", err)
		}
		for _, k := range []string{"formula_version", "aggregation_method", "engine_version",
			"corpus_identity_status"} {
			legacy.IsNull(k)
		}
		legacy.AllConsumed()

		if _, err := Rollup(ctx, pool, time.Now()); err != nil {
			t.Fatalf("Rollup: %v", err)
		}

		var rows int
		var score *float64
		var formula *int
		var aggregation, engine, status *string
		if err := pool.QueryRow(ctx, `
			SELECT COUNT(*), MAX(score_pct), MAX(formula_version), MAX(aggregation_method),
			       MAX(engine_version), MAX(corpus_identity_status)
			  FROM posture_snapshots
			 WHERE host_id = $1 AND snapshot_date = current_date AND framework = ''`, h).
			Scan(&rows, &score, &formula, &aggregation, &engine, &status); err != nil {
			t.Fatalf("read back: %v", err)
		}

		if rows != exp.Int("row_count") {
			t.Errorf("rows = %d, want %d; the upsert must update, not duplicate", rows, exp.Int("row_count"))
		}
		if score == nil || *score != exp.Num("score_pct") {
			t.Errorf("score_pct = %v, want %v recomputed under the new formula", score, exp.Num("score_pct"))
		}
		// The point of the criterion. A recomputed score with the old row's
		// empty provenance is a number described by nothing.
		if formula == nil || *formula != exp.Int("formula_version") {
			t.Errorf("formula_version = %v, want %d; the ON CONFLICT path must refresh "+
				"provenance with the score", formula, exp.Int("formula_version"))
		}
		if aggregation == nil || *aggregation != exp.Str("aggregation_method") {
			t.Errorf("aggregation_method = %v, want %q", aggregation, exp.Str("aggregation_method"))
		}
		if !exp.Bool("engine_version_copied_from_scan_run") {
			t.Fatal("fixture must require the engine version to be copied from the scan run")
		}
		if engine == nil || *engine != runEngineOf(t, ctx, pool, h) {
			t.Errorf("engine_version = %v, want the producing run's %q",
				engine, runEngineOf(t, ctx, pool, h))
		}
		if status == nil || *status != exp.Str("corpus_identity_status") {
			t.Errorf("corpus_identity_status = %v, want %q", status, exp.Str("corpus_identity_status"))
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-13
// AC-13: a scan that produced nothing reconciles the day.
//
// This is the posture form of bugs/OW-024. host_rule_state_current has no row
// for a host whose newest completed scan returned no outcome, so nothing drives
// the UPSERT and the previous scan's score sits in today's slot reading as
// current. Both the all-rules point and any framework series the earlier scan
// produced have to be reconciled, not merely left alone.
func TestRollup_ZeroOutcomeScanReconcilesTheDay(t *testing.T) {
	t.Run("system-posture-snapshots/AC-13", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool)
		ac := specfixture.Get(t, postureCriteria(t), "AC-13")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		h := seedHost(t, pool, user)
		// The framework series is OS-RESOLVED, so a stig_rhel9 key only produces
		// a series on a RHEL 9 host. Without the OS the first rollup writes no
		// per-family row and there is nothing for step 5 to reconcile.
		if _, err := pool.Exec(ctx,
			`UPDATE hosts SET os_family='rhel', os_version='9.6' WHERE id=$1`, h); err != nil {
			t.Fatalf("set host OS: %v", err)
		}

		// 1. A scored scan, with rules mapped to a framework so a per-family
		//    series exists to be reconciled later.
		first := in.Map("first_scan")
		refs := `{"` + first.Str("framework_key") + `":["V-1"]}`
		for i := 0; i < first.Int("passing"); i++ {
			seedRuleStateFW(t, pool, h, fmt.Sprintf("p%d", i), "pass", refs)
		}
		for i := 0; i < first.Int("failing"); i++ {
			seedRuleStateFW(t, pool, h, fmt.Sprintf("f%d", i), "fail", refs)
		}
		first.AllConsumed()

		if _, err := Rollup(ctx, pool, time.Now()); err != nil {
			t.Fatalf("first Rollup: %v", err)
		}

		// The first pass must be what the fixture says, or the reconciliation
		// below would be asserting against a state nobody established.
		var got *float64
		if err := pool.QueryRow(ctx, `
			SELECT score_pct FROM posture_snapshots
			 WHERE host_id = $1 AND snapshot_date = current_date AND framework = ''`, h).
			Scan(&got); err != nil {
			t.Fatalf("read first all-rules row: %v", err)
		}
		if got == nil || *got != exp.Num("first_rollup_all_rules_score_pct") {
			t.Fatalf("first rollup score = %v, want %v", got,
				exp.Num("first_rollup_all_rules_score_pct"))
		}
		series := func() []string {
			rows, err := pool.Query(ctx, `
				SELECT framework FROM posture_snapshots
				 WHERE host_id = $1 AND snapshot_date = current_date AND framework <> ''
				 ORDER BY framework`, h)
			if err != nil {
				t.Fatalf("read framework series: %v", err)
			}
			defer rows.Close()
			var out []string
			for rows.Next() {
				var f string
				if err := rows.Scan(&f); err != nil {
					t.Fatalf("scan framework: %v", err)
				}
				out = append(out, f)
			}
			return out
		}
		wantFirst := exp.List("first_rollup_framework_series")
		if len(series()) != len(wantFirst) {
			t.Fatalf("first rollup wrote series %v, want %v", series(), wantFirst)
		}
		for i, f := range series() {
			if f != wantFirst[i] {
				t.Fatalf("first rollup series[%d] = %q, want %v", i, f, wantFirst[i])
			}
		}

		// 2. A NEWER completed scan that produced no outcome at all. It writes
		//    no host_rule_state rows, which is precisely why the rollup used to
		//    miss it, and it supersedes the scored run so the corpus view is
		//    empty for this host.
		second := in.Map("second_scan")
		finished := time.Now().UTC()
		newRun := corpustest.SeedRun(t, pool, h, "completed", finished.Add(-time.Minute), finished)
		// All four counts come from the fixture. Hardcoding skipped and error
		// to zero here would have made the criterion silent about two of the
		// four predicates the branch depends on.
		if _, err := pool.Exec(ctx, `
			UPDATE scan_runs SET rules_pass = $2, rules_fail = $3, rules_skipped = $4, rules_error = $5,
			       corpus_identity_status = 'unavailable'
			 WHERE id = $1`, newRun,
			second.Int("rules_pass"), second.Int("rules_fail"),
			second.Int("rules_skipped"), second.Int("rules_error")); err != nil {
			t.Fatalf("record zero-outcome counts: %v", err)
		}
		if second.Int("rule_state_rows") != 0 {
			t.Fatalf("fixture expects %d rule-state rows; this scan writes none",
				second.Int("rule_state_rows"))
		}
		second.AllConsumed()

		var live int
		if err := pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM host_rule_state_current WHERE host_id = $1`, h).Scan(&live); err != nil {
			t.Fatalf("count current rule state: %v", err)
		}
		if live != 0 {
			t.Fatalf("host still has %d current rule-state rows; the fixture must leave none, "+
				"or the reconciliation path is never reached", live)
		}

		// A host the rollup covers NOWHERE: it has a snapshot today and no
		// completed scan. The prune must leave it alone. Without the scoping
		// guard this row is deleted for the sole reason that it was not
		// recomputed, which turns a rule about stale verdicts into data loss.
		unscanned := seedHost(t, pool, user)
		unscannedFix := in.Map("unscanned_host_with_snapshot")
		seedSnapshot(t, pool, unscanned, 0, unscannedFix.Num("score_pct"), 29, false)
		unscannedFix.AllConsumed()

		// 3. Roll up again.
		if _, err := Rollup(ctx, pool, time.Now()); err != nil {
			t.Fatalf("second Rollup: %v", err)
		}

		if !exp.Bool("unscanned_host_row_survives") {
			t.Fatal("fixture must claim the never-scanned host's row survives")
		}
		var kept *float64
		if err := pool.QueryRow(ctx, `
			SELECT score_pct FROM posture_snapshots
			 WHERE host_id = $1 AND snapshot_date = current_date AND framework = ''`, unscanned).
			Scan(&kept); err != nil {
			t.Fatalf("never-scanned host's row was deleted: %v; the prune must be scoped "+
				"to the hosts the pass actually covered", err)
		}
		if kept == nil || *kept != exp.Num("unscanned_host_score_pct") {
			t.Errorf("never-scanned host's score = %v, want %v untouched",
				kept, exp.Num("unscanned_host_score_pct"))
		}

		// 4. The all-rules point is reconciled, not left stale.
		var score *float64
		var passing, failing, skipped, errored, total int
		var critical bool
		var formula *int
		var aggregation, engine, status *string
		if err := pool.QueryRow(ctx, `
			SELECT score_pct, passing, failing, skipped, error, total, has_critical_findings,
			       formula_version, aggregation_method, engine_version, corpus_identity_status
			  FROM posture_snapshots
			 WHERE host_id = $1 AND snapshot_date = current_date AND framework = ''`, h).
			Scan(&score, &passing, &failing, &skipped, &errored, &total, &critical,
				&formula, &aggregation, &engine, &status); err != nil {
			t.Fatalf("read reconciled row: %v; the host must not disappear from the day", err)
		}
		exp.IsNull("all_rules_score_pct")
		if score != nil {
			t.Errorf("score_pct = %v, want no score; the scan produced no verdict", *score)
		}
		// The discriminating assertion: the previous scan's answer must not
		// still be sitting here presented as current.
		if bad := exp.Num("forbidden_all_rules_score_pct"); score != nil && *score == bad {
			t.Errorf("score_pct = %v, which is the PREVIOUS scan's score left readable as current", bad)
		}
		if passing != exp.Int("passing") || failing != exp.Int("failing") ||
			skipped != exp.Int("skipped") || errored != exp.Int("error") ||
			total != exp.Int("total") {
			t.Errorf("counts = %d/%d/%d/%d total %d, want %d/%d/%d/%d total %d",
				passing, failing, skipped, errored, total,
				exp.Int("passing"), exp.Int("failing"), exp.Int("skipped"),
				exp.Int("error"), exp.Int("total"))
		}
		if critical != exp.Bool("has_critical_findings") {
			t.Errorf("has_critical_findings = %v, want %v; a scan with no outcome found no critical rule",
				critical, exp.Bool("has_critical_findings"))
		}
		if formula == nil || *formula != exp.Int("formula_version") {
			t.Errorf("formula_version = %v, want %d", formula, exp.Int("formula_version"))
		}
		if aggregation == nil || *aggregation != exp.Str("aggregation_method") {
			t.Errorf("aggregation_method = %v, want %q", aggregation, exp.Str("aggregation_method"))
		}
		// The PRODUCING run's version, which is what the rollup copies. It
		// coincides with this process's here because the seeder stamps what a
		// real worker would; system-scan-runs AC-10 is where they are made to
		// differ, and that is the test that can tell them apart.
		if engine == nil || *engine != runEngineOf(t, ctx, pool, h) {
			t.Errorf("engine_version = %v, want the producing run's %q",
				engine, runEngineOf(t, ctx, pool, h))
		}
		if status == nil || *status != exp.Str("corpus_identity_status") {
			t.Errorf("corpus_identity_status = %v, want %q", status, exp.Str("corpus_identity_status"))
		}

		// 5. The framework series the earlier scan produced must not survive.
		exp.EmptyList("surviving_framework_series")
		if left := series(); len(left) != 0 {
			t.Errorf("framework series %v survived; the current scan produces none, so an earlier "+
				"scan's per-lens score must not remain as a current value", left)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-14
// AC-14: missing rule state is not proof of zero outcomes.
//
// AC-13 proves the reconciliation happens. This proves it happens only on
// evidence. All five hosts here have no current rule state and a same-day row
// from an earlier scored scan, and no scan run among them can testify that
// nothing was assessed: one recorded no counts at all, and the other four each
// recorded outcomes of exactly one kind whose rows are missing. Rewriting any of
// them as a zero-outcome snapshot would invent the measurement, which is what
// migration 0061 exists to undo.
//
// One host per count is what makes the four predicates separable. A single
// fixture tripping two of them hides the removal of either, which is how the
// rules_error predicate went unguarded through two review rounds.
func TestRollup_MissingRuleStateIsNotProofOfZeroOutcomes(t *testing.T) {
	t.Run("system-posture-snapshots/AC-14", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool)
		ac := specfixture.Get(t, postureCriteria(t), "AC-14")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		earlier := in.Map("earlier_scored_scan")
		refs := `{"` + earlier.Str("framework_key") + `":["V-1"]}`

		// setup builds a host with a scored day already rolled up, then a newer
		// completed run whose counts are whatever the fixture names, and no rule
		// state at all.
		setup := func(name string, counts *specfixture.Fields) uuid.UUID {
			h := seedHost(t, pool, user)
			if _, err := pool.Exec(ctx,
				`UPDATE hosts SET os_family='rhel', os_version='9.6' WHERE id=$1`, h); err != nil {
				t.Fatalf("%s: set host OS: %v", name, err)
			}
			for i := 0; i < earlier.Int("passing"); i++ {
				seedRuleStateFW(t, pool, h, fmt.Sprintf("p%d", i), "pass", refs)
			}
			for i := 0; i < earlier.Int("failing"); i++ {
				seedRuleStateFW(t, pool, h, fmt.Sprintf("f%d", i), "fail", refs)
			}
			if _, err := Rollup(ctx, pool, time.Now()); err != nil {
				t.Fatalf("%s: seeding rollup: %v", name, err)
			}
			// The newer run. Its counts are the only evidence about what the
			// scan did, and in every one of these five fixtures they fail to
			// establish "nothing".
			finished := time.Now().UTC()
			run := corpustest.SeedRun(t, pool, h, "completed", finished.Add(-time.Minute), finished)
			col := func(k string) any {
				if counts.IsNullable(k) {
					counts.IsNull(k)
					return nil
				}
				return counts.Int(k)
			}
			if _, err := pool.Exec(ctx, `
				UPDATE scan_runs
				   SET rules_pass = $2, rules_fail = $3, rules_skipped = $4, rules_error = $5,
				       corpus_identity_status = 'unavailable'
				 WHERE id = $1`, run,
				col("rules_pass"), col("rules_fail"), col("rules_skipped"), col("rules_error")); err != nil {
				t.Fatalf("%s: record counts: %v", name, err)
			}
			if counts.Int("rule_state_rows") != 0 {
				t.Fatalf("%s: fixture must write no rule state", name)
			}
			counts.AllConsumed()
			// Retire the old rule state so the corpus view is empty, which is
			// the shape that made the rollup guess in the first place.
			if _, err := pool.Exec(ctx, `DELETE FROM host_rule_state WHERE host_id = $1`, h); err != nil {
				t.Fatalf("%s: clear rule state: %v", name, err)
			}
			var live int
			if err := pool.QueryRow(ctx,
				`SELECT COUNT(*) FROM host_rule_state_current WHERE host_id = $1`, h).Scan(&live); err != nil {
				t.Fatalf("%s: count current: %v", name, err)
			}
			if live != 0 {
				t.Fatalf("%s: %d rule-state rows remain; the branch under test is never reached", name, live)
			}
			return h
		}

		// One host per count, each disqualifying on exactly ONE of the four.
		// A fixture that trips two predicates hides the removal of either: the
		// pass/fail host used to cover both, so dropping the rules_error
		// predicate changed nothing anywhere.
		hosts := []struct {
			name    string
			fixture string
		}{
			{"null-counts", "null_counts_host"},
			{"pass-only", "pass_only_host"},
			{"fail-only", "fail_only_host"},
			{"skipped-only", "skipped_only_host"},
			{"error-only", "error_only_host"},
		}
		seeded := make(map[string]uuid.UUID, len(hosts))
		for _, hst := range hosts {
			seeded[hst.name] = setup(hst.name, in.Map(hst.fixture))
		}
		earlier.AllConsumed()

		// The return value is the assertion, not a discarded blank. Rollup
		// reports the rows it wrote, and "no host qualified" has to be checked
		// against what it actually returned.
		written, err := Rollup(ctx, pool, time.Now())
		if err != nil {
			t.Fatalf("Rollup: %v", err)
		}
		if want := exp.Int("rows_rewritten"); written != want {
			t.Errorf("Rollup wrote %d rows, want %d; no host here carries evidence that its "+
				"scan assessed nothing", written, want)
		}

		exp.IsNull("forbidden_score_pct")
		check := func(name string, h uuid.UUID) {
			var score *float64
			var total int
			var formula *int
			if err := pool.QueryRow(ctx, `
				SELECT score_pct, total, formula_version FROM posture_snapshots
				 WHERE host_id = $1 AND snapshot_date = current_date AND framework = ''`, h).
				Scan(&score, &total, &formula); err != nil {
				t.Fatalf("%s: all-rules row is gone: %v; a host the rollup cannot measure "+
					"must be left exactly as it was", name, err)
			}
			if score == nil {
				t.Errorf("%s: score was cleared to NULL; missing rule state is not proof "+
					"the scan assessed nothing", name)
			} else if *score != exp.Num("score_pct") {
				t.Errorf("%s: score_pct = %v, want %v untouched", name, *score, exp.Num("score_pct"))
			}
			if total == exp.Int("forbidden_zeroed_total") {
				t.Errorf("%s: total was rewritten to %d; the zero-outcome branch fired without "+
					"evidence", name, total)
			}

			rows, err := pool.Query(ctx, `
				SELECT framework FROM posture_snapshots
				 WHERE host_id = $1 AND snapshot_date = current_date AND framework <> ''
				 ORDER BY framework`, h)
			if err != nil {
				t.Fatalf("%s: read series: %v", name, err)
			}
			defer rows.Close()
			var got []string
			for rows.Next() {
				var f string
				if err := rows.Scan(&f); err != nil {
					t.Fatalf("%s: scan series: %v", name, err)
				}
				got = append(got, f)
			}
			want := exp.List("surviving_framework_series")
			if len(got) != len(want) {
				t.Errorf("%s: series = %v, want %v; a host absent from the computed set "+
					"must be skipped by the prune too", name, got, want)
			}
			for i := range got {
				if i < len(want) && got[i] != want[i] {
					t.Errorf("%s: series[%d] = %q, want %v", name, i, got[i], want[i])
				}
			}
		}
		for _, hst := range hosts {
			check(hst.name, seeded[hst.name])
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-15
// AC-15: a day mixing formula versions has no score.
//
// The refusal has to be specific to MIXING. A day of only version-2 rows and a
// day of only legacy rows both score normally in the same test, or this would
// be indistinguishable from the trend simply having stopped working.
func TestFleetTrend_MixedFormulaVersionsHaveNoScore(t *testing.T) {
	t.Run("system-posture-snapshots/AC-15", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool)
		ac := specfixture.Get(t, postureCriteria(t), "AC-15")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		// seedLegacy writes a row the way a pre-redesign release did: a stored
		// score and no formula version. Its counts are deliberately unrelated
		// to the score, which is exactly why a version-2 reader must not touch
		// them.
		seedLegacy := func(host uuid.UUID, daysAgo int, score float64) {
			t.Helper()
			if _, err := pool.Exec(ctx, `
				INSERT INTO posture_snapshots
					(host_id, snapshot_date, passing, failing, skipped, error, total,
					 score_pct, has_critical_findings)
				VALUES ($1, current_date - $2::int, 2, 3, 0, 0, 5, $3, false)`,
				host, daysAgo, score); err != nil {
				t.Fatalf("seed legacy row: %v", err)
			}
		}
		seedV2 := func(host uuid.UUID, daysAgo, passing, failing int) {
			t.Helper()
			pct := float64(passing) / float64(passing+failing) * 100
			seedSnapshotScore(t, pool, host, daysAgo, &pct, passing, failing, false)
		}

		// Day 0: one legacy row and one version-2 row.
		mixed := in.Map("mixed_day")
		legacy := mixed.Map("legacy_row")
		legacy.IsNull("formula_version")
		seedLegacy(seedHost(t, pool, user), 0, legacy.Num("score_pct"))
		legacy.AllConsumed()
		v2 := mixed.Map("v2_row")
		if v2.Int("formula_version") != 2 {
			t.Fatal("fixture's v2 row must carry formula version 2")
		}
		seedV2(seedHost(t, pool, user), 0, v2.Int("passing"), v2.Int("failing"))
		v2.AllConsumed()
		mixed.AllConsumed()

		// Day 1: version-2 rows only. Day 2: legacy rows only.
		v2Day := in.Map("v2_only_day")
		for _, r := range v2Day.MapList("rows") {
			seedV2(seedHost(t, pool, user), 1, r.Int("passing"), r.Int("failing"))
			r.AllConsumed()
		}
		v2Day.AllConsumed()
		legacyDay := in.Map("legacy_only_day")
		for _, r := range legacyDay.MapList("rows") {
			seedLegacy(seedHost(t, pool, user), 2, r.Num("score_pct"))
			r.AllConsumed()
		}
		legacyDay.AllConsumed()

		points, err := FleetTrend(ctx, pool, 30, "")
		if err != nil {
			t.Fatalf("FleetTrend: %v", err)
		}
		if len(points) != 3 {
			t.Fatalf("%d trend days, want 3", len(points))
		}
		// Oldest first, so index 0 is the legacy-only day two days back.
		legacyOnly, v2Only, mixedDay := points[0], points[1], points[2]

		exp.IsNull("mixed_day_score_pct")
		if mixedDay.Score.Present() {
			pct, _ := mixedDay.Score.Value()
			t.Errorf("mixed day scored %v; two formulas produce two quantities and their "+
				"mean is a compliance score under neither", pct)
		}
		// The discriminating value. Averaging 40.0 with 80.0 gives 60.0, which
		// is what the day published before this rule existed. Read outside the
		// condition: `ok && exp.Num(...)` short-circuits when the score is
		// absent, so the expectation would go unasserted on exactly the path
		// this criterion is about.
		forbiddenMixed := exp.Num("forbidden_mixed_day_pct")
		if pct, ok := mixedDay.Score.Value(); ok && pct == forbiddenMixed {
			t.Errorf("mixed day scored %v, the arithmetic mean of a legacy row and a "+
				"version-2 row", pct)
		}
		if want := exp.Str("mixed_day_formula_status"); string(mixedDay.FormulaStatus) != want {
			t.Errorf("mixed day formula status = %q, want %q; without it the consumer cannot "+
				"tell this day from one with no snapshots at all", mixedDay.FormulaStatus, want)
		}
		if mixedDay.Hosts != exp.Int("mixed_day_hosts") {
			t.Errorf("mixed day hosts = %d, want %d; the counts must survive so the gap can "+
				"be explained", mixedDay.Hosts, exp.Int("mixed_day_hosts"))
		}

		// The two unmixed days still score, which is what makes the refusal
		// specific rather than a blanket failure.
		if got := mustScore(t, v2Only, "version-2 only"); got != exp.Num("v2_only_day_score_pct") {
			t.Errorf("version-2 day = %v, want %v", got, exp.Num("v2_only_day_score_pct"))
		}
		if want := exp.Str("v2_only_day_formula_status"); string(v2Only.FormulaStatus) != want {
			t.Errorf("version-2 only day status = %q, want %q", v2Only.FormulaStatus, want)
		}
		if got := mustScore(t, legacyOnly, "legacy only"); got != exp.Num("legacy_only_day_score_pct") {
			t.Errorf("legacy day = %v, want %v", got, exp.Num("legacy_only_day_score_pct"))
		}
		// The state a boolean could not express: a real score whose formula is
		// unknown, which is NOT comparable with an identified one.
		if want := exp.Str("legacy_only_day_formula_status"); string(legacyOnly.FormulaStatus) != want {
			t.Errorf("legacy only day status = %q, want %q", legacyOnly.FormulaStatus, want)
		}
		if legacyOnly.FormulaStatus == v2Only.FormulaStatus {
			t.Error("a legacy day and a version-2 day report the same formula status; the two " +
				"scores mean different things and must be distinguishable")
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// mustScore reads a trend point's score or fails, so an absent score is never
// silently read as zero.
func mustScore(t *testing.T, p FleetDayPoint, label string) float64 {
	t.Helper()
	pct, ok := p.Score.Rounded()
	if !ok {
		t.Fatalf("%s day has no score", label)
	}
	return pct
}

// runEngineOf reads the engine version recorded on a host's latest completed
// scan run, which is the value the rollup must copy.
func runEngineOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, host uuid.UUID) string {
	t.Helper()
	var got *string
	if err := pool.QueryRow(ctx, `
		SELECT engine_version FROM scan_runs
		 WHERE host_id = $1 AND status = 'completed'
		 ORDER BY finished_at DESC NULLS LAST, id DESC LIMIT 1`, host).Scan(&got); err != nil {
		t.Fatalf("read run engine: %v", err)
	}
	if got == nil {
		return ""
	}
	return *got
}
