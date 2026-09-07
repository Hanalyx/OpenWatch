// @spec api-compliance-trend
//
// AC traceability (DSN-gated like every api_*_test in this package):
//
//	AC-01  TestHostComplianceTrend_WindowAndShape
//	AC-02  TestComplianceTrend_RBACAndUnknownHost
//	AC-03  TestFleetComplianceTrend_AggregatesAndDeletedHosts
//	AC-04  TestComplianceTrend_DaysClamp
//	AC-05  TestHostComplianceTrend_FollowsOrgLens
//	AC-06  TestComplianceTrend_AbsentScoreDayOmitted
package server

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/specfixture"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
	"github.com/Hanalyx/openwatch/internal/version"
)

// seedTrendSnapshot writes one posture_snapshots row daysAgo days back.
func seedTrendSnapshot(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID,
	daysAgo int, score float64, passing, failing int, critical bool) {
	t.Helper()
	// Version-2 metadata, and the score must match the counts.
	//
	// A fixture mixing formula versions on one date now produces a point with
	// no score at all (system-posture-snapshots C-11), so a seeder that quietly
	// wrote legacy rows would make unrelated tests lose a day. The guard turns
	// a self-contradictory row into a failure here rather than a puzzling
	// absence three assertions later.
	if want := float64(passing) / float64(passing+failing) * 100; passing+failing > 0 &&
		math.Abs(want-score) > 0.05 {
		t.Fatalf("seed score %v does not match counts %d/%d, which produce %v",
			score, passing, failing, want)
	}
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

// seedTrendSnapshotFW writes a snapshot row for a specific framework series
// (framework="" is all-rules; a family id is that lens's series).
func seedTrendSnapshotFW(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID,
	daysAgo int, framework string, score float64, passing, failing int) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO posture_snapshots
			(host_id, snapshot_date, framework, passing, failing, skipped, error, total,
			 score_pct, has_critical_findings)
		VALUES ($1, current_date - $2::int, $3, $4, $5, 0, 0, $4::int + $5::int, $6, false)`,
		hostID, daysAgo, framework, passing, failing, score)
	if err != nil {
		t.Fatalf("seed snapshot fw: %v", err)
	}
}

type hostTrendDay struct {
	Date string `json:"date"`
	// Nullable, so a day whose rules produced no verdict says so rather
	// than reading as a genuine zero.
	ScorePct       *float64 `json:"score_pct"`
	FormulaStatus  string   `json:"formula_status"`
	FormulaVersion *int     `json:"formula_version"`
	Envelope       struct {
		Lens                 string  `json:"lens"`
		FormulaVersion       *int    `json:"formula_version"`
		AggregationMethod    string  `json:"aggregation_method"`
		EngineVersion        *string `json:"engine_version"`
		EngineIdentityStatus string  `json:"engine_identity_status"`
		Engines              []struct {
			EngineVersion      string `json:"engine_version"`
			ContributorsScored int    `json:"contributors_scored"`
		} `json:"engines"`
		HostsWithoutEngineIdentity int    `json:"hosts_without_engine_identity"`
		CorpusIdentityStatus       string `json:"corpus_identity_status"`
	} `json:"envelope"`
	Passing int `json:"passing"`
	Failing int `json:"failing"`
	Total   int `json:"total"`
}

type hostTrendResp struct {
	Days []hostTrendDay `json:"days"`
}

// dayScore reads a trend day's score, failing when it is absent. A helper
// returning 0 would erase the distinction the nullable field exists to make.
func dayScore(t *testing.T, v *float64, label string) float64 {
	t.Helper()
	if v == nil {
		t.Fatalf("%s: score_pct is null, want a value", label)
	}
	return *v
}

func getHostTrend(t *testing.T, url string, hostID, query string) (int, hostTrendResp) {
	t.Helper()
	req := asRole(t, "GET", url+"/api/v1/hosts/"+hostID+"/compliance/trend"+query,
		auth.RoleViewer, nil)
	resp := doReq(t, req)
	defer resp.Body.Close()
	var body hostTrendResp
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode trend: %v", err)
		}
	}
	return resp.StatusCode, body
}

// seedTrendSnapshotAbsent writes a snapshot for a day on which no rule produced
// a verdict, which is what the endpoints must not render as 0.0.
func seedTrendSnapshotAbsent(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, daysAgo int) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO posture_snapshots
			(host_id, snapshot_date, passing, failing, skipped, error, total,
			 score_pct, has_critical_findings, formula_version, aggregation_method,
			 engine_version, corpus_identity_status)
		VALUES ($1, current_date - $2::int, 0, 0, 12, 0, 12,
		        NULL, false, 2, 'none', 'v0.9.0', 'unavailable')`,
		hostID, daysAgo)
	if err != nil {
		t.Fatalf("seed absent-score snapshot: %v", err)
	}
}

// @ac AC-01
// AC-01: points come back oldest-first with full field round-trip;
// out-of-window rows excluded; no snapshots = empty array.
func TestHostComplianceTrend_WindowAndShape(t *testing.T) {
	t.Run("api-compliance-trend/AC-01", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		empty := seedHostForIntel(t, pool)

		seedTrendSnapshot(t, pool, hostID, 0, 80, 8, 2, false)
		seedTrendSnapshot(t, pool, hostID, 5, 60, 6, 4, true)
		seedTrendSnapshot(t, pool, hostID, 45, 10, 1, 9, true) // outside 30d

		status, body := getHostTrend(t, url, hostID.String(), "")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if len(body.Days) != 2 {
			t.Fatalf("days = %d, want 2 (45-day row excluded at default 30)", len(body.Days))
		}
		oldest, newest := body.Days[0], body.Days[1]
		if dayScore(t, oldest.ScorePct, "oldest") != 60 || oldest.Passing != 6 || oldest.Failing != 4 || oldest.Total != 10 {
			t.Errorf("oldest = %+v, want 60/6/4/10", oldest)
		}
		if dayScore(t, newest.ScorePct, "newest") != 80 || newest.Total != 10 {
			t.Errorf("newest = %+v, want score 80 total 10", newest)
		}
		if !(oldest.Date < newest.Date) {
			t.Errorf("ordering: %s !< %s, want oldest first", oldest.Date, newest.Date)
		}

		// No snapshots: empty array, never an error.
		status, body = getHostTrend(t, url, empty.String(), "")
		if status != http.StatusOK || len(body.Days) != 0 {
			t.Errorf("empty host: status=%d days=%d, want 200 with []", status, len(body.Days))
		}
	})
}

// @ac AC-02
// AC-02: unknown host 404s with hosts.not_found; anonymous rejected on
// both endpoints; viewer succeeds on both.
func TestComplianceTrend_RBACAndUnknownHost(t *testing.T) {
	t.Run("api-compliance-trend/AC-02", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		ghost := uuid.Must(uuid.NewV7())

		status, _ := getHostTrend(t, url, ghost.String(), "")
		if status != http.StatusNotFound {
			t.Errorf("ghost status = %d, want 404", status)
		}

		for _, p := range []string{
			"/api/v1/hosts/" + hostID.String() + "/compliance/trend",
			"/api/v1/fleet/compliance/trend",
		} {
			anon, _ := http.NewRequest("GET", url+p, nil)
			resp, err := http.DefaultClient.Do(anon)
			if err != nil {
				t.Fatalf("%s anon: %v", p, err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s anonymous = %d, want 401/403", p, resp.StatusCode)
			}

			ok := asRole(t, "GET", url+p, auth.RoleViewer, nil)
			okResp := doReq(t, ok)
			okResp.Body.Close()
			if okResp.StatusCode != http.StatusOK {
				t.Errorf("%s viewer = %d, want 200", p, okResp.StatusCode)
			}
		}
	})
}

// @ac AC-03
// AC-03: fleet aggregates per day; soft-deleted hosts excluded; empty
// fleet returns [].
func TestFleetComplianceTrend_AggregatesAndDeletedHosts(t *testing.T) {
	t.Run("api-compliance-trend/AC-03", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		a := seedHostForIntel(t, pool)
		b := seedHostForIntel(t, pool)
		seedTrendSnapshot(t, pool, a, 0, 80, 8, 2, false)
		seedTrendSnapshot(t, pool, b, 0, 60, 6, 4, true)

		ghost := seedHostForIntel(t, pool)
		seedTrendSnapshot(t, pool, ghost, 0, 0, 0, 99, true)
		if _, err := pool.Exec(context.Background(),
			`UPDATE hosts SET deleted_at = now() WHERE id = $1`, ghost); err != nil {
			t.Fatalf("soft delete: %v", err)
		}

		req := asRole(t, "GET", url+"/api/v1/fleet/compliance/trend", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var body struct {
			Days []struct {
				Date          string  `json:"date"`
				ScorePct      float64 `json:"score_pct"`
				Hosts         int     `json:"hosts"`
				Failing       int     `json:"failing"`
				CriticalHosts int     `json:"critical_hosts"`
			} `json:"days"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(body.Days) != 1 {
			t.Fatalf("days = %d, want 1", len(body.Days))
		}
		d := body.Days[0]
		if d.Hosts != 2 || d.ScorePct != 70.0 || d.Failing != 6 || d.CriticalHosts != 1 {
			t.Errorf("day = %+v, want hosts 2 avg 70 failing 6 critical 1 (ghost dropped)", d)
		}
	})
}

// @ac AC-04
// AC-04: the days window clamps (0 -> 1, 500 -> 90) and defaults to
// 30 - never a 4xx.
func TestComplianceTrend_DaysClamp(t *testing.T) {
	t.Run("api-compliance-trend/AC-04", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		seedTrendSnapshot(t, pool, hostID, 0, 80, 8, 2, false)  // today: inside every window
		seedTrendSnapshot(t, pool, hostID, 5, 70, 7, 3, false)  // outside days=1
		seedTrendSnapshot(t, pool, hostID, 45, 50, 5, 5, false) // inside 90, outside 30
		seedTrendSnapshot(t, pool, hostID, 89, 40, 4, 6, false) // inside the 90 cap

		// days=0 clamps to 1: only today's row.
		status, body := getHostTrend(t, url, hostID.String(), "?days=0")
		if status != http.StatusOK || len(body.Days) != 1 {
			t.Errorf("days=0: status=%d len=%d, want 200/1 (clamped to 1)", status, len(body.Days))
		}
		// days=500 clamps to 90: all four rows.
		status, body = getHostTrend(t, url, hostID.String(), "?days=500")
		if status != http.StatusOK || len(body.Days) != 4 {
			t.Errorf("days=500: status=%d len=%d, want 200/4 (clamped to 90)", status, len(body.Days))
		}
		// Default 30: today + the 5-day row.
		status, body = getHostTrend(t, url, hostID.String(), "")
		if status != http.StatusOK || len(body.Days) != 2 {
			t.Errorf("default: status=%d len=%d, want 200/2", status, len(body.Days))
		}
	})
}

// @ac AC-05
// AC-05: the trend follows the effective lens server-side — with the org
// default set to "stig", the host trend returns its STIG series, not
// all-rules; clearing the org default falls back to the all-rules series.
func TestHostComplianceTrend_FollowsOrgLens(t *testing.T) {
	t.Run("api-compliance-trend/AC-05", func(t *testing.T) {
		ctx := context.Background()
		url, pool := freshAPIServer(t)
		user := firstSeededUserID(t, pool)
		hostID := seedHostForIntel(t, pool)

		// Two series for today: STIG (88) and all-rules (68).
		seedTrendSnapshotFW(t, pool, hostID, 0, "stig", 88, 353, 32)
		seedTrendSnapshotFW(t, pool, hostID, 0, "", 68, 523, 106)

		store := systemconfig.NewStore(pool, audit.Emit)

		// Org default = stig -> trend follows STIG (88).
		if _, err := store.SetCompliance(ctx,
			systemconfig.ComplianceConfig{DefaultFramework: "stig"}, user.String()); err != nil {
			t.Fatalf("set org default: %v", err)
		}
		status, body := getHostTrend(t, url, hostID.String(), "")
		if status != http.StatusOK || len(body.Days) != 1 || dayScore(t, body.Days[0].ScorePct, "stig lens") != 88 {
			t.Errorf("org default stig: status=%d days=%+v, want the STIG series (88)", status, body.Days)
		}

		// Clear the org default -> trend falls back to all-rules (68).
		if _, err := store.SetCompliance(ctx,
			systemconfig.ComplianceConfig{DefaultFramework: ""}, user.String()); err != nil {
			t.Fatalf("clear org default: %v", err)
		}
		status, body = getHostTrend(t, url, hostID.String(), "")
		if status != http.StatusOK || len(body.Days) != 1 || dayScore(t, body.Days[0].ScorePct, "all rules") != 68 {
			t.Errorf("no org default: status=%d days=%+v, want the all-rules series (68)", status, body.Days)
		}
	})
}

// @ac AC-06
// AC-06: a day with no score APPEARS with a null score, never as 0.0.
//
// This inverts the interim rule it replaces. Omission was honest but silent: a
// day nothing could be measured looked identical to a day with no snapshot. Now
// the day is present, its score is null, and its counts explain the absence.
func TestComplianceTrend_AbsentScoreDayIsExplained(t *testing.T) {
	t.Run("api-compliance-trend/AC-06", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/api/compliance-trend.spec.yaml", "api-compliance-trend"), "AC-06")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		hostID := seedHostForIntel(t, pool)
		for _, d := range in.MapList("host_days") {
			if d.IsNullable("score_pct") {
				d.IsNull("score_pct")
				seedTrendSnapshotAbsent(t, pool, hostID, d.Int("days_ago"))
			} else {
				seedTrendSnapshot(t, pool, hostID, d.Int("days_ago"), d.Num("score_pct"), 7, 3, false)
			}
			d.AllConsumed()
		}

		status, body := getHostTrend(t, url, hostID.String(), "")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if len(body.Days) != exp.Int("host_days_returned") {
			t.Fatalf("days = %d, want %d; the scoreless day must APPEAR, with its score null",
				len(body.Days), exp.Int("host_days_returned"))
		}
		// Oldest first: the scored day is a day older than the scoreless one.
		scored, absent := body.Days[0], body.Days[1]
		if scored.ScorePct == nil || *scored.ScorePct != exp.Num("host_scored_day_score_pct") {
			t.Errorf("scored day score_pct = %v, want %v",
				scored.ScorePct, exp.Num("host_scored_day_score_pct"))
		}
		exp.IsNull("host_absent_day_score_pct")
		if absent.ScorePct != nil {
			t.Errorf("scoreless day score_pct = %v, want null", *absent.ScorePct)
		}
		// The discriminating assertion. A regression to the fabricated verdict
		// sends this exact value instead of null.
		bad := exp.Num("forbidden_host_score_pct")
		if absent.ScorePct != nil && *absent.ScorePct == bad {
			t.Errorf("scoreless day arrived with score_pct %v, the fabricated verdict", bad)
		}
		// Every day says which formula produced it. A host point can only be
		// identified or legacy_unknown; both seeded rows use the current one.
		for i, d := range body.Days {
			if d.FormulaStatus != "identified" {
				t.Errorf("day %d formula_status = %q, want identified", i, d.FormulaStatus)
			}
			if d.FormulaVersion == nil || *d.FormulaVersion != 2 {
				t.Errorf("day %d formula_version = %v, want 2 beside an identified status",
					i, d.FormulaVersion)
			}
		}

		// The fleet endpoint: a day with a mix reports the mean of the hosts
		// that scored, and a day on which NO host scored appears with a null
		// average rather than vanishing.
		other := seedHostForIntel(t, pool)
		seedTrendSnapshot(t, pool, other, 0, in.Num("fleet_extra_host_today_score_pct"), 9, 1, false)

		lone := seedHostForIntel(t, pool)
		seedTrendSnapshotAbsent(t, pool, lone, in.Int("fleet_all_unscored_day_days_ago"))

		req := asRole(t, "GET", url+"/api/v1/fleet/compliance/trend", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("fleet status = %d, want 200", resp.StatusCode)
		}
		var fleet struct {
			Days []struct {
				Date              string   `json:"date"`
				ScorePct          *float64 `json:"score_pct"`
				FormulaStatus     string   `json:"formula_status"`
				Hosts             int      `json:"hosts"`
				HostsScored       int      `json:"hosts_scored"`
				HostsWithoutScore int      `json:"hosts_without_score"`
			} `json:"days"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&fleet); err != nil {
			t.Fatalf("decode fleet: %v", err)
		}
		if !exp.Bool("fleet_today_present") {
			t.Fatal("fixture must claim today is present on the fleet endpoint")
		}
		var today *struct {
			Date              string   `json:"date"`
			ScorePct          *float64 `json:"score_pct"`
			FormulaStatus     string   `json:"formula_status"`
			Hosts             int      `json:"hosts"`
			HostsScored       int      `json:"hosts_scored"`
			HostsWithoutScore int      `json:"hosts_without_score"`
		}
		for i := range fleet.Days {
			if fleet.Days[i].Hosts == exp.Int("fleet_today_hosts") {
				today = &fleet.Days[i]
			}
		}
		if today == nil {
			t.Fatalf("no fleet day with %d hosts; got %+v", exp.Int("fleet_today_hosts"), fleet.Days)
		}
		if today.ScorePct == nil || *today.ScorePct != exp.Num("fleet_today_score_pct") {
			t.Errorf("score_pct = %v, want %v (mean of the hosts that scored)",
				today.ScorePct, exp.Num("fleet_today_score_pct"))
		}
		if bad := exp.Num("forbidden_fleet_score_pct"); today.ScorePct != nil &&
			*today.ScorePct == bad {
			t.Errorf("score_pct = %v, the answer produced by averaging the unscored host in as zero", bad)
		}
		if today.HostsScored != 1 || today.HostsWithoutScore != 1 {
			t.Errorf("today participation = %d scored / %d unscored, want 1/1",
				today.HostsScored, today.HostsWithoutScore)
		}

		// The day on which no host scored: PRESENT, with a null average.
		if !exp.Bool("fleet_all_unscored_day_present") {
			t.Fatal("fixture must claim the all-unscored day is present")
		}
		exp.IsNull("fleet_all_unscored_day_score_pct")
		absentDay := time.Now().UTC().AddDate(0, 0, -in.Int("fleet_all_unscored_day_days_ago")).
			Format("2006-01-02")
		var found bool
		for _, d := range fleet.Days {
			if d.Date != absentDay {
				continue
			}
			found = true
			if d.ScorePct != nil {
				t.Errorf("fleet day %s scored %v; no host scored that day", d.Date, *d.ScorePct)
			}
			if d.HostsScored != 0 || d.HostsWithoutScore != 1 {
				t.Errorf("fleet day %s participation = %d/%d, want 0 scored and 1 unscored",
					d.Date, d.HostsScored, d.HostsWithoutScore)
			}
		}
		if !found {
			t.Errorf("fleet day %s is missing; a day with snapshots and no score must appear "+
				"with a null average rather than be omitted", absentDay)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// seedTrendSnapshotLegacy writes a row the way a pre-redesign release did: a
// stored score and no formula version. Its counts are deliberately unrelated to
// the score, which is why a version-2 reader must not recompute from them.
func seedTrendSnapshotLegacy(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID,
	daysAgo int, score float64) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO posture_snapshots
			(host_id, snapshot_date, passing, failing, skipped, error, total,
			 score_pct, has_critical_findings)
		VALUES ($1, current_date - $2::int, 2, 3, 0, 0, 5, $3, false)`,
		hostID, daysAgo, score); err != nil {
		t.Fatalf("seed legacy snapshot: %v", err)
	}
}

// @ac AC-07
// AC-07: formula_status and formula_version travel together on every day.
//
// A version without its status cannot say whether a null means "predates the
// formula" or "the contributors disagreed", and those are different facts about
// the same missing number.
func TestComplianceTrend_FormulaStatusAndVersion(t *testing.T) {
	t.Run("api-compliance-trend/AC-07", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/api/compliance-trend.spec.yaml", "api-compliance-trend"), "AC-07")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		hostID := seedHostForIntel(t, pool)
		for _, d := range in.MapList("host_days") {
			switch d.Str("formula") {
			case "legacy":
				seedTrendSnapshotLegacy(t, pool, hostID, d.Int("days_ago"), d.Num("score_pct"))
			case "v2":
				p, f := d.Int("passing"), d.Int("failing")
				seedTrendSnapshot(t, pool, hostID, d.Int("days_ago"),
					float64(p)/float64(p+f)*100, p, f, false)
			default:
				t.Fatalf("fixture names formula %q, which this test does not seed", d.Str("formula"))
			}
			d.AllConsumed()
		}

		status, body := getHostTrend(t, url, hostID.String(), "")
		if status != http.StatusOK || len(body.Days) != 2 {
			t.Fatalf("status=%d days=%d, want 200 and 2", status, len(body.Days))
		}
		// Oldest first: the legacy day was seeded two days back.
		check := func(label string, got hostTrendDay, want *specfixture.Fields) {
			t.Helper()
			if got.FormulaStatus != want.Str("formula_status") {
				t.Errorf("%s formula_status = %q, want %q", label, got.FormulaStatus,
					want.Str("formula_status"))
			}
			if want.IsNullable("formula_version") {
				want.IsNull("formula_version")
				if got.FormulaVersion != nil {
					t.Errorf("%s formula_version = %d, want null beside a %q status",
						label, *got.FormulaVersion, got.FormulaStatus)
				}
			} else if got.FormulaVersion == nil || *got.FormulaVersion != want.Int("formula_version") {
				t.Errorf("%s formula_version = %v, want %d", label, got.FormulaVersion,
					want.Int("formula_version"))
			}
			if want.IsNullable("score_pct") {
				want.IsNull("score_pct")
				if got.ScorePct != nil {
					t.Errorf("%s score_pct = %v, want null", label, *got.ScorePct)
				}
			} else if got.ScorePct == nil || *got.ScorePct != want.Num("score_pct") {
				t.Errorf("%s score_pct = %v, want %v", label, got.ScorePct, want.Num("score_pct"))
			}
			want.AllConsumed()
		}
		check("legacy day", body.Days[0], exp.Map("host_legacy_day"))
		check("version-2 day", body.Days[1], exp.Map("host_v2_day"))

		// A host point can never be mixed: one snapshot row holds one formula.
		if exp.Bool("host_mixed_reachable") {
			t.Fatal("fixture claims a host point can be mixed; a snapshot row holds one formula")
		}
		for i, d := range body.Days {
			if d.FormulaStatus == "mixed" {
				t.Errorf("host day %d reported mixed, which is unreachable on a host point", i)
			}
		}

		// The fleet point is where versions can meet. Two hosts on the SAME day,
		// one legacy and one version 2.
		mixedDay := in.Map("fleet_mixed_day")
		seedTrendSnapshotLegacy(t, pool, seedHostForIntel(t, pool), mixedDay.Int("days_ago"), 40)
		seedTrendSnapshot(t, pool, seedHostForIntel(t, pool), mixedDay.Int("days_ago"), 80, 8, 2, false)
		mixedDay.AllConsumed()

		req := asRole(t, "GET", url+"/api/v1/fleet/compliance/trend", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		var fleet struct {
			Days []struct {
				Date           string   `json:"date"`
				ScorePct       *float64 `json:"score_pct"`
				FormulaStatus  string   `json:"formula_status"`
				FormulaVersion *int     `json:"formula_version"`
				Hosts          int      `json:"hosts"`
			} `json:"days"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&fleet); err != nil {
			t.Fatalf("decode fleet: %v", err)
		}
		wantMixed := exp.Map("fleet_mixed_day")
		today := time.Now().UTC().Format("2006-01-02")
		var found bool
		for _, d := range fleet.Days {
			if d.Date != today {
				continue
			}
			found = true
			if d.FormulaStatus != wantMixed.Str("formula_status") {
				t.Errorf("fleet mixed day formula_status = %q, want %q",
					d.FormulaStatus, wantMixed.Str("formula_status"))
			}
			wantMixed.IsNull("formula_version")
			if d.FormulaVersion != nil {
				t.Errorf("fleet mixed day formula_version = %d, want null", *d.FormulaVersion)
			}
			wantMixed.IsNull("score_pct")
			if d.ScorePct != nil {
				t.Errorf("fleet mixed day scored %v; two formulas measure different things "+
					"and their mean is a score under neither", *d.ScorePct)
			}
		}
		if !found {
			t.Fatalf("no fleet day for %s; a mixed day must APPEAR and say why it has no score", today)
		}
		wantMixed.AllConsumed()

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-08
// AC-08: a trend point's envelope reports what the snapshot recorded.
//
// The producing run is stamped with a version no running process reports, so an
// envelope built from the reader is visibly wrong rather than accidentally
// right. The legacy point is the other half: nothing recorded its formula or
// engine, and the envelope says so instead of filling in today's values.
func TestComplianceTrend_EnvelopeComesFromTheSnapshot(t *testing.T) {
	t.Run("api-compliance-trend/AC-08", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/api/compliance-trend.spec.yaml", "api-compliance-trend"), "AC-08")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		producer := in.Str("producer_engine_version")
		if producer == version.Kensa() {
			t.Fatalf("fixture engine %q equals this process's; the two must differ or an "+
				"envelope built from the reader would pass", producer)
		}

		hostID := seedHostForIntel(t, pool)
		v2 := in.Map("v2_day")
		p, f := v2.Int("passing"), v2.Int("failing")
		seedTrendSnapshot(t, pool, hostID, v2.Int("days_ago"),
			float64(p)/float64(p+f)*100, p, f, false)
		// Restamp the snapshot with the PRODUCING engine, which is what the
		// rollup copies from the scan run.
		if _, err := pool.Exec(ctx, `
			UPDATE posture_snapshots SET engine_version = $2
			 WHERE host_id = $1 AND snapshot_date = current_date`, hostID, producer); err != nil {
			t.Fatalf("stamp producer engine: %v", err)
		}
		v2.AllConsumed()

		legacy := in.Map("legacy_day")
		seedTrendSnapshotLegacy(t, pool, hostID, legacy.Int("days_ago"), legacy.Num("score_pct"))
		legacy.AllConsumed()

		status, body := getHostTrend(t, url, hostID.String(), "")
		if status != http.StatusOK || len(body.Days) != 2 {
			t.Fatalf("status=%d days=%d, want 200 and 2", status, len(body.Days))
		}
		// Oldest first: the legacy day was seeded a day back.
		legacyDay, v2Day := body.Days[0], body.Days[1]

		// The version-2 point names the PRODUCER.
		wantEngines := exp.List("v2_engines")
		if len(v2Day.Envelope.Engines) != len(wantEngines) {
			t.Fatalf("version-2 engines = %v, want %v", v2Day.Envelope.Engines, wantEngines)
		}
		if v2Day.Envelope.Engines[0].EngineVersion != exp.Str("v2_engine_version") {
			t.Errorf("version-2 engines = %v, want %q", v2Day.Envelope.Engines,
				exp.Str("v2_engine_version"))
		}
		if v2Day.Envelope.EngineVersion == nil ||
			*v2Day.Envelope.EngineVersion != exp.Str("v2_engine_version") {
			t.Errorf("version-2 engine_version = %v, want %q", v2Day.Envelope.EngineVersion,
				exp.Str("v2_engine_version"))
		}
		// The discriminating assertion: the serving process's own version.
		if v2Day.Envelope.EngineVersion != nil && *v2Day.Envelope.EngineVersion == version.Kensa() {
			t.Errorf("version-2 engine_version = %q, which is the SERVING process's version, "+
				"not the engine that produced the outcomes", version.Kensa())
		}
		if v2Day.Envelope.FormulaVersion == nil ||
			*v2Day.Envelope.FormulaVersion != exp.Int("v2_formula_version") {
			t.Errorf("version-2 formula_version = %v, want %d", v2Day.Envelope.FormulaVersion,
				exp.Int("v2_formula_version"))
		}

		// The legacy point records neither, and says so.
		exp.EmptyList("legacy_engines")
		if len(legacyDay.Envelope.Engines) != 0 {
			t.Errorf("legacy engines = %v, want empty; nothing recorded which engine produced "+
				"that day", legacyDay.Envelope.Engines)
		}
		exp.IsNull("legacy_engine_version")
		if legacyDay.Envelope.EngineVersion != nil {
			t.Errorf("legacy engine_version = %q, want null", *legacyDay.Envelope.EngineVersion)
		}
		exp.IsNull("legacy_formula_version")
		if legacyDay.Envelope.FormulaVersion != nil {
			t.Errorf("legacy formula_version = %d, want null", *legacyDay.Envelope.FormulaVersion)
		}

		for i, d := range body.Days {
			if d.Envelope.AggregationMethod != exp.Str("aggregation_method") {
				t.Errorf("day %d aggregation_method = %q, want %q; one host aggregates nothing",
					i, d.Envelope.AggregationMethod, exp.Str("aggregation_method"))
			}
			if d.Envelope.CorpusIdentityStatus != exp.Str("corpus_identity_status") {
				t.Errorf("day %d corpus_identity_status = %q, want %q",
					i, d.Envelope.CorpusIdentityStatus, exp.Str("corpus_identity_status"))
			}
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-09
// AC-09: the fleet point's envelope accounting reconciles with hosts_scored.
//
// One scored snapshot and one unscored one. The envelope counts contributors to
// a SCORE, so it must describe exactly one. It described two, because the total
// came from a count of snapshots lacking corpus provenance and that count
// includes snapshots with no score.
func TestFleetComplianceTrend_EnvelopeAccountingReconciles(t *testing.T) {
	t.Run("api-compliance-trend/AC-09", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/api/compliance-trend.spec.yaml", "api-compliance-trend"), "AC-09")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		scored := in.Map("scored_snapshot")
		p, f := scored.Int("passing"), scored.Int("failing")
		seedTrendSnapshot(t, pool, seedHostForIntel(t, pool), 0,
			float64(p)/float64(p+f)*100, p, f, false)
		scored.AllConsumed()

		// A scored snapshot whose corpus IS named. Without it, hosts_scored and
		// the missing-corpus count coincide and the two candidate totals are
		// indistinguishable.
		withCorpus := in.Map("scored_snapshot_with_corpus")
		cp, cf := withCorpus.Int("passing"), withCorpus.Int("failing")
		corpusHost := seedHostForIntel(t, pool)
		seedTrendSnapshot(t, pool, corpusHost, 0, float64(cp)/float64(cp+cf)*100, cp, cf, false)
		if _, err := pool.Exec(context.Background(), `
			UPDATE posture_snapshots
			   SET corpus_identity_status = 'identified', corpus_digest = $2
			 WHERE host_id = $1 AND snapshot_date = current_date`,
			corpusHost, withCorpus.Str("corpus_digest")); err != nil {
			t.Fatalf("name the corpus: %v", err)
		}
		withCorpus.AllConsumed()

		unscored := in.Map("unscored_snapshot")
		if unscored.Int("skipped") == 0 {
			t.Fatal("fixture must seed a snapshot with no verdict")
		}
		seedTrendSnapshotAbsent(t, pool, seedHostForIntel(t, pool), 0)
		unscored.AllConsumed()

		req := asRole(t, "GET", url+"/api/v1/fleet/compliance/trend", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var body struct {
			Days []struct {
				HostsScored       int `json:"hosts_scored"`
				HostsWithoutScore int `json:"hosts_without_score"`
				Envelope          struct {
					HostsWithoutCorpusIdentity int `json:"hosts_without_corpus_identity"`
					HostsWithoutEngineIdentity int `json:"hosts_without_engine_identity"`
					Engines                    []struct {
						ContributorsScored int `json:"contributors_scored"`
					} `json:"engines"`
				} `json:"envelope"`
			} `json:"days"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(body.Days) != 1 {
			t.Fatalf("fleet days = %d, want 1", len(body.Days))
		}
		d := body.Days[0]

		if d.HostsScored != exp.Int("hosts_scored") ||
			d.HostsWithoutScore != exp.Int("hosts_without_score") {
			t.Fatalf("participation = %d scored / %d unscored, want %d/%d",
				d.HostsScored, d.HostsWithoutScore,
				exp.Int("hosts_scored"), exp.Int("hosts_without_score"))
		}
		// The point of the criterion: the envelope describes the SCORED
		// population, not every snapshot on the day.
		if d.Envelope.HostsWithoutCorpusIdentity != exp.Int("hosts_without_corpus_identity") {
			t.Errorf("envelope hosts_without_corpus_identity = %d, want %d",
				d.Envelope.HostsWithoutCorpusIdentity, exp.Int("hosts_without_corpus_identity"))
		}
		if bad := exp.Int("forbidden_hosts_without_corpus_identity"); d.Envelope.HostsWithoutCorpusIdentity == bad {
			t.Errorf("envelope claims %d contributors while the point says %d hosts scored; the "+
				"unscored snapshot contributed to no score", bad, d.HostsScored)
		}
		if !exp.Bool("engine_contributors_sum_to_hosts_scored") {
			t.Fatal("fixture must require the engine counts to reconcile")
		}
		total := d.Envelope.HostsWithoutEngineIdentity
		for _, e := range d.Envelope.Engines {
			total += e.ContributorsScored
		}
		if total != d.HostsScored {
			t.Errorf("engine contributors sum to %d but %d hosts scored", total, d.HostsScored)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}
