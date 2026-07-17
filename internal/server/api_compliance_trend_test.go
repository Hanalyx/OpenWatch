// @spec api-compliance-trend
//
// AC traceability (DSN-gated like every api_*_test in this package):
//
//	AC-01  TestHostComplianceTrend_WindowAndShape
//	AC-02  TestComplianceTrend_RBACAndUnknownHost
//	AC-03  TestFleetComplianceTrend_AggregatesAndDeletedHosts
//	AC-04  TestComplianceTrend_DaysClamp
//	AC-05  TestHostComplianceTrend_FollowsOrgLens
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
)

// seedTrendSnapshot writes one posture_snapshots row daysAgo days back.
func seedTrendSnapshot(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID,
	daysAgo int, score float64, passing, failing int, critical bool) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO posture_snapshots
			(host_id, snapshot_date, passing, failing, skipped, error, total,
			 score_pct, has_critical_findings)
		VALUES ($1, current_date - $2::int, $3, $4, 0, 0, $3::int + $4::int, $5, $6)`,
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

type hostTrendResp struct {
	Days []struct {
		Date     string  `json:"date"`
		ScorePct float64 `json:"score_pct"`
		Passing  int     `json:"passing"`
		Failing  int     `json:"failing"`
		Total    int     `json:"total"`
	} `json:"days"`
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
		if oldest.ScorePct != 60 || oldest.Passing != 6 || oldest.Failing != 4 || oldest.Total != 10 {
			t.Errorf("oldest = %+v, want 60/6/4/10", oldest)
		}
		if newest.ScorePct != 80 || newest.Total != 10 {
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
				AvgScorePct   float64 `json:"avg_score_pct"`
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
		if d.Hosts != 2 || d.AvgScorePct != 70.0 || d.Failing != 6 || d.CriticalHosts != 1 {
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
		if status != http.StatusOK || len(body.Days) != 1 || body.Days[0].ScorePct != 88 {
			t.Errorf("org default stig: status=%d days=%+v, want the STIG series (88)", status, body.Days)
		}

		// Clear the org default -> trend falls back to all-rules (68).
		if _, err := store.SetCompliance(ctx,
			systemconfig.ComplianceConfig{DefaultFramework: ""}, user.String()); err != nil {
			t.Fatalf("clear org default: %v", err)
		}
		status, body = getHostTrend(t, url, hostID.String(), "")
		if status != http.StatusOK || len(body.Days) != 1 || body.Days[0].ScorePct != 68 {
			t.Errorf("no org default: status=%d days=%+v, want the all-rules series (68)", status, body.Days)
		}
	})
}
