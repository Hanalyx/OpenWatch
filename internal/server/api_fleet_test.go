// @spec api-fleet-observability
//
// AC traceability (this file):
//   AC-01  TestAPI_Fleet_Score_MixedPassFail_ReturnsFraction
//   AC-02  TestAPI_Fleet_Score_EmptyFleet_ZeroNotError
//   AC-03  TestAPI_Fleet_Liveness_FourBucketsSumToActiveHosts
//   AC-04  TestAPI_Fleet_TopFailingRules_OrderedDescByCount
//   AC-05  TestAPI_Fleet_TopFailingHosts_OrderedDescByCount
//   AC-06  TestAPI_Fleet_RecentChanges_OrderedDescByOccurred
//   AC-07  TestAPI_Fleet_RecentChanges_SinceCursorFilters
//   AC-08  TestAPI_Fleet_RecentChanges_MalformedSince_Returns400
//   AC-09  TestAPI_Fleet_Limit_Overflow_Returns400
//   AC-10  TestAPI_Fleet_Limit_Negative_Returns400
//   AC-11  TestAPI_Fleet_Anonymous_Returns403
//   AC-12  TestAPI_Fleet_ViewerSession_HappyPath
//   AC-13  TestFleetHandlers_NoSQL_NoPoolAccess (in fleet_source_test.go)
//   AC-14  TestAPI_Fleet_Score_FrameworkFilter (v1.1.0)
//   AC-15  TestAPI_Fleet_TopFailingRules_FrameworkFilter (v1.1.0)
//   AC-16  TestAPI_Fleet_RecentChanges_FrameworkFilter (v1.1.0)
//   AC-17  TestAPI_Fleet_Score_EmptyFrameworkParam_SameAsNoParam (v1.1.0)
//   AC-18  TestAPI_Fleet_NonGET_Returns405 (renumbered from v1.0.0 AC-14)

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/db/corpustest"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/specfixture"
	"github.com/Hanalyx/openwatch/internal/version"
)

// ---------------------------------------------------------------------
// Seed helpers (Slice B tables)
// ---------------------------------------------------------------------

func seedFleetHost(t *testing.T, pool *pgxpool.Pool, createdBy uuid.UUID) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO hosts (id, hostname, ip_address, created_by)
		 VALUES ($1, $2, $3::inet, $4)`,
		id, "fleet-"+id.String(), "192.0.2.10", createdBy)
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	return id
}

func seedFleetRuleState(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status string) {
	t.Helper()
	seedFleetRuleStateWithFrameworks(t, pool, hostID, ruleID, status, nil)
}

// seedFleetRuleStateWithFrameworks variant lets a test attach a
// framework_refs JSONB so v1.1.0/v1.2.0 ?framework= filter ACs can be
// exercised. frameworks=nil → '{}'::jsonb (the legacy default).
func seedFleetRuleStateWithFrameworks(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status string, frameworks map[string]string) {
	t.Helper()
	now := time.Now().UTC()
	scanID := corpustest.CurrentRun(t, pool, hostID)
	refsJSON := []byte("{}")
	if len(frameworks) > 0 {
		var err error
		refsJSON, err = json.Marshal(frameworks)
		if err != nil {
			t.Fatalf("marshal framework refs: %v", err)
		}
	}
	_, err := pool.Exec(context.Background(), `
		INSERT INTO host_rule_state
			(host_id, rule_id, current_status, severity,
			 last_checked_at, check_count, last_scan_id, evidence,
			 framework_refs, first_seen_at, last_changed_at)
		VALUES ($1, $2, $3, 'medium', $4, 1, $5, '{}'::jsonb, $6::jsonb, $4, $4)`,
		hostID, ruleID, status, now, scanID, refsJSON,
	)
	if err != nil {
		t.Fatalf("seed rule_state: %v", err)
	}
}

func seedFleetLiveness(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, status string) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO host_liveness (host_id, reachability_status, last_probe_at)
		VALUES ($1, $2, now())`, hostID, status)
	if err != nil {
		t.Fatalf("seed liveness: %v", err)
	}
}

func seedFleetTransaction(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status, changeKind string, occurredAt time.Time) uuid.UUID {
	return seedFleetTransactionWithFrameworks(t, pool, hostID, ruleID, status, changeKind, occurredAt, nil)
}

func seedFleetTransactionWithFrameworks(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status, changeKind string, occurredAt time.Time, frameworks map[string]string) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	scanID, _ := uuid.NewV7()
	refsJSON := []byte("{}")
	if len(frameworks) > 0 {
		var err error
		refsJSON, err = json.Marshal(frameworks)
		if err != nil {
			t.Fatalf("marshal framework refs: %v", err)
		}
	}
	_, err := pool.Exec(context.Background(), `
		INSERT INTO transactions
			(id, host_id, rule_id, scan_id, status, severity,
			 change_kind, evidence, framework_refs, occurred_at)
		VALUES ($1, $2, $3, $4, $5, 'medium', $6, '{}'::jsonb, $7::jsonb, $8)`,
		id, hostID, ruleID, scanID, status, changeKind, refsJSON, occurredAt,
	)
	if err != nil {
		t.Fatalf("seed transaction: %v", err)
	}
	return id
}

// firstSeededUserID reads back the viewer user the API server fixture
// creates. We need it as the FK for seeded hosts.
func firstSeededUserID(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(context.Background(),
		`SELECT id FROM users LIMIT 1`).Scan(&id)
	if err != nil {
		t.Fatalf("read seeded user: %v", err)
	}
	return id
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

// @ac AC-01
// AC-01: GET /fleet/score on mixed pass/fail fleet returns the right
// fraction + total in the typed schema.
func TestAPI_Fleet_Score_MixedPassFail_ReturnsFraction(t *testing.T) {
	t.Run("api-fleet-observability/AC-01", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		user := firstSeededUserID(t, pool)
		h1 := seedFleetHost(t, pool, user)
		h2 := seedFleetHost(t, pool, user)
		seedFleetRuleState(t, pool, h1, "rule.a", "pass")
		seedFleetRuleState(t, pool, h1, "rule.b", "pass")
		seedFleetRuleState(t, pool, h1, "rule.c", "fail")
		seedFleetRuleState(t, pool, h2, "rule.a", "pass")
		seedFleetRuleState(t, pool, h2, "rule.b", "fail")

		req := asRole(t, "GET", url+"/api/v1/fleet/score", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, b)
		}
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		// Decoded into a map first, so the ABSENCE of the removed keys can be
		// asserted. A typed struct would silently ignore them.
		var keys map[string]any
		if err := json.Unmarshal(raw, &keys); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for _, gone := range []string{"passing_fraction", "total_evaluations"} {
			if _, present := keys[gone]; present {
				t.Errorf("%s is still in the response; it is removed with no alias, so a "+
					"client reading it must fail rather than receive a different quantity", gone)
			}
		}
		var body struct {
			ScorePct          *float64 `json:"score_pct"`
			HostsScored       int      `json:"hosts_scored"`
			HostsWithoutScore int      `json:"hosts_without_score"`
			HostsTotal        int      `json:"hosts_total"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("decode typed: %v", err)
		}
		// Host A: 2 of 3 verdicts = 66.666...; host B: 1 of 2 = 50. Their mean
		// is 58.333..., rounded ONCE to 58.3.
		//
		// Not 58.4. That is what rounding each host first produces: 66.7 and
		// 50.0 average to 58.35, which rounds up. compliance-scoring C-06
		// requires the mean over unrounded values, and this endpoint is where
		// the difference becomes visible to an operator.
		if body.ScorePct == nil || *body.ScorePct != 58.3 {
			t.Errorf("score_pct = %v, want 58.3 (equal-host mean, rounded once)", body.ScorePct)
		}
		if body.ScorePct != nil && *body.ScorePct == 58.4 {
			t.Error("score_pct = 58.4, each host rounded BEFORE averaging")
		}
		if body.ScorePct != nil && *body.ScorePct == 60 {
			t.Error("score_pct = 60, the pooled answer over every rule row")
		}
		if body.HostsScored != 2 || body.HostsWithoutScore != 0 || body.HostsTotal != 2 {
			t.Errorf("participation = %d scored / %d unscored / %d total, want 2/0/2",
				body.HostsScored, body.HostsWithoutScore, body.HostsTotal)
		}
	})
}

// @ac AC-02
// AC-02: an empty fleet returns 200 with NO score, not zero and not an error.
func TestAPI_Fleet_Score_EmptyFleetIsAbsentNotZero(t *testing.T) {
	t.Run("api-fleet-observability/AC-02", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		get := func() struct {
			ScorePct          *float64 `json:"score_pct"`
			HostsScored       int      `json:"hosts_scored"`
			HostsWithoutScore int      `json:"hosts_without_score"`
			HostsTotal        int      `json:"hosts_total"`
		} {
			t.Helper()
			req := asRole(t, "GET", url+"/api/v1/fleet/score", auth.RoleViewer, nil)
			resp := doReq(t, req)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				b, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, b)
			}
			var body struct {
				ScorePct          *float64 `json:"score_pct"`
				HostsScored       int      `json:"hosts_scored"`
				HostsWithoutScore int      `json:"hosts_without_score"`
				HostsTotal        int      `json:"hosts_total"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			return body
		}

		empty := get()
		if empty.ScorePct != nil {
			t.Errorf("empty fleet scored %v; it has no score at all", *empty.ScorePct)
		}
		if empty.HostsScored != 0 || empty.HostsWithoutScore != 0 || empty.HostsTotal != 0 {
			t.Errorf("empty fleet participation = %d/%d/%d, want zeros",
				empty.HostsScored, empty.HostsWithoutScore, empty.HostsTotal)
		}

		// The counterexample that gives the absence meaning. A fleet whose every
		// evaluated rule failed scores 0, and the removed passing_fraction
		// reported both cases as 0 with no way to tell them apart.
		user := firstSeededUserID(t, pool)
		h := seedFleetHost(t, pool, user)
		seedFleetRuleState(t, pool, h, "rule.a", "fail")
		seedFleetRuleState(t, pool, h, "rule.b", "fail")

		failed := get()
		if failed.ScorePct == nil {
			t.Fatal("a fleet that failed every rule has a real score of 0, not an absent one")
		}
		if *failed.ScorePct != 0 {
			t.Errorf("all-failing fleet scored %v, want 0", *failed.ScorePct)
		}
		if (empty.ScorePct == nil) == (failed.ScorePct == nil) {
			t.Error("an empty fleet and an all-failing fleet are indistinguishable on the wire")
		}
	})
}

// @ac AC-03
// AC-03: liveness rollup returns 4 buckets summing to active hosts.
func TestAPI_Fleet_Liveness_FourBucketsSumToActiveHosts(t *testing.T) {
	t.Run("api-fleet-observability/AC-03", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		user := firstSeededUserID(t, pool)
		hReach := seedFleetHost(t, pool, user)
		hUnreach := seedFleetHost(t, pool, user)
		hUnknown := seedFleetHost(t, pool, user)
		_ = seedFleetHost(t, pool, user) // never-probed
		_ = seedFleetHost(t, pool, user) // never-probed
		seedFleetLiveness(t, pool, hReach, "reachable")
		seedFleetLiveness(t, pool, hUnreach, "unreachable")
		seedFleetLiveness(t, pool, hUnknown, "unknown")

		req := asRole(t, "GET", url+"/api/v1/fleet/liveness", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, b)
		}
		var body struct {
			Reachable   int64 `json:"reachable"`
			Unreachable int64 `json:"unreachable"`
			Unknown     int64 `json:"unknown"`
			NeverProbed int64 `json:"never_probed"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if body.Reachable != 1 || body.Unreachable != 1 || body.Unknown != 1 || body.NeverProbed != 2 {
			t.Errorf("got %+v, want {1,1,1,2}", body)
		}
		if total := body.Reachable + body.Unreachable + body.Unknown + body.NeverProbed; total != 5 {
			t.Errorf("sum = %d, want 5", total)
		}
	})
}

// @ac AC-04
// AC-04: top-failing-rules ordered DESC by count; ?limit caps.
func TestAPI_Fleet_TopFailingRules_OrderedDescByCount(t *testing.T) {
	t.Run("api-fleet-observability/AC-04", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		user := firstSeededUserID(t, pool)
		h1, h2, h3 := seedFleetHost(t, pool, user), seedFleetHost(t, pool, user), seedFleetHost(t, pool, user)
		// rule.A on 3, rule.B on 2, rule.C on 1.
		seedFleetRuleState(t, pool, h1, "rule.A", "fail")
		seedFleetRuleState(t, pool, h2, "rule.A", "fail")
		seedFleetRuleState(t, pool, h3, "rule.A", "fail")
		seedFleetRuleState(t, pool, h1, "rule.B", "fail")
		seedFleetRuleState(t, pool, h2, "rule.B", "fail")
		seedFleetRuleState(t, pool, h1, "rule.C", "fail")
		seedFleetRuleState(t, pool, h1, "rule.D", "pass") // must NOT appear

		req := asRole(t, "GET", url+"/api/v1/fleet/top-failing-rules", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, b)
		}
		var body struct {
			Items []struct {
				RuleID           string `json:"rule_id"`
				FailingHostCount int64  `json:"failing_host_count"`
			} `json:"items"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if len(body.Items) != 3 {
			t.Fatalf("got %d items, want 3", len(body.Items))
		}
		if body.Items[0].RuleID != "rule.A" || body.Items[0].FailingHostCount != 3 {
			t.Errorf("Items[0] = %+v, want {rule.A,3}", body.Items[0])
		}
		if body.Items[2].FailingHostCount != 1 {
			t.Errorf("Items[2] = %+v, want last by count", body.Items[2])
		}

		// limit cap.
		req = asRole(t, "GET", url+"/api/v1/fleet/top-failing-rules?limit=2", auth.RoleViewer, nil)
		resp2 := doReq(t, req)
		defer resp2.Body.Close()
		_ = json.NewDecoder(resp2.Body).Decode(&body)
		if len(body.Items) != 2 {
			t.Errorf("with ?limit=2 got %d items", len(body.Items))
		}
	})
}

// @ac AC-05
// AC-05: top-failing-hosts ordered DESC by count.
func TestAPI_Fleet_TopFailingHosts_OrderedDescByCount(t *testing.T) {
	t.Run("api-fleet-observability/AC-05", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		user := firstSeededUserID(t, pool)
		worst := seedFleetHost(t, pool, user)
		mid := seedFleetHost(t, pool, user)
		best := seedFleetHost(t, pool, user)
		seedFleetRuleState(t, pool, worst, "rule.1", "fail")
		seedFleetRuleState(t, pool, worst, "rule.2", "fail")
		seedFleetRuleState(t, pool, worst, "rule.3", "fail")
		seedFleetRuleState(t, pool, mid, "rule.1", "fail")
		seedFleetRuleState(t, pool, mid, "rule.2", "fail")
		seedFleetRuleState(t, pool, best, "rule.1", "fail")

		req := asRole(t, "GET", url+"/api/v1/fleet/top-failing-hosts", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, b)
		}
		var body struct {
			Items []struct {
				HostID           string `json:"host_id"`
				FailingRuleCount int64  `json:"failing_rule_count"`
			} `json:"items"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if len(body.Items) != 3 {
			t.Fatalf("got %d items, want 3", len(body.Items))
		}
		if body.Items[0].HostID != worst.String() || body.Items[0].FailingRuleCount != 3 {
			t.Errorf("Items[0] = %+v, want {worst,3}", body.Items[0])
		}
	})
}

// @ac AC-06
// AC-06: recent-changes ordered DESC by occurred_at.
func TestAPI_Fleet_RecentChanges_OrderedDescByOccurred(t *testing.T) {
	t.Run("api-fleet-observability/AC-06", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		user := firstSeededUserID(t, pool)
		h := seedFleetHost(t, pool, user)
		t0 := time.Now().UTC().Truncate(time.Second)
		seedFleetTransaction(t, pool, h, "rule.a", "fail", "state_changed", t0)
		seedFleetTransaction(t, pool, h, "rule.b", "pass", "state_changed", t0.Add(time.Minute))
		seedFleetTransaction(t, pool, h, "rule.c", "fail", "first_seen", t0.Add(2*time.Minute))

		req := asRole(t, "GET", url+"/api/v1/fleet/recent-changes", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, b)
		}
		var body struct {
			Items []struct {
				RuleID     string    `json:"rule_id"`
				OccurredAt time.Time `json:"occurred_at"`
			} `json:"items"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if len(body.Items) != 3 {
			t.Fatalf("got %d items, want 3", len(body.Items))
		}
		if body.Items[0].RuleID != "rule.c" {
			t.Errorf("Items[0].RuleID = %q, want rule.c (newest)", body.Items[0].RuleID)
		}
		if body.Items[2].RuleID != "rule.a" {
			t.Errorf("Items[2].RuleID = %q, want rule.a (oldest)", body.Items[2].RuleID)
		}
	})
}

// @ac AC-07
// AC-07: ?since filters to strictly-newer rows.
func TestAPI_Fleet_RecentChanges_SinceCursorFilters(t *testing.T) {
	t.Run("api-fleet-observability/AC-07", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		user := firstSeededUserID(t, pool)
		h := seedFleetHost(t, pool, user)
		t0 := time.Now().UTC().Truncate(time.Second)
		seedFleetTransaction(t, pool, h, "old", "fail", "state_changed", t0)
		seedFleetTransaction(t, pool, h, "middle", "pass", "state_changed", t0.Add(time.Minute))
		seedFleetTransaction(t, pool, h, "new", "fail", "first_seen", t0.Add(2*time.Minute))

		since := t0.Format(time.RFC3339)
		req := asRole(t, "GET", url+"/api/v1/fleet/recent-changes?since="+since, auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		var body struct {
			Items []struct {
				RuleID string `json:"rule_id"`
			} `json:"items"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		// Strictly newer than t0 → middle + new (not "old").
		if len(body.Items) != 2 {
			t.Errorf("with since=t0 got %d items, want 2", len(body.Items))
		}
		for _, it := range body.Items {
			if it.RuleID == "old" {
				t.Errorf("rule.old should have been filtered out by since=t0")
			}
		}
	})
}

// @ac AC-08
// AC-08: malformed since returns 400.
func TestAPI_Fleet_RecentChanges_MalformedSince_Returns400(t *testing.T) {
	t.Run("api-fleet-observability/AC-08", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req := asRole(t, "GET", url+"/api/v1/fleet/recent-changes?since=not-a-date", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})
}

// @ac AC-09
// AC-09: ?limit=2000 (> MaxLimit) returns 400 pagination.limit_exceeded.
func TestAPI_Fleet_Limit_Overflow_Returns400(t *testing.T) {
	t.Run("api-fleet-observability/AC-09", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		for _, ep := range []string{
			"/api/v1/fleet/top-failing-rules?limit=2000",
			"/api/v1/fleet/top-failing-hosts?limit=2000",
			"/api/v1/fleet/recent-changes?limit=2000",
		} {
			req := asRole(t, "GET", url+ep, auth.RoleViewer, nil)
			resp := doReq(t, req)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("%s status = %d, want 400; body=%s", ep, resp.StatusCode, body)
				continue
			}
			if !strings.Contains(string(body), "pagination.limit_exceeded") {
				t.Errorf("%s body lacks pagination.limit_exceeded: %s", ep, body)
			}
		}
	})
}

// @ac AC-10
// AC-10: ?limit=-1 returns 400 pagination.limit_exceeded.
func TestAPI_Fleet_Limit_Negative_Returns400(t *testing.T) {
	t.Run("api-fleet-observability/AC-10", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req := asRole(t, "GET", url+"/api/v1/fleet/top-failing-rules?limit=-1", auth.RoleViewer, nil)
		resp := doReq(t, req)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		// oapi-codegen schema minimum=1 catches this first → either 400
		// from codegen, or 400 from our validatePaginatedLimit. Either
		// way 400 is correct.
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400; body=%s", resp.StatusCode, body)
		}
	})
}

// @ac AC-11
// AC-11: anonymous request returns 403 authz.permission_denied.
func TestAPI_Fleet_Anonymous_Returns403(t *testing.T) {
	t.Run("api-fleet-observability/AC-11", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		req, _ := http.NewRequest("GET", url+"/api/v1/fleet/score", nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 401 (anonymous); body=%s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "auth.required") {
			t.Errorf("body lacks auth.required: %s", b)
		}
	})
}

// @ac AC-12
// AC-12: viewer session (has system:read) → 200 on every fleet endpoint.
func TestAPI_Fleet_ViewerSession_HappyPath(t *testing.T) {
	t.Run("api-fleet-observability/AC-12", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		for _, ep := range []string{
			"/api/v1/fleet/score",
			"/api/v1/fleet/liveness",
			"/api/v1/fleet/top-failing-rules",
			"/api/v1/fleet/top-failing-hosts",
			"/api/v1/fleet/recent-changes",
		} {
			req := asRole(t, "GET", url+ep, auth.RoleViewer, nil)
			resp := doReq(t, req)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("%s status = %d, want 200; body=%s", ep, resp.StatusCode, body)
			}
		}
	})
}

// @ac AC-18
// AC-18 (renumbered from v1.0.0 AC-14 in v1.1.0): POST against a
// /fleet endpoint returns 405.
func TestAPI_Fleet_NonGET_Returns405(t *testing.T) {
	t.Run("api-fleet-observability/AC-18", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		for _, ep := range []string{
			"/api/v1/fleet/score",
			"/api/v1/fleet/liveness",
			"/api/v1/fleet/top-failing-rules",
			"/api/v1/fleet/top-failing-hosts",
			"/api/v1/fleet/recent-changes",
		} {
			req := asRole(t, "POST", url+ep, auth.RoleViewer, map[string]any{})
			resp := doReq(t, req)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("POST %s status = %d, want 405; body=%s", ep, resp.StatusCode, body)
			}
		}
	})
}

// @ac AC-14
// AC-14 (v1.1.0): GET /fleet/score?framework=cis_rhel9_v2.0.0 computes
// the score only from host_rule_state rows whose framework_refs
// contains "cis_rhel9_v2.0.0" as a top-level key.
func TestAPI_Fleet_Score_FrameworkFilter(t *testing.T) {
	t.Run("api-fleet-observability/AC-14", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		user := firstSeededUserID(t, pool)
		h := seedFleetHost(t, pool, user)
		// 3 rules in CIS, 1 also in STIG, 1 in STIG-only, 1 in neither.
		seedFleetRuleStateWithFrameworks(t, pool, h, "r.cis.pass", "pass",
			map[string]string{"cis_rhel9_v2.0.0": "1.1"})
		seedFleetRuleStateWithFrameworks(t, pool, h, "r.cis.fail", "fail",
			map[string]string{"cis_rhel9_v2.0.0": "1.2"})
		seedFleetRuleStateWithFrameworks(t, pool, h, "r.cis.stig.pass", "pass",
			map[string]string{"cis_rhel9_v2.0.0": "1.3", "stig_rhel9_v2r7": "ABC-1"})
		seedFleetRuleStateWithFrameworks(t, pool, h, "r.stig.fail", "fail",
			map[string]string{"stig_rhel9_v2r7": "ABC-2"})
		seedFleetRuleState(t, pool, h, "r.neither", "pass") // no framework refs

		req := asRole(t, "GET", url+"/api/v1/fleet/score?framework=cis_rhel9_v2.0.0", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d; body=%s", resp.StatusCode, b)
		}
		var body struct {
			ScorePct *float64 `json:"score_pct"`
			Envelope struct {
				Lens string `json:"lens"`
			} `json:"envelope"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		// CIS rules: 2 pass, 1 fail on ONE host, so the equal-host mean is that
		// host's own score, 66.7.
		if body.ScorePct == nil || *body.ScorePct != 66.7 {
			t.Errorf("score_pct = %v, want 66.7 (CIS only)", body.ScorePct)
		}
		// The envelope echoes the lens AS REQUESTED. A specific corpus key stays
		// a specific corpus key rather than being reported as its family, so the
		// response names the exact rule set the number was computed over.
		if body.Envelope.Lens != "cis_rhel9_v2.0.0" {
			t.Errorf("envelope lens = %q, want %q; the number must name what it measured",
				body.Envelope.Lens, "cis_rhel9_v2.0.0")
		}
	})
}

// @ac AC-15
// AC-15 (v1.1.0): GET /fleet/top-failing-rules?framework=stig_rhel9_v2r7
// returns only rules mapped to STIG.
func TestAPI_Fleet_TopFailingRules_FrameworkFilter(t *testing.T) {
	t.Run("api-fleet-observability/AC-15", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		user := firstSeededUserID(t, pool)
		h1 := seedFleetHost(t, pool, user)
		h2 := seedFleetHost(t, pool, user)
		seedFleetRuleStateWithFrameworks(t, pool, h1, "rule.cis-only", "fail",
			map[string]string{"cis_rhel9_v2.0.0": "1.1"})
		seedFleetRuleStateWithFrameworks(t, pool, h2, "rule.cis-only", "fail",
			map[string]string{"cis_rhel9_v2.0.0": "1.1"})
		seedFleetRuleStateWithFrameworks(t, pool, h1, "rule.stig", "fail",
			map[string]string{"stig_rhel9_v2r7": "X-1"})

		req := asRole(t, "GET", url+"/api/v1/fleet/top-failing-rules?framework=stig_rhel9_v2r7", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		var body struct {
			Items []struct {
				RuleID string `json:"rule_id"`
			} `json:"items"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if len(body.Items) != 1 || body.Items[0].RuleID != "rule.stig" {
			t.Errorf("expected only rule.stig, got %+v", body.Items)
		}
	})
}

// @ac AC-16
// AC-16 (v1.1.0): GET /fleet/recent-changes?framework=cis_rhel9_v2.0.0
// returns only transactions whose framework_refs contains that key.
func TestAPI_Fleet_RecentChanges_FrameworkFilter(t *testing.T) {
	t.Run("api-fleet-observability/AC-16", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		user := firstSeededUserID(t, pool)
		h := seedFleetHost(t, pool, user)
		t0 := time.Now().UTC().Truncate(time.Second)
		seedFleetTransactionWithFrameworks(t, pool, h, "rule.cis", "fail", "state_changed", t0,
			map[string]string{"cis_rhel9_v2.0.0": "1.1"})
		seedFleetTransactionWithFrameworks(t, pool, h, "rule.stig", "pass", "state_changed", t0.Add(time.Minute),
			map[string]string{"stig_rhel9_v2r7": "X-1"})

		req := asRole(t, "GET", url+"/api/v1/fleet/recent-changes?framework=cis_rhel9_v2.0.0", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		var body struct {
			Items []struct {
				RuleID string `json:"rule_id"`
			} `json:"items"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if len(body.Items) != 1 || body.Items[0].RuleID != "rule.cis" {
			t.Errorf("expected only rule.cis, got %+v", body.Items)
		}
	})
}

// @ac AC-17
// AC-17 (v1.1.0): GET /fleet/score (no framework) and
// GET /fleet/score?framework= (empty value) both return the same
// unfiltered Score.
func TestAPI_Fleet_Score_EmptyFrameworkParam_SameAsNoParam(t *testing.T) {
	t.Run("api-fleet-observability/AC-17", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		user := firstSeededUserID(t, pool)
		h := seedFleetHost(t, pool, user)
		seedFleetRuleState(t, pool, h, "rule.a", "pass")
		seedFleetRuleState(t, pool, h, "rule.b", "fail")

		req := asRole(t, "GET", url+"/api/v1/fleet/score", auth.RoleViewer, nil)
		resp := doReq(t, req)
		b1, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		req = asRole(t, "GET", url+"/api/v1/fleet/score?framework=", auth.RoleViewer, nil)
		resp = doReq(t, req)
		b2, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if string(b1) != string(b2) {
			t.Errorf("?framework= empty differs from no-param: %s vs %s", b1, b2)
		}
	})
}

// @ac AC-19
// AC-19 (v1.2.0): the removed fields are gone and the envelope is complete.
//
// AC-32 checks the artifacts; this checks the RESPONSE. A field can be absent
// from the schema and still be emitted by a handler that builds its own map.
func TestAPI_Fleet_Score_EnvelopeAndRemovedFields(t *testing.T) {
	t.Run("api-fleet-observability/AC-19", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/api/fleet-observability.spec.yaml", "api-fleet-observability"), "AC-19")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		user := firstSeededUserID(t, pool)
		producer := in.Str("producer_engine_version")
		if producer == version.Kensa() {
			t.Fatalf("fixture engine %q equals this process's; the two must differ or an "+
				"envelope built from the serving process would pass", producer)
		}
		for _, h := range in.MapList("hosts") {
			id := seedFleetHost(t, pool, user)
			label := h.Str("id")
			for i := 0; i < h.Int("pass"); i++ {
				seedFleetRuleState(t, pool, id, fmt.Sprintf("%s.p%d", label, i), "pass")
			}
			for i := 0; i < h.Int("fail"); i++ {
				seedFleetRuleState(t, pool, id, fmt.Sprintf("%s.f%d", label, i), "fail")
			}
			// Stamp the PRODUCING run with a version no running process reports.
			if _, err := pool.Exec(context.Background(),
				`UPDATE scan_runs SET engine_version = $2 WHERE host_id = $1`,
				id, producer); err != nil {
				t.Fatalf("stamp producer engine: %v", err)
			}
			h.AllConsumed()
		}

		req := asRole(t, "GET", url+"/api/v1/fleet/score", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var keys map[string]any
		if err := json.Unmarshal(raw, &keys); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for _, raw := range exp.List("forbidden_keys") {
			name, _ := raw.(string)
			if _, present := keys[name]; present {
				t.Errorf("%s is still in the response body", name)
			}
		}

		var body struct {
			ScorePct          *float64 `json:"score_pct"`
			Passing           int64    `json:"passing"`
			Failing           int64    `json:"failing"`
			Skipped           int64    `json:"skipped"`
			Error             int64    `json:"error"`
			CoverageStatus    string   `json:"coverage_status"`
			CoveragePct       *float64 `json:"coverage_pct"`
			HostsScored       int      `json:"hosts_scored"`
			HostsWithoutScore int      `json:"hosts_without_score"`
			HostsTotal        int      `json:"hosts_total"`
			Envelope          struct {
				Lens                 string  `json:"lens"`
				FormulaVersion       *int    `json:"formula_version"`
				AggregationMethod    string  `json:"aggregation_method"`
				EngineVersion        *string `json:"engine_version"`
				EngineIdentityStatus string  `json:"engine_identity_status"`
				Engines              []struct {
					EngineVersion      string `json:"engine_version"`
					ContributorsScored int    `json:"contributors_scored"`
				} `json:"engines"`
				HostsWithoutEngineIdentity int     `json:"hosts_without_engine_identity"`
				CorpusIdentityStatus       string  `json:"corpus_identity_status"`
				Corpora                    []any   `json:"corpora"`
				HostsWithoutCorpusIdentity int     `json:"hosts_without_corpus_identity"`
				CorpusVersion              *string `json:"corpus_version"`
				CorpusDigest               *string `json:"corpus_digest"`
			} `json:"envelope"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("decode typed: %v", err)
		}

		if body.ScorePct == nil || *body.ScorePct != exp.Num("score_pct") {
			t.Errorf("score_pct = %v, want %v", body.ScorePct, exp.Num("score_pct"))
		}
		if body.HostsScored != exp.Int("hosts_scored") ||
			body.HostsWithoutScore != exp.Int("hosts_without_score") ||
			body.HostsTotal != exp.Int("hosts_total") {
			t.Errorf("participation = %d/%d/%d, want %d/%d/%d",
				body.HostsScored, body.HostsWithoutScore, body.HostsTotal,
				exp.Int("hosts_scored"), exp.Int("hosts_without_score"), exp.Int("hosts_total"))
		}

		// The outcome counts come from the same statement as the score, so they
		// describe the same fleet the number does.
		if body.Passing != int64(exp.Int("passing")) || body.Failing != int64(exp.Int("failing")) ||
			body.Skipped != int64(exp.Int("skipped")) || body.Error != int64(exp.Int("error")) {
			t.Errorf("counts = %d/%d/%d/%d, want %d/%d/%d/%d",
				body.Passing, body.Failing, body.Skipped, body.Error,
				exp.Int("passing"), exp.Int("failing"), exp.Int("skipped"), exp.Int("error"))
		}
		if body.CoverageStatus != exp.Str("coverage_status") {
			t.Errorf("coverage_status = %q, want %q", body.CoverageStatus, exp.Str("coverage_status"))
		}
		// C-07: the percentage exists if and only if the status is available. A
		// status announcing a number beside no number is the defect the whole
		// vocabulary exists to prevent.
		if body.CoveragePct == nil || *body.CoveragePct != exp.Num("coverage_pct") {
			t.Errorf("coverage_pct = %v, want %v beside status %q",
				body.CoveragePct, exp.Num("coverage_pct"), body.CoverageStatus)
		}

		e := body.Envelope
		if e.Lens != exp.Str("lens") {
			t.Errorf("lens = %q, want %q", e.Lens, exp.Str("lens"))
		}
		if e.FormulaVersion == nil || *e.FormulaVersion != exp.Int("formula_version") {
			t.Errorf("formula_version = %v, want %d", e.FormulaVersion, exp.Int("formula_version"))
		}
		if e.AggregationMethod != exp.Str("aggregation_method") {
			t.Errorf("aggregation_method = %q, want %q", e.AggregationMethod,
				exp.Str("aggregation_method"))
		}
		// The engine is COPIED from each host's scan run. These hosts have no
		// recorded engine, so nothing can be named and both scored hosts count
		// as lacking one. Reporting the serving process's version here is the
		// defect the copy exists to prevent.
		if e.EngineIdentityStatus != exp.Str("engine_identity_status") {
			t.Errorf("engine_identity_status = %q, want %q", e.EngineIdentityStatus,
				exp.Str("engine_identity_status"))
		}
		wantEngines := exp.MapList("engines")
		if len(e.Engines) != len(wantEngines) {
			t.Fatalf("engines = %v, want %d entries", e.Engines, len(wantEngines))
		}
		for i, w := range wantEngines {
			if e.Engines[i].EngineVersion != w.Str("engine_version") {
				t.Errorf("engines[%d].engine_version = %q, want %q", i,
					e.Engines[i].EngineVersion, w.Str("engine_version"))
			}
			// The COUNT is what a bare version list could not carry, and what
			// separates "everyone agreed" from "one host said this".
			if e.Engines[i].ContributorsScored != w.Int("contributors_scored") {
				t.Errorf("engines[%d].contributors_scored = %d, want %d", i,
					e.Engines[i].ContributorsScored, w.Int("contributors_scored"))
			}
			w.AllConsumed()
		}
		if e.HostsWithoutEngineIdentity != exp.Int("hosts_without_engine_identity") {
			t.Errorf("hosts_without_engine_identity = %d, want %d",
				e.HostsWithoutEngineIdentity, exp.Int("hosts_without_engine_identity"))
		}
		if e.EngineVersion == nil || *e.EngineVersion != exp.Str("engine_version") {
			t.Errorf("engine_version = %v, want %q", e.EngineVersion, exp.Str("engine_version"))
		}
		// The discriminating assertion. The serving process's own version is
		// what this reported before the copy.
		_ = exp.Str("forbidden_engine_version")
		if e.EngineVersion != nil && *e.EngineVersion == version.Kensa() {
			t.Errorf("engine_version = %q, the SERVING process's version rather than the "+
				"engine that produced the outcomes", version.Kensa())
		}
		// The counts must add up to the scored population.
		total := e.HostsWithoutEngineIdentity
		for _, en := range e.Engines {
			total += en.ContributorsScored
		}
		if total != body.HostsScored {
			t.Errorf("engine contributors sum to %d but %d hosts scored; the accounting must "+
				"reconcile", total, body.HostsScored)
		}
		// Until the scan engine can report which corpus it used, no host can
		// name one, so every SCORED host is counted as lacking an identity.
		if e.CorpusIdentityStatus != exp.Str("corpus_identity_status") {
			t.Errorf("corpus_identity_status = %q, want %q", e.CorpusIdentityStatus,
				exp.Str("corpus_identity_status"))
		}
		exp.EmptyList("corpora")
		if len(e.Corpora) != 0 {
			t.Errorf("corpora = %v, want empty; nothing can name a corpus yet", e.Corpora)
		}
		if e.HostsWithoutCorpusIdentity != exp.Int("hosts_without_corpus_identity") {
			t.Errorf("hosts_without_corpus_identity = %d, want %d",
				e.HostsWithoutCorpusIdentity, exp.Int("hosts_without_corpus_identity"))
		}
		exp.IsNull("corpus_version")
		exp.IsNull("corpus_digest")
		if e.CorpusVersion != nil || e.CorpusDigest != nil {
			t.Errorf("singular corpus fields = %v / %v, want both null with no identified corpus",
				e.CorpusVersion, e.CorpusDigest)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}
