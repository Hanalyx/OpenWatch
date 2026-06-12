// @spec api-host-compliance
//
// AC traceability (DSN-gated like every api_*_test in this package;
// AC-03's catalog half lives in internal/kensa/catalog_test.go):
//
//	AC-01  TestHostFailedRules_OrderingShapeAndLimitClamp
//	AC-02  TestHostFailedRules_FrameworkFilterAndControlIDs
//	AC-03  TestHostFailedRules_NoCatalog_FallsBackToRuleID
//	AC-04  TestHostFailedRules_UnknownHost404
//	AC-05  TestHostFailedRules_RBAC_AnonymousRejected_ViewerAllowed
//	AC-06  TestHostFailedRulesHandler_NeverReferencesSensitiveColumn
//	AC-07  TestFleetScanQueue_CountsQueuedAndRunningOnly
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/auth"
)

// seedRuleState inserts one host_rule_state row. Column set per
// migration 0012 + the transactionlog writer: severity nullable,
// framework_refs JSONB defaulting to {}, first/last timestamps NOT NULL.
func seedRuleState(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID,
	ruleID, status string, severity any, checkedAt time.Time, checkCount int, frameworkRefs string) {
	t.Helper()
	if frameworkRefs == "" {
		frameworkRefs = "{}"
	}
	scanID := uuid.Must(uuid.NewV7())
	_, err := pool.Exec(context.Background(), `
		INSERT INTO host_rule_state
			(host_id, rule_id, current_status, severity, last_checked_at,
			 check_count, last_scan_id, framework_refs,
			 first_seen_at, last_changed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $5, $5)`,
		hostID, ruleID, status, severity, checkedAt, checkCount, scanID, frameworkRefs)
	if err != nil {
		t.Fatalf("seed host_rule_state %s: %v", ruleID, err)
	}
}

type failedRulesResp struct {
	TotalFailing int64 `json:"total_failing"`
	Rules        []struct {
		RuleID        string    `json:"rule_id"`
		Title         string    `json:"title"`
		Category      string    `json:"category"`
		Severity      string    `json:"severity"`
		ControlIDs    []string  `json:"control_ids"`
		LastCheckedAt time.Time `json:"last_checked_at"`
		CheckCount    int       `json:"check_count"`
	} `json:"rules"`
}

func getFailedRules(t *testing.T, url string, role auth.RoleID, hostID, query string) (int, failedRulesResp) {
	t.Helper()
	req := asRole(t, "GET", url+"/api/v1/hosts/"+hostID+"/compliance/failed-rules"+query, role, nil)
	resp := doReq(t, req)
	defer resp.Body.Close()
	var body failedRulesResp
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode failed-rules: %v", err)
		}
	}
	return resp.StatusCode, body
}

// @ac AC-01
// AC-01: failing rows come back severity-ordered (critical > high >
// medium > low > unset; last_checked_at DESC within a band), passing
// rows are excluded, total_failing is the pre-limit count, and an
// out-of-range limit is clamped rather than rejected.
func TestHostFailedRules_OrderingShapeAndLimitClamp(t *testing.T) {
	t.Run("api-host-compliance/AC-01", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		base := time.Now().UTC().Truncate(time.Second)

		seedRuleState(t, pool, hostID, "r-low", "fail", "low", base, 3, "")
		seedRuleState(t, pool, hostID, "r-crit", "fail", "critical", base, 5, "")
		seedRuleState(t, pool, hostID, "r-high-old", "fail", "high", base.Add(-time.Hour), 2, "")
		seedRuleState(t, pool, hostID, "r-high-new", "fail", "high", base, 4, "")
		seedRuleState(t, pool, hostID, "r-med", "fail", "medium", base, 1, "")
		seedRuleState(t, pool, hostID, "r-none", "fail", nil, base, 7, "")
		seedRuleState(t, pool, hostID, "r-pass", "pass", "critical", base, 9, "")

		status, body := getFailedRules(t, url, auth.RoleViewer, hostID.String(), "")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if body.TotalFailing != 6 {
			t.Errorf("total_failing = %d, want 6 (pass row excluded)", body.TotalFailing)
		}
		wantOrder := []string{"r-crit", "r-high-new", "r-high-old", "r-med", "r-low", "r-none"}
		if len(body.Rules) != len(wantOrder) {
			t.Fatalf("rules len = %d, want %d", len(body.Rules), len(wantOrder))
		}
		for i, want := range wantOrder {
			if body.Rules[i].RuleID != want {
				t.Errorf("rules[%d] = %s, want %s (severity ordering)", i, body.Rules[i].RuleID, want)
			}
		}
		// Shape: check_count and last_checked_at round-trip.
		if body.Rules[0].CheckCount != 5 {
			t.Errorf("r-crit check_count = %d, want 5", body.Rules[0].CheckCount)
		}
		if !body.Rules[0].LastCheckedAt.Equal(base) {
			t.Errorf("r-crit last_checked_at = %v, want %v", body.Rules[0].LastCheckedAt, base)
		}
		if body.Rules[5].Severity != "" {
			t.Errorf("r-none severity = %q, want empty", body.Rules[5].Severity)
		}

		// limit truncates the page but not the total.
		status, body = getFailedRules(t, url, auth.RoleViewer, hostID.String(), "?limit=2")
		if status != http.StatusOK || len(body.Rules) != 2 || body.TotalFailing != 6 {
			t.Errorf("limit=2: status=%d len=%d total=%d, want 200/2/6",
				status, len(body.Rules), body.TotalFailing)
		}
		if body.Rules[0].RuleID != "r-crit" || body.Rules[1].RuleID != "r-high-new" {
			t.Errorf("limit=2 page = %s,%s; want r-crit,r-high-new",
				body.Rules[0].RuleID, body.Rules[1].RuleID)
		}

		// Out-of-range limit is clamped (200 -> 100), never a 400.
		status, body = getFailedRules(t, url, auth.RoleViewer, hostID.String(), "?limit=200")
		if status != http.StatusOK || len(body.Rules) != 6 {
			t.Errorf("limit=200: status=%d len=%d, want 200/6 (clamped, not rejected)",
				status, len(body.Rules))
		}
	})
}

// @ac AC-02
// AC-02: ?framework= filters to rows whose framework_refs contains the
// key and projects that framework's control ids; without it,
// control_ids is empty.
func TestHostFailedRules_FrameworkFilterAndControlIDs(t *testing.T) {
	t.Run("api-host-compliance/AC-02", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		base := time.Now().UTC().Truncate(time.Second)

		seedRuleState(t, pool, hostID, "fw-a", "fail", "high", base, 1,
			`{"stig-rhel9-v2r7": ["V-230221", "V-230222"], "cis-rhel9-v2.0.0": ["1.1.1"]}`)
		seedRuleState(t, pool, hostID, "fw-b", "fail", "high", base, 1,
			`{"cis-rhel9-v2.0.0": ["5.2.1"]}`)

		status, body := getFailedRules(t, url, auth.RoleViewer, hostID.String(),
			"?framework=stig-rhel9-v2r7")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if body.TotalFailing != 1 || len(body.Rules) != 1 {
			t.Fatalf("filtered total=%d len=%d, want 1/1", body.TotalFailing, len(body.Rules))
		}
		if body.Rules[0].RuleID != "fw-a" {
			t.Errorf("rule = %s, want fw-a", body.Rules[0].RuleID)
		}
		got := body.Rules[0].ControlIDs
		if len(got) != 2 || got[0] != "V-230221" || got[1] != "V-230222" {
			t.Errorf("control_ids = %v, want [V-230221 V-230222]", got)
		}

		// Without ?framework=: both rows, control_ids empty.
		status, body = getFailedRules(t, url, auth.RoleViewer, hostID.String(), "")
		if status != http.StatusOK || body.TotalFailing != 2 {
			t.Fatalf("unfiltered: status=%d total=%d, want 200/2", status, body.TotalFailing)
		}
		for _, ru := range body.Rules {
			if len(ru.ControlIDs) != 0 {
				t.Errorf("%s control_ids = %v, want empty without ?framework=", ru.RuleID, ru.ControlIDs)
			}
		}
	})
}

// @ac AC-03
// AC-03 (endpoint half): the test harness wires no RuleCatalog, so
// title falls back to the rule id and category to "" — the endpoint
// works without the kensa-rules corpus.
func TestHostFailedRules_NoCatalog_FallsBackToRuleID(t *testing.T) {
	t.Run("api-host-compliance/AC-03", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		seedRuleState(t, pool, hostID, "uncataloged_rule", "fail", "medium",
			time.Now().UTC(), 1, "")

		status, body := getFailedRules(t, url, auth.RoleViewer, hostID.String(), "")
		if status != http.StatusOK || len(body.Rules) != 1 {
			t.Fatalf("status=%d len=%d, want 200/1", status, len(body.Rules))
		}
		if body.Rules[0].Title != "uncataloged_rule" {
			t.Errorf("title = %q, want the rule id fallback", body.Rules[0].Title)
		}
		if body.Rules[0].Category != "" {
			t.Errorf("category = %q, want empty fallback", body.Rules[0].Category)
		}
	})
}

// @ac AC-04
// AC-04: unknown host id returns 404 hosts.not_found.
func TestHostFailedRules_UnknownHost404(t *testing.T) {
	t.Run("api-host-compliance/AC-04", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		ghost := uuid.Must(uuid.NewV7())

		req := asRole(t, "GET", url+"/api/v1/hosts/"+ghost.String()+"/compliance/failed-rules",
			auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
		var env struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&env)
		if env.Error.Code != "hosts.not_found" {
			t.Errorf("code = %q, want hosts.not_found", env.Error.Code)
		}
	})
}

// @ac AC-05
// AC-05: anonymous callers are rejected; a viewer (host:read) succeeds.
func TestHostFailedRules_RBAC_AnonymousRejected_ViewerAllowed(t *testing.T) {
	t.Run("api-host-compliance/AC-05", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)

		// Anonymous: no session cookie.
		req, _ := http.NewRequest("GET",
			url+"/api/v1/hosts/"+hostID.String()+"/compliance/failed-rules", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("anon GET: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			t.Errorf("anonymous status = %d, want 401/403", resp.StatusCode)
		}

		status, _ := getFailedRules(t, url, auth.RoleViewer, hostID.String(), "")
		if status != http.StatusOK {
			t.Errorf("viewer status = %d, want 200 (host:read suffices)", status)
		}
	})
}

// @ac AC-06
// AC-06: source inspection — the failed-rules handler file never
// references the host_rule_state stored check-output column, so the
// sensitive payload cannot reach the response.
func TestHostFailedRulesHandler_NeverReferencesSensitiveColumn(t *testing.T) {
	t.Run("api-host-compliance/AC-06", func(t *testing.T) {
		_, file, _, _ := runtime.Caller(0)
		handlerPath := filepath.Join(filepath.Dir(file), "host_compliance_handler.go")
		b, err := os.ReadFile(handlerPath)
		if err != nil {
			t.Fatalf("read handler source: %v", err)
		}
		// The column name, matched as a standalone token (any case).
		forbidden := regexp.MustCompile(`(?i)\bevidence\b`)
		if forbidden.MatchString(string(b)) {
			t.Errorf("host_compliance_handler.go references the sensitive host_rule_state column — it must never be selected or named (C-02)")
		}
	})
}

// @ac AC-07
// AC-07: /fleet/scan-queue counts queued + running scan_runs only;
// terminal rows are excluded; anonymous callers are rejected.
func TestFleetScanQueue_CountsQueuedAndRunningOnly(t *testing.T) {
	t.Run("api-host-compliance/AC-07", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)

		seed := func(status string) {
			t.Helper()
			id := uuid.Must(uuid.NewV7())
			_, err := pool.Exec(context.Background(), `
				INSERT INTO scan_runs (id, host_id, trigger_source, status)
				VALUES ($1, $2, 'scheduled', $3)`, id, hostID, status)
			if err != nil {
				t.Fatalf("seed scan_run %s: %v", status, err)
			}
		}
		seed("queued")
		seed("queued")
		seed("running")
		seed("completed")
		seed("failed")

		req := asRole(t, "GET", url+"/api/v1/fleet/scan-queue", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var body struct {
			Queued  int64 `json:"queued"`
			Running int64 `json:"running"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.Queued != 2 || body.Running != 1 {
			t.Errorf("scan-queue = {queued:%d running:%d}, want {queued:2 running:1} (terminal rows excluded)",
				body.Queued, body.Running)
		}

		// Anonymous rejected.
		anonReq, _ := http.NewRequest("GET", url+"/api/v1/fleet/scan-queue", nil)
		anonResp, err := http.DefaultClient.Do(anonReq)
		if err != nil {
			t.Fatalf("anon GET: %v", err)
		}
		anonResp.Body.Close()
		if anonResp.StatusCode != http.StatusUnauthorized && anonResp.StatusCode != http.StatusForbidden {
			t.Errorf("anonymous status = %d, want 401/403", anonResp.StatusCode)
		}
	})
}
