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
//	AC-08  TestHostComplianceLens_ShapeAndReconciliation
//	       TestLensCategories_SortFailingDescThenCategoryAsc (non-DSN)
//	AC-09  TestHostComplianceLens_FrameworkFilterAndControlIDProjection
//	AC-10  TestHostComplianceLens_ScanContextLatestCompletedRun
//	AC-11  TestHostComplianceFrameworks_ListingAndEmptyWhenUnscanned
//	AC-12  TestHostComplianceLens_UnknownHost404AndAnonymousRejected
//	AC-13  TestHostComplianceLensHandler_NeverReferencesSensitiveColumn
//	AC-14  TestHostComplianceFrameworks_ScoresAndOverallAggregate
//	AC-15  TestHostComplianceLens_DurationAndDescription
//	       TestFirstSentence_TrimsCatalogProse (non-DSN)
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/server/api"
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

// ---------------------------------------------------------------------------
// Compliance lens (spec v1.1.0) — GET /hosts/{id}/compliance (+ /frameworks).
// ---------------------------------------------------------------------------

type lensResp struct {
	ScanContext struct {
		LastScanAt      *time.Time `json:"last_scan_at"`
		ScanID          *string    `json:"scan_id"`
		PolicyVersion   string     `json:"policy_version"`
		DurationSeconds *int       `json:"duration_seconds"`
	} `json:"scan_context"`
	Summary struct {
		Passing  int64   `json:"passing"`
		Failing  int64   `json:"failing"`
		Skipped  int64   `json:"skipped"`
		Error    int64   `json:"error"`
		Total    int64   `json:"total"`
		ScorePct float64 `json:"score_pct"`
	} `json:"summary"`
	Categories []struct {
		Category string `json:"category"`
		Passing  int64  `json:"passing"`
		Failing  int64  `json:"failing"`
		Total    int64  `json:"total"`
	} `json:"categories"`
	Rules []struct {
		RuleID        string    `json:"rule_id"`
		Title         string    `json:"title"`
		Category      string    `json:"category"`
		Severity      string    `json:"severity"`
		Status        string    `json:"status"`
		Description   string    `json:"description"`
		ControlIDs    []string  `json:"control_ids"`
		LastCheckedAt time.Time `json:"last_checked_at"`
	} `json:"rules"`
}

func getLens(t *testing.T, url string, role auth.RoleID, hostID, query string) (int, lensResp) {
	t.Helper()
	req := asRole(t, "GET", url+"/api/v1/hosts/"+hostID+"/compliance"+query, role, nil)
	resp := doReq(t, req)
	defer resp.Body.Close()
	var body lensResp
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode lens: %v", err)
		}
	}
	return resp.StatusCode, body
}

// reconcileLens recomputes the per-status counts from the rules array
// and compares them to the summary (spec C-05).
func reconcileLens(t *testing.T, body lensResp) {
	t.Helper()
	var pass, fail, skip, errs int64
	for _, ru := range body.Rules {
		switch ru.Status {
		case "pass":
			pass++
		case "fail":
			fail++
		case "skipped":
			skip++
		case "error":
			errs++
		}
	}
	s := body.Summary
	if s.Passing != pass || s.Failing != fail || s.Skipped != skip ||
		s.Error != errs || s.Total != int64(len(body.Rules)) {
		t.Errorf("summary %+v does not reconcile with rules (pass=%d fail=%d skip=%d err=%d len=%d)",
			s, pass, fail, skip, errs, len(body.Rules))
	}
}

// @ac AC-08
// AC-08: the lens returns every status, severity-ordered with rule_id
// ASC as the tiebreaker; summary reconciles with the rules array;
// score_pct is passing/total to one decimal; categories bucket
// catalog-unknown rules under "uncategorized".
func TestHostComplianceLens_ShapeAndReconciliation(t *testing.T) {
	t.Run("api-host-compliance/AC-08", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		base := time.Now().UTC().Truncate(time.Second)

		seedRuleState(t, pool, hostID, "r2-crit", "fail", "critical", base, 1, "")
		seedRuleState(t, pool, hostID, "b-high", "fail", "high", base, 1, "")
		seedRuleState(t, pool, hostID, "a-high", "fail", "high", base.Add(-time.Hour), 1, "")
		seedRuleState(t, pool, hostID, "m-pass", "pass", "medium", base, 1, "")
		seedRuleState(t, pool, hostID, "l-pass", "pass", "low", base, 1, "")
		seedRuleState(t, pool, hostID, "s-skip", "skipped", nil, base, 1, "")
		seedRuleState(t, pool, hostID, "e-err", "error", "medium", base, 1, "")

		status, body := getLens(t, url, auth.RoleViewer, hostID.String(), "")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}

		// Every status present, severity-ordered then rule_id ASC
		// (a-high before b-high despite the older last_checked_at).
		wantOrder := []string{"r2-crit", "a-high", "b-high", "e-err", "m-pass", "l-pass", "s-skip"}
		if len(body.Rules) != len(wantOrder) {
			t.Fatalf("rules len = %d, want %d (every status, not just fail)", len(body.Rules), len(wantOrder))
		}
		for i, want := range wantOrder {
			if body.Rules[i].RuleID != want {
				t.Errorf("rules[%d] = %s, want %s (severity then rule_id ASC)", i, body.Rules[i].RuleID, want)
			}
		}
		if body.Rules[0].Status != "fail" || body.Rules[4].Status != "pass" ||
			body.Rules[6].Status != "skipped" {
			t.Errorf("statuses not carried through: %s/%s/%s",
				body.Rules[0].Status, body.Rules[4].Status, body.Rules[6].Status)
		}

		// Summary: 2 pass / 3 fail / 1 skipped / 1 error of 7.
		s := body.Summary
		if s.Passing != 2 || s.Failing != 3 || s.Skipped != 1 || s.Error != 1 || s.Total != 7 {
			t.Errorf("summary = %+v, want 2/3/1/1 of 7", s)
		}
		// score_pct = round(2/7*1000)/10 = 28.6.
		if s.ScorePct != 28.6 {
			t.Errorf("score_pct = %v, want 28.6", s.ScorePct)
		}
		reconcileLens(t, body)

		// No catalog wired in the harness: every rule falls back to the
		// shared "uncategorized" bucket, title falls back to rule_id.
		if body.Rules[0].Title != "r2-crit" || body.Rules[0].Category != "uncategorized" {
			t.Errorf("fallbacks = title %q category %q, want rule id / uncategorized",
				body.Rules[0].Title, body.Rules[0].Category)
		}
		if len(body.Categories) != 1 {
			t.Fatalf("categories len = %d, want 1 (single uncategorized bucket)", len(body.Categories))
		}
		c := body.Categories[0]
		if c.Category != "uncategorized" || c.Passing != 2 || c.Failing != 3 || c.Total != 7 {
			t.Errorf("category bucket = %+v, want uncategorized 2/3 of 7", c)
		}
	})
}

// @ac AC-08
// AC-08 (sorting half, no DSN needed): category buckets sort failing
// DESC then category ASC, aggregating the same rows the lens returns.
func TestLensCategories_SortFailingDescThenCategoryAsc(t *testing.T) {
	t.Run("api-host-compliance/AC-08", func(t *testing.T) {
		rules := []api.HostComplianceRule{
			{RuleId: "r1", Category: "ssh", Status: "fail"},
			{RuleId: "r2", Category: "ssh", Status: "pass"},
			{RuleId: "r3", Category: "auditd", Status: "fail"},
			{RuleId: "r4", Category: "auditd", Status: "fail"},
			{RuleId: "r5", Category: "kernel", Status: "fail"},
			{RuleId: "r6", Category: "boot", Status: "pass"},
			{RuleId: "r7", Category: "boot", Status: "skipped"},
		}
		got := lensCategoriesFromRules(rules)
		wantOrder := []string{"auditd", "kernel", "ssh", "boot"}
		if len(got) != len(wantOrder) {
			t.Fatalf("categories len = %d, want %d", len(got), len(wantOrder))
		}
		for i, want := range wantOrder {
			if got[i].Category != want {
				t.Errorf("categories[%d] = %s, want %s (failing DESC then category ASC)",
					i, got[i].Category, want)
			}
		}
		if got[0].Failing != 2 || got[0].Total != 2 {
			t.Errorf("auditd = %+v, want failing=2 total=2", got[0])
		}
		if got[3].Passing != 1 || got[3].Failing != 0 || got[3].Total != 2 {
			t.Errorf("boot = %+v, want passing=1 failing=0 total=2 (skipped counts in total)", got[3])
		}
	})
}

// @ac AC-09
// AC-09: ?framework= filters every section, recounts the summary
// under the lens, and projects the framework's FULL control-id array
// (multi-control mapping pinned); without it, control_ids is empty.
func TestHostComplianceLens_FrameworkFilterAndControlIDProjection(t *testing.T) {
	t.Run("api-host-compliance/AC-09", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		base := time.Now().UTC().Truncate(time.Second)

		seedRuleState(t, pool, hostID, "fwl-a", "fail", "high", base, 1,
			`{"stig-rhel9-v2r7": ["V-230221", "V-230222"], "cis-rhel9-v2.0.0": ["1.1.1"]}`)
		seedRuleState(t, pool, hostID, "fwl-b", "pass", "medium", base, 1,
			`{"stig-rhel9-v2r7": ["V-230300"]}`)
		seedRuleState(t, pool, hostID, "fwl-c", "fail", "high", base, 1,
			`{"cis-rhel9-v2.0.0": ["5.2.1"]}`)

		status, body := getLens(t, url, auth.RoleViewer, hostID.String(),
			"?framework=stig-rhel9-v2r7")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if len(body.Rules) != 2 {
			t.Fatalf("filtered rules len = %d, want 2 (fwl-c excluded)", len(body.Rules))
		}
		if body.Rules[0].RuleID != "fwl-a" || body.Rules[1].RuleID != "fwl-b" {
			t.Errorf("rules = %s,%s; want fwl-a,fwl-b", body.Rules[0].RuleID, body.Rules[1].RuleID)
		}
		// Multi-control projection: BOTH stig controls, stored order.
		got := body.Rules[0].ControlIDs
		if len(got) != 2 || got[0] != "V-230221" || got[1] != "V-230222" {
			t.Errorf("fwl-a control_ids = %v, want [V-230221 V-230222]", got)
		}
		if len(body.Rules[1].ControlIDs) != 1 || body.Rules[1].ControlIDs[0] != "V-230300" {
			t.Errorf("fwl-b control_ids = %v, want [V-230300]", body.Rules[1].ControlIDs)
		}
		// Summary recounted under the lens: 1 pass + 1 fail of 2, 50%.
		s := body.Summary
		if s.Passing != 1 || s.Failing != 1 || s.Total != 2 || s.ScorePct != 50.0 {
			t.Errorf("filtered summary = %+v, want 1/1 of 2 at 50.0", s)
		}
		reconcileLens(t, body)

		// Without ?framework=: all 3 rows, control_ids empty everywhere.
		status, body = getLens(t, url, auth.RoleViewer, hostID.String(), "")
		if status != http.StatusOK || len(body.Rules) != 3 || body.Summary.Total != 3 {
			t.Fatalf("unfiltered: status=%d len=%d total=%d, want 200/3/3",
				status, len(body.Rules), body.Summary.Total)
		}
		for _, ru := range body.Rules {
			if len(ru.ControlIDs) != 0 {
				t.Errorf("%s control_ids = %v, want empty without ?framework=", ru.RuleID, ru.ControlIDs)
			}
		}
		reconcileLens(t, body)
	})
}

// @ac AC-10
// AC-10: scan_context carries the latest COMPLETED run only; newer
// failed/queued runs never appear; never-scanned hosts get nulls.
func TestHostComplianceLens_ScanContextLatestCompletedRun(t *testing.T) {
	t.Run("api-host-compliance/AC-10", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)

		// Never scanned: nulls and empty policy_version, not an error.
		status, body := getLens(t, url, auth.RoleViewer, hostID.String(), "")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if body.ScanContext.LastScanAt != nil || body.ScanContext.ScanID != nil ||
			body.ScanContext.PolicyVersion != "" {
			t.Errorf("never-scanned scan_context = %+v, want nulls", body.ScanContext)
		}

		base := time.Now().UTC().Truncate(time.Second)
		seedRun := func(runStatus, policy string, finishedAt any) uuid.UUID {
			t.Helper()
			id := uuid.Must(uuid.NewV7())
			_, err := pool.Exec(context.Background(), `
				INSERT INTO scan_runs (id, host_id, trigger_source, status, finished_at, policy_version)
				VALUES ($1, $2, 'scheduled', $3, $4, NULLIF($5, ''))`,
				id, hostID, runStatus, finishedAt, policy)
			if err != nil {
				t.Fatalf("seed scan_run %s: %v", runStatus, err)
			}
			return id
		}
		seedRun("completed", "v1", base.Add(-2*time.Hour))
		latestCompleted := seedRun("completed", "v2", base.Add(-time.Hour))
		seedRun("failed", "v3", base) // newer but failed — never wins
		seedRun("queued", "v4", nil)  // active — never wins

		status, body = getLens(t, url, auth.RoleViewer, hostID.String(), "")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if body.ScanContext.ScanID == nil || *body.ScanContext.ScanID != latestCompleted.String() {
			t.Errorf("scan_id = %v, want %s (latest completed)", body.ScanContext.ScanID, latestCompleted)
		}
		if body.ScanContext.LastScanAt == nil || !body.ScanContext.LastScanAt.Equal(base.Add(-time.Hour)) {
			t.Errorf("last_scan_at = %v, want %v", body.ScanContext.LastScanAt, base.Add(-time.Hour))
		}
		if body.ScanContext.PolicyVersion != "v2" {
			t.Errorf("policy_version = %q, want v2", body.ScanContext.PolicyVersion)
		}
	})
}

// @ac AC-11
// AC-11: /compliance/frameworks lists distinct framework_refs keys
// with mapped-rule counts, ordered by id; unscanned hosts get [].
func TestHostComplianceFrameworks_ListingAndEmptyWhenUnscanned(t *testing.T) {
	t.Run("api-host-compliance/AC-11", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		scanned := seedHostForIntel(t, pool)
		unscanned := seedHostForIntel(t, pool)
		base := time.Now().UTC().Truncate(time.Second)

		seedRuleState(t, pool, scanned, "fwk-a", "fail", "high", base, 1,
			`{"stig-rhel9-v2r7": ["V-1"], "cis-rhel9-v2.0.0": ["1.1"]}`)
		seedRuleState(t, pool, scanned, "fwk-b", "pass", "low", base, 1,
			`{"cis-rhel9-v2.0.0": ["1.2"]}`)
		seedRuleState(t, pool, scanned, "fwk-c", "pass", "low", base, 1, "{}")

		type fwResp struct {
			Frameworks []struct {
				FrameworkID string `json:"framework_id"`
				RuleCount   int64  `json:"rule_count"`
			} `json:"frameworks"`
		}
		fetch := func(hostID string) (int, fwResp) {
			t.Helper()
			req := asRole(t, "GET", url+"/api/v1/hosts/"+hostID+"/compliance/frameworks",
				auth.RoleViewer, nil)
			resp := doReq(t, req)
			defer resp.Body.Close()
			var body fwResp
			if resp.StatusCode == http.StatusOK {
				if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
					t.Fatalf("decode frameworks: %v", err)
				}
			}
			return resp.StatusCode, body
		}

		status, body := fetch(scanned.String())
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if len(body.Frameworks) != 2 {
			t.Fatalf("frameworks len = %d, want 2", len(body.Frameworks))
		}
		// Ordered by framework id: cis... < stig...
		if body.Frameworks[0].FrameworkID != "cis-rhel9-v2.0.0" || body.Frameworks[0].RuleCount != 2 {
			t.Errorf("frameworks[0] = %+v, want cis-rhel9-v2.0.0 x2", body.Frameworks[0])
		}
		if body.Frameworks[1].FrameworkID != "stig-rhel9-v2r7" || body.Frameworks[1].RuleCount != 1 {
			t.Errorf("frameworks[1] = %+v, want stig-rhel9-v2r7 x1", body.Frameworks[1])
		}

		// Unscanned host: empty list, never an error.
		status, body = fetch(unscanned.String())
		if status != http.StatusOK || len(body.Frameworks) != 0 {
			t.Errorf("unscanned: status=%d len=%d, want 200 with empty frameworks",
				status, len(body.Frameworks))
		}
	})
}

// @ac AC-12
// AC-12: both lens endpoints 404 (hosts.not_found) on unknown ids,
// reject anonymous callers, and accept a viewer (host:read).
func TestHostComplianceLens_UnknownHost404AndAnonymousRejected(t *testing.T) {
	t.Run("api-host-compliance/AC-12", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		ghost := uuid.Must(uuid.NewV7())

		paths := []string{"/compliance", "/compliance/frameworks"}
		for _, p := range paths {
			// Unknown host: 404 hosts.not_found.
			req := asRole(t, "GET", url+"/api/v1/hosts/"+ghost.String()+p, auth.RoleViewer, nil)
			resp := doReq(t, req)
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s ghost status = %d, want 404", p, resp.StatusCode)
			}
			var env struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&env)
			resp.Body.Close()
			if env.Error.Code != "hosts.not_found" {
				t.Errorf("%s code = %q, want hosts.not_found", p, env.Error.Code)
			}

			// Anonymous: rejected.
			anonReq, _ := http.NewRequest("GET", url+"/api/v1/hosts/"+hostID.String()+p, nil)
			anonResp, err := http.DefaultClient.Do(anonReq)
			if err != nil {
				t.Fatalf("%s anon GET: %v", p, err)
			}
			anonResp.Body.Close()
			if anonResp.StatusCode != http.StatusUnauthorized &&
				anonResp.StatusCode != http.StatusForbidden {
				t.Errorf("%s anonymous status = %d, want 401/403", p, anonResp.StatusCode)
			}

			// Viewer (host:read): succeeds.
			okReq := asRole(t, "GET", url+"/api/v1/hosts/"+hostID.String()+p, auth.RoleViewer, nil)
			okResp := doReq(t, okReq)
			okResp.Body.Close()
			if okResp.StatusCode != http.StatusOK {
				t.Errorf("%s viewer status = %d, want 200", p, okResp.StatusCode)
			}
		}
	})
}

// @ac AC-13
// AC-13: source inspection extended to the lens handler — the file
// never references the host_rule_state stored check-output column.
func TestHostComplianceLensHandler_NeverReferencesSensitiveColumn(t *testing.T) {
	t.Run("api-host-compliance/AC-13", func(t *testing.T) {
		_, file, _, _ := runtime.Caller(0)
		handlerPath := filepath.Join(filepath.Dir(file), "host_compliance_lens_handler.go")
		b, err := os.ReadFile(handlerPath)
		if err != nil {
			t.Fatalf("read lens handler source: %v", err)
		}
		forbidden := regexp.MustCompile(`(?i)\bevidence\b`)
		if forbidden.MatchString(string(b)) {
			t.Errorf("host_compliance_lens_handler.go references the sensitive host_rule_state column — it must never be selected or named (C-02)")
		}
	})
}

// @ac AC-14
// AC-14 (v1.2.0): each frameworks[] item carries passing/failing and
// score_pct over the rows holding that key; overall (framework_id
// "all") aggregates ALL host rows so the All-rules chip needs no
// second request.
func TestHostComplianceFrameworks_ScoresAndOverallAggregate(t *testing.T) {
	t.Run("api-host-compliance/AC-14", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		empty := seedHostForIntel(t, pool)
		base := time.Now().UTC().Truncate(time.Second)

		// cis: 2 rows (1 pass, 1 fail) -> 50%. stig: 1 row (fail) -> 0%.
		// unmapped: 1 pass row counted ONLY by overall.
		seedRuleState(t, pool, hostID, "fwk-a", "fail", "high", base, 1,
			`{"cis-rhel9-v2.0.0": ["1.1"], "stig-rhel9-v2r7": ["V-1"]}`)
		seedRuleState(t, pool, hostID, "fwk-b", "pass", "low", base, 1,
			`{"cis-rhel9-v2.0.0": ["1.2"]}`)
		seedRuleState(t, pool, hostID, "fwk-c", "pass", "low", base, 1, "{}")
		seedRuleState(t, pool, hostID, "fwk-d", "skipped", "low", base, 1, "{}")

		type fwItem struct {
			FrameworkID string  `json:"framework_id"`
			RuleCount   int64   `json:"rule_count"`
			Passing     int64   `json:"passing"`
			Failing     int64   `json:"failing"`
			ScorePct    float64 `json:"score_pct"`
		}
		type fwResp struct {
			Frameworks []fwItem `json:"frameworks"`
			Overall    fwItem   `json:"overall"`
		}
		fetch := func(id string) fwResp {
			t.Helper()
			req := asRole(t, "GET", url+"/api/v1/hosts/"+id+"/compliance/frameworks",
				auth.RoleViewer, nil)
			resp := doReq(t, req)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			var body fwResp
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode frameworks: %v", err)
			}
			return body
		}

		body := fetch(hostID.String())
		if len(body.Frameworks) != 2 {
			t.Fatalf("frameworks len = %d, want 2", len(body.Frameworks))
		}
		cis, stig := body.Frameworks[0], body.Frameworks[1]
		if cis.FrameworkID != "cis-rhel9-v2.0.0" || cis.RuleCount != 2 ||
			cis.Passing != 1 || cis.Failing != 1 || cis.ScorePct != 50 {
			t.Errorf("cis item = %+v, want 2 rules / 1 pass / 1 fail / 50%%", cis)
		}
		if stig.FrameworkID != "stig-rhel9-v2r7" || stig.RuleCount != 1 ||
			stig.Passing != 0 || stig.Failing != 1 || stig.ScorePct != 0 {
			t.Errorf("stig item = %+v, want 1 rule / 0 pass / 1 fail / 0%%", stig)
		}
		// Overall: 4 rows total, 2 pass, 1 fail -> 50.0%.
		if body.Overall.FrameworkID != "all" || body.Overall.RuleCount != 4 ||
			body.Overall.Passing != 2 || body.Overall.Failing != 1 ||
			body.Overall.ScorePct != 50 {
			t.Errorf("overall = %+v, want all / 4 rules / 2 pass / 1 fail / 50%%", body.Overall)
		}

		// Zero-row host: overall zeros, never an error (no divide-by-zero).
		emptyBody := fetch(empty.String())
		if emptyBody.Overall.RuleCount != 0 || emptyBody.Overall.ScorePct != 0 {
			t.Errorf("empty-host overall = %+v, want zero counts and score", emptyBody.Overall)
		}
	})
}

// @ac AC-15
// AC-15 (v1.2.0, endpoint half): duration_seconds = finished_at -
// started_at of the latest completed run, null when started_at is
// missing. The harness wires no RuleCatalog, so description is empty —
// the field can only carry catalog prose.
func TestHostComplianceLens_DurationAndDescription(t *testing.T) {
	t.Run("api-host-compliance/AC-15", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		hostID := seedHostForIntel(t, pool)
		base := time.Now().UTC().Truncate(time.Second)
		seedRuleState(t, pool, hostID, "fwk-a", "pass", "low", base, 1, "{}")

		seedRun := func(started any, finished time.Time, policy string) {
			t.Helper()
			_, err := pool.Exec(context.Background(), `
				INSERT INTO scan_runs (id, host_id, trigger_source, status,
				                       started_at, finished_at, policy_version)
				VALUES ($1, $2, 'scheduled', 'completed', $3, $4, $5)`,
				uuid.Must(uuid.NewV7()), hostID, started, finished, policy)
			if err != nil {
				t.Fatalf("seed scan_run: %v", err)
			}
		}

		// Latest completed run has both timestamps: 85s apart.
		seedRun(base.Add(-85*time.Second), base, "v2")
		status, body := getLens(t, url, auth.RoleViewer, hostID.String(), "")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if body.ScanContext.DurationSeconds == nil || *body.ScanContext.DurationSeconds != 85 {
			t.Errorf("duration_seconds = %v, want 85", body.ScanContext.DurationSeconds)
		}

		// A newer completed run without started_at: duration goes null.
		seedRun(nil, base.Add(time.Minute), "v3")
		_, body = getLens(t, url, auth.RoleViewer, hostID.String(), "")
		if body.ScanContext.DurationSeconds != nil {
			t.Errorf("duration_seconds = %v, want null without started_at",
				*body.ScanContext.DurationSeconds)
		}

		// No catalog wired: description is empty for every rule.
		for _, r := range body.Rules {
			if r.Description != "" {
				t.Errorf("rule %s description = %q, want empty without a catalog", r.RuleID, r.Description)
			}
		}
	})
}

// @ac AC-15
// AC-15 (trimming half, no DSN): firstSentence keeps the first
// ". "-terminated sentence under 160 chars, else cuts at 160.
func TestFirstSentence_TrimsCatalogProse(t *testing.T) {
	t.Run("api-host-compliance/AC-15", func(t *testing.T) {
		long := strings.Repeat("x", 200)
		cases := []struct{ in, want string }{
			{"Short prose.", "Short prose."},
			{"First sentence. Second sentence.", "First sentence."},
			{"Line one\ncontinues. Tail.", "Line one continues."},
			{long, long[:159] + "."},
			{"", ""},
		}
		for _, c := range cases {
			if got := firstSentence(c.in); got != c.want {
				t.Errorf("firstSentence(%.30q) = %q, want %q", c.in, got, c.want)
			}
		}
	})
}
