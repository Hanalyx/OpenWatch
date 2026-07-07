// @spec api-hosts
//
// AC traceability (this file):
//   AC-13  TestHosts_GetByID_Enrichment_LivenessPresent
//   AC-14  TestHosts_GetByID_Enrichment_LivenessNullWhenUnprobed
//   AC-15  TestHosts_GetByID_Enrichment_ComplianceSummaryCounts
//   AC-16  TestHosts_GetByID_Enrichment_ComplianceSummaryZerosOnEmpty
//   AC-17  TestHosts_GetByID_Enrichment_FrameworkFilterCounts
//   AC-18  TestHosts_GetByID_Enrichment_FrameworkFilterEmpty
//   AC-19  TestHosts_GetHosts_ListLivenessJoined
//   AC-23  TestHosts_GetHosts_ListComplianceSummaryJoined
//   AC-24  TestHosts_GetHosts_ListLatestScanIDJoined
//   AC-25  TestHosts_GetHosts_ListScanStateJoined

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/auth"
)

// seedLivenessForHost inserts a host_liveness row for the host the
// preceding createHostAPI call returned.
func seedLivenessForHost(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, status string, lastProbeAt time.Time, consecutiveFails int) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO host_liveness
			(host_id, reachability_status, last_probe_at,
			 consecutive_failures, last_state_change_at, updated_at)
		VALUES ($1, $2, $3, $4, $3, $3)`,
		hostID, status, lastProbeAt, consecutiveFails,
	)
	if err != nil {
		t.Fatalf("seed host_liveness: %v", err)
	}
}

// seedRuleStateForHost inserts a single host_rule_state row.
func seedRuleStateForHost(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status string) {
	t.Helper()
	seedRuleStateForHostWithFrameworks(t, pool, hostID, ruleID, status, nil)
}

// seedRuleStateForHostWithFrameworks variant attaches framework_refs.
func seedRuleStateForHostWithFrameworks(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status string, frameworks map[string]string) {
	t.Helper()
	now := time.Now().UTC()
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
		INSERT INTO host_rule_state
			(host_id, rule_id, current_status, severity,
			 last_checked_at, check_count, last_scan_id, evidence,
			 framework_refs, first_seen_at, last_changed_at)
		VALUES ($1, $2, $3, 'medium', $4, 1, $5, '{}'::jsonb, $6::jsonb, $4, $4)`,
		hostID, ruleID, status, now, scanID, refsJSON,
	)
	if err != nil {
		t.Fatalf("seed host_rule_state: %v", err)
	}
}

// hostDetailResponse mirrors the shape returned by GET /hosts/{id}
// after the v1.1.0 enrichment. The decoded body uses map[string]any
// for flexibility — strongly-typed unmarshal would require an oapi-
// generated client which lives outside this test surface.
type hostDetailResponse struct {
	Host     map[string]any `json:"host"`
	Liveness *struct {
		ReachabilityStatus  string     `json:"reachability_status"`
		LastProbeAt         *time.Time `json:"last_probe_at"`
		LastResponseMs      *int       `json:"last_response_ms"`
		ConsecutiveFailures *int       `json:"consecutive_failures"`
	} `json:"liveness"`
	ComplianceSummary struct {
		Passing int64 `json:"passing"`
		Failing int64 `json:"failing"`
		Skipped int64 `json:"skipped"`
		Error   int64 `json:"error"`
		Total   int64 `json:"total"`
	} `json:"compliance_summary"`
}

func getHostDetail(t *testing.T, url, hostID string) hostDetailResponse {
	t.Helper()
	req := asRole(t, "GET", url+"/api/v1/hosts/"+hostID, auth.RoleAdmin, nil)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got hostDetailResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

// @ac AC-13
// AC-13: host with a host_liveness row → liveness populated.
func TestHosts_GetByID_Enrichment_LivenessPresent(t *testing.T) {
	t.Run("api-hosts/AC-13", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		created := createHostAPI(t, url, "live-host", "production")
		idStr := created["id"].(string)
		hostID, _ := uuid.Parse(idStr)
		probedAt := time.Now().UTC().Truncate(time.Second)
		seedLivenessForHost(t, pool, hostID, "reachable", probedAt, 0)

		got := getHostDetail(t, url, idStr)
		if got.Liveness == nil {
			t.Fatal("liveness is null; want populated")
		}
		if got.Liveness.ReachabilityStatus != "reachable" {
			t.Errorf("reachability_status = %q, want reachable", got.Liveness.ReachabilityStatus)
		}
		if got.Liveness.LastProbeAt == nil {
			t.Error("last_probe_at is nil; want populated")
		}
	})
}

// @ac AC-14
// AC-14: host with no host_liveness row → liveness=null, not an error.
func TestHosts_GetByID_Enrichment_LivenessNullWhenUnprobed(t *testing.T) {
	t.Run("api-hosts/AC-14", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		created := createHostAPI(t, url, "unprobed-host", "production")
		idStr := created["id"].(string)

		got := getHostDetail(t, url, idStr)
		if got.Liveness != nil {
			t.Errorf("liveness = %+v, want nil for unprobed host", got.Liveness)
		}
		// compliance_summary still present (default zeros), not null.
		if got.ComplianceSummary.Total != 0 {
			t.Errorf("compliance_summary.total = %d, want 0", got.ComplianceSummary.Total)
		}
	})
}

// @ac AC-15
// AC-15: host with mixed host_rule_state → compliance_summary counts
// match.
func TestHosts_GetByID_Enrichment_ComplianceSummaryCounts(t *testing.T) {
	t.Run("api-hosts/AC-15", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		created := createHostAPI(t, url, "mixed-host", "production")
		idStr := created["id"].(string)
		hostID, _ := uuid.Parse(idStr)
		seedRuleStateForHost(t, pool, hostID, "rule.p1", "pass")
		seedRuleStateForHost(t, pool, hostID, "rule.p2", "pass")
		seedRuleStateForHost(t, pool, hostID, "rule.f1", "fail")
		seedRuleStateForHost(t, pool, hostID, "rule.f2", "fail")
		seedRuleStateForHost(t, pool, hostID, "rule.f3", "fail")
		seedRuleStateForHost(t, pool, hostID, "rule.s1", "skipped")
		seedRuleStateForHost(t, pool, hostID, "rule.e1", "error")

		got := getHostDetail(t, url, idStr)
		s := got.ComplianceSummary
		if s.Passing != 2 {
			t.Errorf("passing = %d, want 2", s.Passing)
		}
		if s.Failing != 3 {
			t.Errorf("failing = %d, want 3", s.Failing)
		}
		if s.Skipped != 1 {
			t.Errorf("skipped = %d, want 1", s.Skipped)
		}
		if s.Error != 1 {
			t.Errorf("error = %d, want 1", s.Error)
		}
		if s.Total != 7 {
			t.Errorf("total = %d, want 7", s.Total)
		}
	})
}

// @ac AC-16
// AC-16: host with no host_rule_state rows → compliance_summary all zeros, not null, not error.
func TestHosts_GetByID_Enrichment_ComplianceSummaryZerosOnEmpty(t *testing.T) {
	t.Run("api-hosts/AC-16", func(t *testing.T) {
		url, _ := freshAPIServer(t)
		created := createHostAPI(t, url, "no-rules-host", "production")
		idStr := created["id"].(string)

		got := getHostDetail(t, url, idStr)
		s := got.ComplianceSummary
		// All zero, valid JSON object (not null), no error.
		if s.Passing != 0 || s.Failing != 0 || s.Skipped != 0 || s.Error != 0 || s.Total != 0 {
			t.Errorf("got %+v, want all zeros", s)
		}
	})
}

// @ac AC-17
// AC-17 (v1.2.0): GET /hosts/{id}?framework=cis_rhel9_v2.0.0
// returns compliance_summary computed only from host_rule_state rows
// whose framework_refs contains that key.
func TestHosts_GetByID_Enrichment_FrameworkFilterCounts(t *testing.T) {
	t.Run("api-hosts/AC-17", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		created := createHostAPI(t, url, "fw-host", "production")
		idStr := created["id"].(string)
		hostID, _ := uuid.Parse(idStr)
		// 2 CIS passing + 1 CIS failing, plus 1 STIG-only failing + 1 no-framework rule.
		seedRuleStateForHostWithFrameworks(t, pool, hostID, "rule.cis.p1", "pass",
			map[string]string{"cis_rhel9_v2.0.0": "1.1"})
		seedRuleStateForHostWithFrameworks(t, pool, hostID, "rule.cis.p2", "pass",
			map[string]string{"cis_rhel9_v2.0.0": "1.2"})
		seedRuleStateForHostWithFrameworks(t, pool, hostID, "rule.cis.f1", "fail",
			map[string]string{"cis_rhel9_v2.0.0": "1.3"})
		seedRuleStateForHostWithFrameworks(t, pool, hostID, "rule.stig.f1", "fail",
			map[string]string{"stig_rhel9_v2r7": "X-1"})
		seedRuleStateForHost(t, pool, hostID, "rule.none", "pass") // no framework_refs

		req := asRole(t, "GET", url+"/api/v1/hosts/"+idStr+"?framework=cis_rhel9_v2.0.0", auth.RoleAdmin, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		var got hostDetailResponse
		_ = json.NewDecoder(resp.Body).Decode(&got)
		s := got.ComplianceSummary
		if s.Passing != 2 || s.Failing != 1 || s.Total != 3 {
			t.Errorf("CIS-filtered summary = %+v, want passing=2 failing=1 total=3", s)
		}
	})
}

// @ac AC-19
// AC-19 (v1.3.0): GET /hosts response items carry liveness inline. One
// host with a probe row → liveness populated; another with no
// host_liveness row → liveness null. Both come back in the same list
// response, mirroring the GET /hosts/{id} sub-object shape.
func TestHosts_GetHosts_ListLivenessJoined(t *testing.T) {
	t.Run("api-hosts/AC-19", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		probed := createHostAPI(t, url, "probed-host", "production")
		probedID, _ := uuid.Parse(probed["id"].(string))
		unprobed := createHostAPI(t, url, "unprobed-host", "production")
		unprobedID := unprobed["id"].(string)

		probedAt := time.Now().UTC().Truncate(time.Second)
		seedLivenessForHost(t, pool, probedID, "unreachable", probedAt, 2)

		req := asRole(t, "GET", url+"/api/v1/hosts", auth.RoleAdmin, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var body struct {
			Hosts []struct {
				ID       string `json:"id"`
				Liveness *struct {
					ReachabilityStatus  string     `json:"reachability_status"`
					LastProbeAt         *time.Time `json:"last_probe_at"`
					ConsecutiveFailures *int       `json:"consecutive_failures"`
				} `json:"liveness"`
			} `json:"hosts"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}

		var sawProbed, sawUnprobed bool
		for _, h := range body.Hosts {
			switch h.ID {
			case probedID.String():
				sawProbed = true
				if h.Liveness == nil {
					t.Fatal("probed host liveness is nil; want populated")
				}
				if h.Liveness.ReachabilityStatus != "unreachable" {
					t.Errorf("reachability_status = %q, want unreachable", h.Liveness.ReachabilityStatus)
				}
				if h.Liveness.LastProbeAt == nil {
					t.Error("last_probe_at is nil; want populated")
				}
				if h.Liveness.ConsecutiveFailures == nil || *h.Liveness.ConsecutiveFailures != 2 {
					t.Errorf("consecutive_failures = %v, want 2", h.Liveness.ConsecutiveFailures)
				}
			case unprobedID:
				sawUnprobed = true
				if h.Liveness != nil {
					t.Errorf("unprobed host liveness = %+v, want nil", h.Liveness)
				}
			}
		}
		if !sawProbed {
			t.Error("probed host not present in /hosts response")
		}
		if !sawUnprobed {
			t.Error("unprobed host not present in /hosts response")
		}
	})
}

// @ac AC-18
// AC-18 (v1.2.0): GET /hosts/{id}?framework=<id> on a host whose
// rule_state does NOT reference that framework returns 200 with all
// zero counts — never an error.
func TestHosts_GetByID_Enrichment_FrameworkFilterEmpty(t *testing.T) {
	t.Run("api-hosts/AC-18", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		created := createHostAPI(t, url, "no-stig-host", "production")
		idStr := created["id"].(string)
		hostID, _ := uuid.Parse(idStr)
		// Host has CIS rules but NO STIG rules.
		seedRuleStateForHostWithFrameworks(t, pool, hostID, "rule.cis.p1", "pass",
			map[string]string{"cis_rhel9_v2.0.0": "1.1"})

		req := asRole(t, "GET", url+"/api/v1/hosts/"+idStr+"?framework=stig_rhel9_v2r7", auth.RoleAdmin, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (zeros, not 404)", resp.StatusCode)
		}
		var got hostDetailResponse
		_ = json.NewDecoder(resp.Body).Decode(&got)
		s := got.ComplianceSummary
		if s.Passing != 0 || s.Failing != 0 || s.Total != 0 {
			t.Errorf("STIG-filtered summary on CIS-only host = %+v, want all zeros", s)
		}
	})
}

// @ac AC-23
// AC-23 (v1.5.0): GET /hosts items carry a nullable compliance_summary
// loaded by one grouped host_rule_state query. A scanned host gets the
// correct counts (critical_failing = fail AND critical severity only);
// a never-scanned host gets null — never zeros, never an error.
func TestHosts_GetHosts_ListComplianceSummaryJoined(t *testing.T) {
	t.Run("api-hosts/AC-23", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		scanned := createHostAPI(t, url, "compliance-host", "production")
		scannedID, _ := uuid.Parse(scanned["id"].(string))
		unscanned := createHostAPI(t, url, "unscanned-host", "production")
		unscannedID := unscanned["id"].(string)

		base := time.Now().UTC().Truncate(time.Second)
		// Mixed statuses; one critical failure, one critical pass (must
		// NOT count toward critical_failing), one high failure.
		seedRuleState(t, pool, scannedID, "ls-crit-fail", "fail", "critical", base, 1, "")
		seedRuleState(t, pool, scannedID, "ls-crit-pass", "pass", "critical", base, 1, "")
		seedRuleState(t, pool, scannedID, "ls-high-fail", "fail", "high", base, 1, "")
		seedRuleState(t, pool, scannedID, "ls-pass", "pass", "medium", base, 1, "")
		seedRuleState(t, pool, scannedID, "ls-skip", "skipped", nil, base, 1, "")
		seedRuleState(t, pool, scannedID, "ls-err", "error", "low", base, 1, "")

		req := asRole(t, "GET", url+"/api/v1/hosts", auth.RoleAdmin, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var body struct {
			Hosts []struct {
				ID                string `json:"id"`
				ComplianceSummary *struct {
					Passing         int64 `json:"passing"`
					Failing         int64 `json:"failing"`
					Skipped         int64 `json:"skipped"`
					Error           int64 `json:"error"`
					Total           int64 `json:"total"`
					CriticalFailing int64 `json:"critical_failing"`
				} `json:"compliance_summary"`
			} `json:"hosts"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}

		var sawScanned, sawUnscanned bool
		for _, h := range body.Hosts {
			switch h.ID {
			case scannedID.String():
				sawScanned = true
				cs := h.ComplianceSummary
				if cs == nil {
					t.Fatal("scanned host compliance_summary is null; want populated")
				}
				if cs.Passing != 2 || cs.Failing != 2 || cs.Skipped != 1 ||
					cs.Error != 1 || cs.Total != 6 {
					t.Errorf("compliance_summary = %+v, want 2/2/1/1 of 6", cs)
				}
				if cs.CriticalFailing != 1 {
					t.Errorf("critical_failing = %d, want 1 (fail AND critical only)",
						cs.CriticalFailing)
				}
			case unscannedID:
				sawUnscanned = true
				if h.ComplianceSummary != nil {
					t.Errorf("unscanned host compliance_summary = %+v, want null",
						h.ComplianceSummary)
				}
			}
		}
		if !sawScanned {
			t.Error("scanned host not present in /hosts response")
		}
		if !sawUnscanned {
			t.Error("unscanned host not present in /hosts response")
		}
	})
}

// seedScanRun inserts a scan_runs row with the given status + queued_at
// and returns its id.
func seedScanRun(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, status string, queuedAt time.Time) uuid.UUID {
	t.Helper()
	id, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO scan_runs (id, host_id, trigger_source, status, queued_at)
		VALUES ($1, $2, 'scheduled', $3, $4)`,
		id, hostID, status, queuedAt)
	if err != nil {
		t.Fatalf("seed scan_runs: %v", err)
	}
	return id
}

// @ac AC-24
// AC-24 (v1.6.0): GET /hosts items carry a nullable latest_scan_id = the
// newest COMPLETED scan_run id. A host with an older+newer completed run
// (plus an even-newer queued run) resolves to the newer COMPLETED id (not
// the queued one); a host with only a queued/running run, and a host with
// no runs at all, both resolve to null.
func TestHosts_GetHosts_ListLatestScanIDJoined(t *testing.T) {
	t.Run("api-hosts/AC-24", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		withCompleted := createHostAPI(t, url, "scanned-host", "production")
		withCompletedID, _ := uuid.Parse(withCompleted["id"].(string))
		queuedOnly := createHostAPI(t, url, "queued-host", "production")
		queuedOnlyID := queuedOnly["id"].(string)
		queuedOnlyUUID, _ := uuid.Parse(queuedOnlyID)
		noScans := createHostAPI(t, url, "noscan-host", "production")
		noScansID := noScans["id"].(string)

		base := time.Now().UTC().Truncate(time.Second)
		// host A: older completed, newer completed (the answer), even-newer queued.
		seedScanRun(t, pool, withCompletedID, "completed", base.Add(-2*time.Hour))
		wantID := seedScanRun(t, pool, withCompletedID, "completed", base.Add(-1*time.Hour))
		seedScanRun(t, pool, withCompletedID, "queued", base) // newest, but not a viewable report
		// host B: only a queued/running run.
		seedScanRun(t, pool, queuedOnlyUUID, "running", base)

		req := asRole(t, "GET", url+"/api/v1/hosts", auth.RoleAdmin, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var body struct {
			Hosts []struct {
				ID           string  `json:"id"`
				LatestScanID *string `json:"latest_scan_id"`
			} `json:"hosts"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		seen := map[string]*string{}
		for _, h := range body.Hosts {
			seen[h.ID] = h.LatestScanID
		}

		if got, ok := seen[withCompletedID.String()]; !ok || got == nil {
			t.Fatalf("scanned host latest_scan_id missing/null; want %s", wantID)
		} else if *got != wantID.String() {
			t.Errorf("latest_scan_id = %s, want %s (newest COMPLETED, not the queued run)", *got, wantID)
		}
		if got, ok := seen[queuedOnlyID]; !ok {
			t.Error("queued-only host absent from /hosts response")
		} else if got != nil {
			t.Errorf("queued-only host latest_scan_id = %v, want null", *got)
		}
		if got, ok := seen[noScansID]; !ok {
			t.Error("no-scan host absent from /hosts response")
		} else if got != nil {
			t.Errorf("no-scan host latest_scan_id = %v, want null", *got)
		}
	})
}

// @ac AC-25
// AC-25 (v1.7.0): GET /hosts items carry a nullable scan_state enum
// (queued|running) for the in-flight run, independent of the completed-run
// fields. A queued host resolves to "queued", a running host to "running",
// and a host with only a completed run resolves to null with its
// latest_scan_id still pointing at the completed run.
func TestHosts_GetHosts_ListScanStateJoined(t *testing.T) {
	t.Run("api-hosts/AC-25", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		queuedHost := createHostAPI(t, url, "queued-host", "production")
		queuedID := queuedHost["id"].(string)
		queuedUUID, _ := uuid.Parse(queuedID)
		runningHost := createHostAPI(t, url, "running-host", "production")
		runningID := runningHost["id"].(string)
		runningUUID, _ := uuid.Parse(runningID)
		completedHost := createHostAPI(t, url, "completed-host", "production")
		completedID := completedHost["id"].(string)
		completedUUID, _ := uuid.Parse(completedID)

		base := time.Now().UTC().Truncate(time.Second)
		seedScanRun(t, pool, queuedUUID, "queued", base)
		seedScanRun(t, pool, runningUUID, "running", base)
		completedRunID := seedScanRun(t, pool, completedUUID, "completed", base.Add(-time.Hour))

		req := asRole(t, "GET", url+"/api/v1/hosts", auth.RoleAdmin, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var body struct {
			Hosts []struct {
				ID           string  `json:"id"`
				ScanState    *string `json:"scan_state"`
				LatestScanID *string `json:"latest_scan_id"`
			} `json:"hosts"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		seen := map[string]struct {
			state  *string
			latest *string
		}{}
		for _, h := range body.Hosts {
			seen[h.ID] = struct {
				state  *string
				latest *string
			}{h.ScanState, h.LatestScanID}
		}

		if got := seen[queuedID].state; got == nil || *got != "queued" {
			t.Errorf("queued host scan_state = %v, want queued", got)
		}
		if got := seen[runningID].state; got == nil || *got != "running" {
			t.Errorf("running host scan_state = %v, want running", got)
		}
		if got := seen[completedID].state; got != nil {
			t.Errorf("completed-only host scan_state = %v, want null", *got)
		}
		// The completed run's latest_scan_id is undisturbed by scan_state.
		if got := seen[completedID].latest; got == nil || *got != completedRunID.String() {
			t.Errorf("completed host latest_scan_id = %v, want %s", got, completedRunID)
		}

		// GET /hosts/{id} (detail) carries scan_state + last_scan_at too.
		detail := func(id string) (scanState *string, lastScanAt *string) {
			dreq := asRole(t, "GET", url+"/api/v1/hosts/"+id, auth.RoleAdmin, nil)
			dresp := doReq(t, dreq)
			defer dresp.Body.Close()
			if dresp.StatusCode != http.StatusOK {
				t.Fatalf("GET /hosts/%s = %d, want 200", id, dresp.StatusCode)
			}
			var db struct {
				ScanState  *string `json:"scan_state"`
				LastScanAt *string `json:"last_scan_at"`
			}
			if err := json.NewDecoder(dresp.Body).Decode(&db); err != nil {
				t.Fatalf("decode detail: %v", err)
			}
			return db.ScanState, db.LastScanAt
		}
		if st, _ := detail(queuedID); st == nil || *st != "queued" {
			t.Errorf("detail queued host scan_state = %v, want queued", st)
		}
		if st, _ := detail(completedID); st != nil {
			t.Errorf("detail completed-only host scan_state = %v, want null", *st)
		}
	})
}
