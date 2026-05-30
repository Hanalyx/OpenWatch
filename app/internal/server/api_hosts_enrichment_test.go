// @spec api-hosts
//
// AC traceability (this file):
//   AC-13  TestHosts_GetByID_Enrichment_LivenessPresent
//   AC-14  TestHosts_GetByID_Enrichment_LivenessNullWhenUnprobed
//   AC-15  TestHosts_GetByID_Enrichment_ComplianceSummaryCounts
//   AC-16  TestHosts_GetByID_Enrichment_ComplianceSummaryZerosOnEmpty
//   AC-17  TestHosts_GetByID_Enrichment_FrameworkFilterCounts
//   AC-18  TestHosts_GetByID_Enrichment_FrameworkFilterEmpty

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
