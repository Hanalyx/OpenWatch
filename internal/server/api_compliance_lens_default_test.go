// @spec system-compliance-lens
//
// AC traceability (this file):
//
//	AC-09  TestAPI_HostsList_DefaultsToPerHostEffectiveTarget
//	AC-10  TestAPI_FleetScore_DefaultsToOrgLens
//
// Covers C-06: the effective-lens default applies to the hosts-list
// compliance column (per-host effective target) and the fleet KPI (org
// default lens), not only the host-detail hero tile.

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/audit"
	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/Hanalyx/openwatch/internal/systemconfig"
)

// getHostsList GETs /api/v1/hosts (optionally with a query suffix like
// "?framework=cis") and returns the decoded items.
func getHostsList(t *testing.T, base, suffix string) []api.HostListItem {
	t.Helper()
	req := asRole(t, "GET", base+"/api/v1/hosts"+suffix, auth.RoleViewer, nil)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /hosts%s = %d: %s", suffix, resp.StatusCode, b)
	}
	var out api.HostListResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode hosts: %v", err)
	}
	return out.Hosts
}

func findHostItem(items []api.HostListItem, id uuid.UUID) *api.HostListItem {
	for i := range items {
		if items[i].Id == id {
			return &items[i]
		}
	}
	return nil
}

// @ac AC-09
// AC-09: with no ?framework=, each host's list compliance_summary is scored
// against its OWN effective target; an explicit param overrides per host.
func TestAPI_HostsList_DefaultsToPerHostEffectiveTarget(t *testing.T) {
	t.Run("system-compliance-lens/AC-09", func(t *testing.T) {
		ctx := context.Background()
		url, pool := freshAPIServer(t)
		user := firstSeededUserID(t, pool)

		// Host A carries its own STIG target. It has 2 STIG rules (1 pass,
		// 1 fail) and 1 CIS rule (pass): STIG-scoped total=2, all-rules total=3.
		hostA := seedFleetHost(t, pool, user)
		if _, err := pool.Exec(ctx,
			`UPDATE hosts SET target_framework='stig' WHERE id=$1`, hostA); err != nil {
			t.Fatalf("set host A target: %v", err)
		}
		seedFleetRuleStateWithFrameworks(t, pool, hostA, "a.stig.pass", "pass", map[string]string{"stig_rhel9": "x"})
		seedFleetRuleStateWithFrameworks(t, pool, hostA, "a.stig.fail", "fail", map[string]string{"stig_rhel9": "x"})
		seedFleetRuleStateWithFrameworks(t, pool, hostA, "a.cis.pass", "pass", map[string]string{"cis_rhel9": "x"})

		// Host B has NO target and (this test sets no org default) scores All
		// rules: 1 CIS rule -> total=1.
		hostB := seedFleetHost(t, pool, user)
		seedFleetRuleStateWithFrameworks(t, pool, hostB, "b.cis.pass", "pass", map[string]string{"cis_rhel9": "x"})

		// No framework param: A defaults to its STIG target, B to All rules.
		items := getHostsList(t, url, "")
		a := findHostItem(items, hostA)
		b := findHostItem(items, hostB)
		if a == nil || a.ComplianceSummary == nil {
			t.Fatalf("host A missing compliance_summary: %+v", a)
		}
		if a.ComplianceSummary.Total != 2 || a.ComplianceSummary.Passing != 1 {
			t.Errorf("host A (target stig): total=%d passing=%d, want 2/1 (STIG-scoped, not all-rules 3)",
				a.ComplianceSummary.Total, a.ComplianceSummary.Passing)
		}
		if b == nil || b.ComplianceSummary == nil {
			t.Fatalf("host B missing compliance_summary: %+v", b)
		}
		if b.ComplianceSummary.Total != 1 {
			t.Errorf("host B (no target, no org default): total=%d, want 1 (All rules)",
				b.ComplianceSummary.Total)
		}

		// Explicit ?framework=cis overrides per host: A -> only its CIS rule.
		itemsCis := getHostsList(t, url, "?framework=cis")
		aCis := findHostItem(itemsCis, hostA)
		if aCis == nil || aCis.ComplianceSummary == nil || aCis.ComplianceSummary.Total != 1 {
			t.Errorf("host A ?framework=cis: got %+v, want total=1 (override beats target)", aCis.ComplianceSummary)
		}
	})
}

func getFleetScore(t *testing.T, base, suffix string) api.FleetScore {
	t.Helper()
	req := asRole(t, "GET", base+"/api/v1/fleet/score"+suffix, auth.RoleViewer, nil)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /fleet/score%s = %d: %s", suffix, resp.StatusCode, b)
	}
	var s api.FleetScore
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		t.Fatalf("decode fleet score: %v", err)
	}
	return s
}

// @ac AC-10
// AC-10: with no ?framework=, the fleet score defaults to the org default
// lens; an explicit param overrides.
func TestAPI_FleetScore_DefaultsToOrgLens(t *testing.T) {
	t.Run("system-compliance-lens/AC-10", func(t *testing.T) {
		ctx := context.Background()
		url, pool := freshAPIServer(t)
		user := firstSeededUserID(t, pool)

		// Org default lens = STIG.
		store := systemconfig.NewStore(pool, audit.Emit)
		if _, err := store.SetCompliance(ctx,
			systemconfig.ComplianceConfig{DefaultFramework: "stig"}, user.String()); err != nil {
			t.Fatalf("set org default: %v", err)
		}

		// One host: 2 STIG (1 pass, 1 fail) + 1 CIS (pass). STIG: 1/2 = 0.5;
		// All rules would be 2/3.
		h := seedFleetHost(t, pool, user)
		seedFleetRuleStateWithFrameworks(t, pool, h, "s.pass", "pass", map[string]string{"stig_rhel9": "x"})
		seedFleetRuleStateWithFrameworks(t, pool, h, "s.fail", "fail", map[string]string{"stig_rhel9": "x"})
		seedFleetRuleStateWithFrameworks(t, pool, h, "c.pass", "pass", map[string]string{"cis_rhel9": "x"})

		// No param -> org default STIG.
		s := getFleetScore(t, url, "")
		if s.TotalEvaluations != 2 || s.PassingFraction != 0.5 {
			t.Errorf("fleet default (org stig): frac=%v total=%d, want 0.5/2 (STIG, not all-rules 2/3)",
				s.PassingFraction, s.TotalEvaluations)
		}

		// Explicit ?framework=cis overrides the org default.
		sCis := getFleetScore(t, url, "?framework=cis")
		if sCis.TotalEvaluations != 1 || sCis.PassingFraction != 1.0 {
			t.Errorf("fleet ?framework=cis: frac=%v total=%d, want 1.0/1", sCis.PassingFraction, sCis.TotalEvaluations)
		}
	})
}
