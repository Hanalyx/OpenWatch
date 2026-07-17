// @spec system-compliance-lens
//
// Group compliance-target (Phase 3 compliance-targets): SetTarget's D1 rule
// (site groups only) and set/clear/validate. Kept in its own file so its spec
// annotation does not re-attribute the api-groups tests in service_db_test.go.

package group

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// @ac AC-11
// AC-11: the /groups per-group AND fleet compliance averages are lens-scoped
// and OS-resolved — a RHEL 9 member's "stig" counts stig_rhel9 only (its
// stig_rhel10 row is excluded), not the family union or all-rules.
func TestGroupCompliance_LensScopedOSResolved(t *testing.T) {
	t.Run("system-compliance-lens/AC-11", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)
		owner := seedUser(t, pool)

		// One RHEL 9 member: stig_rhel9 (1 pass, 1 fail) + stig_rhel10 (1 pass).
		// All-rules = 2/3 (67%); STIG (stig_rhel9) = 1/2 (50%).
		h := seedHost(t, pool, owner, "rhel", false)
		if _, err := pool.Exec(ctx, `UPDATE hosts SET os_version='9.6' WHERE id=$1`, h); err != nil {
			t.Fatalf("set os_version: %v", err)
		}
		seedFW := func(rule, status, refs string) {
			if _, err := pool.Exec(ctx, `
				INSERT INTO host_rule_state
				  (host_id, rule_id, current_status, severity, last_checked_at,
				   last_scan_id, framework_refs, first_seen_at, last_changed_at)
				VALUES ($1,$2,$3,'medium',now(),$4,$5::jsonb,now(),now())`,
				h, rule, status, uuid.New(), refs); err != nil {
				t.Fatalf("seed fw rule: %v", err)
			}
		}
		seedFW("s9.pass", "pass", `{"stig_rhel9":["V-1"]}`)
		seedFW("s9.fail", "fail", `{"stig_rhel9":["V-2"]}`)
		seedFW("s10.pass", "pass", `{"stig_rhel10":["V-1"]}`)

		site, err := svc.Create(ctx, CreateInput{Name: "Prod", Kind: KindSite, Membership: MembershipManual})
		if err != nil {
			t.Fatalf("create site: %v", err)
		}
		if err := svc.AddMember(ctx, site.ID, h); err != nil {
			t.Fatalf("add member: %v", err)
		}

		// Org default = stig -> per-group AVG and fleet AVG are stig_rhel9 (50).
		roll := listOneLens(t, svc, ctx, site.ID, "stig")
		if roll.AvgCompliancePct == nil || *roll.AvgCompliancePct != 50 {
			t.Errorf("per-group avg (org stig) = %v, want 50 (stig_rhel9 only, not all-rules 67)", roll.AvgCompliancePct)
		}
		sum, err := svc.Summary(ctx, "stig")
		if err != nil {
			t.Fatalf("Summary(stig): %v", err)
		}
		if sum.AvgCompliancePct == nil || *sum.AvgCompliancePct != 50 {
			t.Errorf("fleet avg (org stig) = %v, want 50 (stig_rhel9)", sum.AvgCompliancePct)
		}

		// No org default -> all rules (2/3 = 67).
		all, err := svc.List(ctx, "")
		if err != nil {
			t.Fatalf("List(''): %v", err)
		}
		var allRules *int
		for _, gr := range all {
			if gr.ID == site.ID {
				allRules = gr.Rollup.AvgCompliancePct
			}
		}
		if allRules == nil || *allRules != 67 {
			t.Errorf("per-group avg (no default) = %v, want 67 (all rules)", allRules)
		}
	})
}

// listOneLens fetches one group's rollup from List under an org-default lens.
func listOneLens(t *testing.T, svc *Service, ctx context.Context, id uuid.UUID, orgDefault string) Rollup {
	t.Helper()
	all, err := svc.List(ctx, orgDefault)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, g := range all {
		if g.ID == id {
			return g.Rollup
		}
	}
	t.Fatalf("group %s not found", id)
	return Rollup{}
}

// @ac AC-07
// D1: only a site group may carry a compliance target. SetTarget on an
// os_category group is rejected; a site group sets, clears, and validates.
func TestSetTarget_SiteOnly(t *testing.T) {
	t.Run("system-compliance-lens/AC-07", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		svc := NewService(pool)

		site, err := svc.Create(ctx, CreateInput{Name: "Prod", Kind: KindSite, Membership: MembershipManual})
		if err != nil {
			t.Fatalf("create site: %v", err)
		}
		auto, err := svc.Create(ctx, CreateInput{
			Name: "RHEL", Kind: KindOSCategory, Membership: MembershipAuto, MatchFamily: "rhel",
		})
		if err != nil {
			t.Fatalf("create auto: %v", err)
		}

		// D1: target on an os_category group is rejected.
		if _, err := svc.SetTarget(ctx, auto.ID, "stig"); err != ErrTargetOnlyOnSite {
			t.Errorf("SetTarget(auto) err = %v, want ErrTargetOnlyOnSite", err)
		}
		// Site group: set then clear.
		g, err := svc.SetTarget(ctx, site.ID, "stig")
		if err != nil {
			t.Fatalf("SetTarget(site): %v", err)
		}
		if g.TargetFramework != "stig" {
			t.Errorf("target = %q, want stig", g.TargetFramework)
		}
		g, err = svc.SetTarget(ctx, site.ID, "")
		if err != nil {
			t.Fatalf("clear target: %v", err)
		}
		if g.TargetFramework != "" {
			t.Errorf("cleared target = %q, want empty", g.TargetFramework)
		}
		// Invalid family value rejected.
		if _, err := svc.SetTarget(ctx, site.ID, "BAD SPACE"); err != ErrInvalidTarget {
			t.Errorf("SetTarget(bad) err = %v, want ErrInvalidTarget", err)
		}
		// Unknown group -> ErrNotFound.
		if _, err := svc.SetTarget(ctx, uuid.New(), "stig"); err != ErrNotFound {
			t.Errorf("SetTarget(unknown) err = %v, want ErrNotFound", err)
		}
	})
}
