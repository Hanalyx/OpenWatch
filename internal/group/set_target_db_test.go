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
