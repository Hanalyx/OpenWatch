// @spec api-remediation
//
// AC traceability (DSN-gated):
//
//	AC-18  TestProjectLift_NISTIsSP80053Only

package remediation

import (
	"context"
	"math"
	"testing"
)

// @ac AC-18
// AC-18: the nist projection is NIST SP 800-53 only. Kensa v0.10.0 added
// nist_800_171, and a "nist" prefix match folds it in two ways at once: a
// rule mapped to 800-171 alone is quoted a NIST lift, and every 800-171-only
// rule inflates the denominator. The fixture discriminates both: with the
// prefix match the first rule reads 25 (one of four) and the second rule
// gets a projection; with the family match it reads 100/3 and gets none.
func TestProjectLift_NISTIsSP80053Only(t *testing.T) {
	t.Run("api-remediation/AC-18", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool, "lift-nist")
		hostID := seedHost(t, pool, user)
		svc := NewService(pool, fakeEmitter(&[]emitCall{}))

		seedRuleState(t, pool, hostID, "r53-fail", "fail", `{"nist_800_53":["AC-2"]}`)
		seedRuleState(t, pool, hostID, "r53-pass", "pass", `{"nist_800_53":["AC-3"]}`)
		seedRuleState(t, pool, hostID, "rboth-pass", "pass", `{"nist_800_53":["AC-6"],"nist_800_171":["3.1.5[a]"]}`)
		seedRuleState(t, pool, hostID, "r171-fail", "fail", `{"nist_800_171":["3.13.9[c]"]}`)

		got, err := svc.ProjectLift(ctx, hostID, "r53-fail")
		if err != nil {
			t.Fatalf("ProjectLift: %v", err)
		}
		if got.NIST == nil {
			t.Fatal("no nist projection for a failing 800-53 rule")
		}
		if want := math.Round(100.0/3*100) / 100; *got.NIST != want {
			t.Errorf("nist lift = %v, want %v (one of three 800-53 rules). 25 means the "+
				"denominator counted the 800-171-only rule", *got.NIST, want)
		}

		only171, err := svc.ProjectLift(ctx, hostID, "r171-fail")
		if err != nil {
			t.Fatalf("ProjectLift: %v", err)
		}
		if only171.NIST != nil {
			t.Errorf("nist lift for a rule mapped only to nist_800_171 = %v, want none: "+
				"the field is labeled NIST and means 800-53", *only171.NIST)
		}
	})
}
