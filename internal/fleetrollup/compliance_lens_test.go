// @spec system-compliance-lens
//
// The family-aware fleet score: a family filter spans a mixed-OS fleet.

package fleetrollup

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// seedRuleStateFW inserts a host_rule_state row with a specific
// framework_refs JSONB literal (e.g. `{"stig_rhel9":["V-1"]}`).
func seedRuleStateFW(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status, frameworkRefs string) {
	t.Helper()
	now := time.Now().UTC()
	scanID, _ := uuid.NewV7()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO host_rule_state
			(host_id, rule_id, current_status, severity,
			 last_checked_at, check_count, last_scan_id, evidence,
			 framework_refs, first_seen_at, last_changed_at)
		VALUES ($1, $2, $3, 'medium', $4, 1, $5, '{}'::jsonb, $6::jsonb, $4, $4)`,
		hostID, ruleID, status, now, scanID, frameworkRefs,
	)
	if err != nil {
		t.Fatalf("seed rule_state fw: %v", err)
	}
}

// @ac AC-03
// AC-03: a FAMILY filter spans a mixed-OS fleet — each host resolved to its
// OWN OS key (a RHEL 9 host's "stig" -> stig_rhel9, a RHEL 10 host's ->
// stig_rhel10) so both contribute; a specific-key filter matches only that OS;
// no filter counts all rules.
func TestFleetComplianceScore_FamilyMatchesMixedOS(t *testing.T) {
	t.Run("system-compliance-lens/AC-03", func(t *testing.T) {
		pool := freshPool(t)
		svc := NewService(pool)
		user := seedUser(t, pool)
		h9 := seedHost(t, pool, user)  // RHEL 9
		h10 := seedHost(t, pool, user) // RHEL 10
		if _, err := pool.Exec(context.Background(),
			`UPDATE hosts SET os_family='rhel', os_version='9.6' WHERE id=$1`, h9); err != nil {
			t.Fatalf("set h9 os: %v", err)
		}
		if _, err := pool.Exec(context.Background(),
			`UPDATE hosts SET os_family='rhel', os_version='10.0' WHERE id=$1`, h10); err != nil {
			t.Fatalf("set h10 os: %v", err)
		}

		seedRuleStateFW(t, pool, h9, "r.a", "pass", `{"stig_rhel9":["V-1"]}`)
		seedRuleStateFW(t, pool, h9, "r.b", "fail", `{"stig_rhel9":["V-2"]}`)
		seedRuleStateFW(t, pool, h9, "r.c", "pass", `{"cis_rhel9":["1.1"]}`)
		seedRuleStateFW(t, pool, h10, "r.a", "pass", `{"stig_rhel10":["V-1"]}`)

		// Family "stig": h9 resolves to stig_rhel9 (1 pass, 1 fail), h10 to
		// stig_rhel10 (1 pass) → 2 pass / 3 evaluations across the fleet.
		stig, err := svc.FleetComplianceScore(context.Background(), WithFramework("stig"))
		if err != nil {
			t.Fatalf("stig score: %v", err)
		}
		if stig.TotalEvaluations != 3 || stig.PassingFraction != 2.0/3.0 {
			t.Errorf("stig family = %d evals / %v, want 3 / %v",
				stig.TotalEvaluations, stig.PassingFraction, 2.0/3.0)
		}

		// A specific key matches only that OS.
		key, _ := svc.FleetComplianceScore(context.Background(), WithFramework("stig_rhel9"))
		if key.TotalEvaluations != 2 {
			t.Errorf("stig_rhel9 = %d evals, want 2", key.TotalEvaluations)
		}

		// No filter = all rules (3 pass + 1 fail = 4 evaluations).
		all, _ := svc.FleetComplianceScore(context.Background())
		if all.TotalEvaluations != 4 {
			t.Errorf("all rules = %d evals, want 4", all.TotalEvaluations)
		}
	})
}
