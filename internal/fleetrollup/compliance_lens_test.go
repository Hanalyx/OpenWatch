// @spec system-compliance-lens
//
// The family-aware fleet score: a family filter spans a mixed-OS fleet.

package fleetrollup

import (
	"context"
	"testing"
	"time"

	"github.com/Hanalyx/openwatch/internal/db/corpustest"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// seedRuleStateFW inserts a host_rule_state row with a specific
// framework_refs JSONB literal (e.g. `{"stig_rhel9":["V-1"]}`).
func seedRuleStateFW(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status, frameworkRefs string) {
	t.Helper()
	now := time.Now().UTC()
	scanID := corpustest.CurrentRun(t, pool, hostID)
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

		// Family "stig": h9 resolves to stig_rhel9 (1 pass, 1 fail) and h10 to
		// stig_rhel10 (1 pass). Under the equal-host mean that is 50 and 100
		// averaged to 75, NOT the pooled 2/3. Both hosts are scored on the SAME
		// family; each is resolved to its own OS variant of it, which is one
		// lens applied to a mixed fleet, not two lenses blended.
		stig, err := svc.FleetComplianceScore(context.Background(), WithFramework("stig"))
		if err != nil {
			t.Fatalf("stig score: %v", err)
		}
		got, ok := stig.Score.Rounded()
		if !ok {
			t.Fatal("stig family score absent")
		}
		if got == 66.7 {
			t.Error("stig family scored 66.7, the pooled answer over three rule rows")
		}

		// A specific key matches only that OS. h9 scores 1 of 2 on stig_rhel9;
		// h10 carries no stig_rhel9 rule, so it has no score and is counted
		// rather than averaged in. The mean is h9's own 50.
		key, _ := svc.FleetComplianceScore(context.Background(), WithFramework("stig_rhel9"))
		keyPct, ok := key.Score.Rounded()
		if !ok || keyPct != 50.0 {
			t.Errorf("stig_rhel9 = %v present=%v, want 50", keyPct, ok)
		}
		if key.HostsScored != 1 || key.HostsWithoutScore != 1 {
			t.Errorf("stig_rhel9 participation = %d scored / %d unscored, want 1 and 1; the host "+
				"with no rule under this lens is counted, not dropped",
				key.HostsScored, key.HostsWithoutScore)
		}

		// No filter = all rules. h9 is 2 of 3 (66.666...), h10 is 1 of 1, so the
		// equal-host mean is 83.3. Pooling the four rows would give 75.
		all, _ := svc.FleetComplianceScore(context.Background())
		allPct, ok := all.Score.Rounded()
		if !ok || allPct != 83.3 {
			t.Errorf("all rules = %v present=%v, want 83.3", allPct, ok)
		}
		if allPct == 75.0 {
			t.Error("all rules scored 75, the pooled answer over four rule rows")
		}
	})
}
