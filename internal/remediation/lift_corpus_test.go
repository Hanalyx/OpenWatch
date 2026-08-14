// @spec system-current-corpus
//
// AC traceability (DSN-gated):
//
//	AC-07  TestProjectLift_IsCorpusScopedInBothHalves

package remediation

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/db/corpustest"
)

// seedRetiredRuleState writes a row stamped with an OLD completed run, so
// it sits outside the host's current corpus while remaining on disk.
func seedRetiredRuleState(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID, ruleID, status, refsJSON string) {
	t.Helper()
	old := time.Now().UTC().Add(-6 * time.Hour)
	oldRun := corpustest.SeedRun(t, pool, hostID, "completed", old, old)
	_, err := pool.Exec(context.Background(), `
		INSERT INTO host_rule_state
			(host_id, rule_id, current_status, severity, last_checked_at,
			 check_count, last_scan_id, evidence, framework_refs, first_seen_at, last_changed_at)
		VALUES ($1, $2, $3, 'high', now(), 1, $4, '{}'::jsonb, $5::jsonb, now(), now())`,
		hostID, ruleID, status, oldRun, refsJSON)
	if err != nil {
		t.Fatalf("seed retired rule state %s: %v", ruleID, err)
	}
}

// @ac AC-07
// AC-07: projected lift is corpus-scoped in BOTH halves.
//
// The first half is the offer. A retired failing rule keeps its verdict
// forever, and unscoped, ProjectLift would happily estimate the gain
// from fixing it. Nothing can fix it: no scan clears it because it is
// never evaluated, and the engine has no handler for a rule it no longer
// ships. Offering it puts an item on an operator's work list that can
// never be completed.
//
// The second half is the denominator, and it is the one worth asserting
// directly. A projection computed over a denominator inflated by dead
// rules still LOOKS plausible: it is a small positive number in the
// right units. Only comparing it against the count of rules that
// actually exist shows the difference, which is why this asserts the
// exact value rather than that a projection was returned.
func TestProjectLift_IsCorpusScopedInBothHalves(t *testing.T) {
	t.Run("system-current-corpus/AC-07", func(t *testing.T) {
		pool := freshPool(t)
		ctx := context.Background()
		user := seedUser(t, pool, "lift")
		hostID := seedHost(t, pool, user)
		svc := NewService(pool, fakeEmitter(&[]emitCall{}))

		const cisRefs = `{"cis_rhel9_v2":["1.1"]}`

		// Two rules the current scan still evaluates: one failing, one
		// passing. The denominator over the current corpus is therefore 2,
		// so a correct projection is 100/2 = 50.
		seedRuleState(t, pool, hostID, "current-fail", "fail", cisRefs)
		seedRuleState(t, pool, hostID, "current-pass", "pass", cisRefs)

		// Two rules that left the corpus, both failing and both mapped to
		// the same framework. Unscoped the denominator would be 4 and the
		// projection would read 25.
		seedRetiredRuleState(t, pool, hostID, "shell-timeout-600", "fail", cisRefs)
		seedRetiredRuleState(t, pool, hostID, "shell-idle-timeout-tmout", "fail", cisRefs)

		// Precondition: the retired rules really are outside the corpus
		// and the current ones really are inside it.
		var inCorpus int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM host_rule_state_current WHERE host_id = $1`, hostID).Scan(&inCorpus); err != nil {
			t.Fatalf("count corpus: %v", err)
		}
		if inCorpus != 2 {
			t.Fatalf("current corpus holds %d rules, want 2; the fixture does not describe the "+
				"case under test", inCorpus)
		}
		var total int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM host_rule_state WHERE host_id = $1`, hostID).Scan(&total); err != nil {
			t.Fatalf("count rows: %v", err)
		}
		if total != 4 {
			t.Fatalf("host_rule_state holds %d rows, want 4; the retired rows must still exist "+
				"or there is nothing for an unscoped read to over-count", total)
		}

		t.Run("a retired failing rule is not offered", func(t *testing.T) {
			got, err := svc.ProjectLift(ctx, hostID, "shell-timeout-600")
			if err != nil {
				t.Fatalf("ProjectLift: %v", err)
			}
			if got.CIS != nil || got.STIG != nil || got.NIST != nil {
				t.Errorf("ProjectLift for a retired failing rule = %+v, want an empty projection. "+
					"No scan can clear this rule and no remediation can fix it, so offering a "+
					"projected gain puts an item on a work list that can never be completed", got)
			}
		})

		t.Run("the denominator counts only current-corpus rules", func(t *testing.T) {
			got, err := svc.ProjectLift(ctx, hostID, "current-fail")
			if err != nil {
				t.Fatalf("ProjectLift: %v", err)
			}
			if got.CIS == nil {
				t.Fatal("ProjectLift for a current failing rule returned no CIS projection")
			}
			if *got.CIS != 50 {
				t.Errorf("projected CIS lift = %v, want 50 (one rule of the TWO in the current "+
					"corpus). A value of 25 means the denominator counted all four rows, so the "+
					"two dead rules are deflating an estimate an operator reads as a promise",
					*got.CIS)
			}
		})
	})
}
