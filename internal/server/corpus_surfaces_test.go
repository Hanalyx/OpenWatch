// @spec system-current-corpus
//
// AC traceability (DSN-gated):
//
//	AC-05  TestCorpusSurfaces_MergedRuleCountsOnceEverywhere
//	AC-06  TestCorpusSurfaces_FailedRulesDropsTheRetiredRule
//	AC-18  TestCorpusSurfaces_EmptyCorpusReadsAsNeverScanned
//
// The four operator-facing surfaces, on one fixture. Each of the tests
// below could pass alone against a surface that scoped correctly while
// its neighbor did not, which is the point: the story is that the host
// reports ONE number, and only reading every surface off the same host
// can show that.

package server

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/db/corpustest"
	"github.com/Hanalyx/openwatch/internal/fleetrollup"
	"github.com/Hanalyx/openwatch/internal/group"
)

// The measured case from the spec: Kensa v0.10.0 merges two rules into
// one. Both predecessors keep their last verdict forever unless the
// reads are scoped.
const (
	retiredA = "shell-timeout-600"
	retiredB = "shell-idle-timeout-tmout"
	merged   = "shell-timeout"
)

const cisRefs = `{"cis_rhel9_v2.0.0": ["5.4.5"]}`

// seedMergedFixture builds the AC-05 host: scanned under the old corpus
// with two rules failing, then scanned again under a corpus where both
// are replaced by one passing rule.
//
// The two scans are real scan_runs rows, so the corpus resolves the way
// it does in production rather than because a fixture said so.
func seedMergedFixture(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID) {
	t.Helper()
	old := time.Now().UTC().Add(-4 * time.Hour)
	oldRun := corpustest.SeedRun(t, pool, hostID, "completed", old, old)
	corpustest.SeedRules(t, pool, hostID, oldRun,
		corpustest.Rule{RuleID: retiredA, Status: "fail", Severity: "high", FrameworkRefs: cisRefs},
		corpustest.Rule{RuleID: retiredB, Status: "fail", Severity: "high", FrameworkRefs: cisRefs},
	)

	recent := time.Now().UTC().Add(-1 * time.Hour)
	newRun := corpustest.SeedRun(t, pool, hostID, "completed", recent, recent)
	corpustest.SeedRules(t, pool, hostID, newRun,
		corpustest.Rule{RuleID: merged, Status: "pass", Severity: "high", FrameworkRefs: cisRefs},
	)
}

// corpusRuleIDs reads the view for a host.
func corpusRuleIDs(t *testing.T, pool *pgxpool.Pool, hostID uuid.UUID) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT rule_id FROM host_rule_state_current WHERE host_id = $1 ORDER BY rule_id`, hostID)
	if err != nil {
		t.Fatalf("query view: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, id)
	}
	return out
}

// @ac AC-05
// AC-05: the measured merge case, end to end, on every surface.
//
// The numbers are chosen so every wrong answer is a DIFFERENT number.
// One control passing reads 100 percent over a total of 1. Counting the
// two dead predecessors reads 33 percent over a total of 3. A surface
// that scoped its numerator but not its denominator reads 33 over 3 as
// well, which is why the totals are asserted and not only the score.
func TestCorpusSurfaces_MergedRuleCountsOnceEverywhere(t *testing.T) {
	t.Run("system-current-corpus/AC-05", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		created := createHostAPI(t, url, "merged-host", "production")
		idStr := created["id"].(string)
		hostID, _ := uuid.Parse(idStr)
		seedMergedFixture(t, pool, hostID)

		// The corpus itself, so a failure downstream can be told from a
		// broken fixture.
		if got := corpusRuleIDs(t, pool, hostID); len(got) != 1 || got[0] != merged {
			t.Fatalf("current corpus = %v, want [%s] only", got, merged)
		}

		t.Run("single-host compliance summary counts one control", func(t *testing.T) {
			got := getHostDetail(t, url, idStr)
			s := got.ComplianceSummary
			if s.Total != 1 || s.Passing != 1 || s.Failing != 0 {
				t.Errorf("compliance_summary = %+v, want passing=1 failing=0 total=1. A total of "+
					"3 means the two merged-away predecessors are still being counted, so this "+
					"host is graded on the same control three times", s)
			}
		})

		t.Run("the retired rows are still on disk", func(t *testing.T) {
			var n int
			if err := pool.QueryRow(ctx,
				`SELECT count(*) FROM host_rule_state WHERE host_id = $1 AND rule_id = ANY($2)`,
				hostID, []string{retiredA, retiredB}).Scan(&n); err != nil {
				t.Fatalf("count retired rows: %v", err)
			}
			if n != 2 {
				t.Errorf("retired rows on disk = %d, want 2. Scoping the reads is only defensible "+
					"because nothing is deleted: these rows are the record of what this host used "+
					"to be measured against", n)
			}
		})

		t.Run("the fleet score reports the same number", func(t *testing.T) {
			sc, err := fleetrollup.NewService(pool).FleetComplianceScore(ctx)
			if err != nil {
				t.Fatalf("fleet score: %v", err)
			}
			if sc.TotalEvaluations != 1 || sc.PassingFraction != 1 {
				t.Errorf("fleet score = %+v, want 1 evaluation and a passing fraction of 1. "+
					"Three evaluations at one third is the same host graded on two rules that "+
					"no longer exist", sc)
			}
		})

		t.Run("a group average reports the same number", func(t *testing.T) {
			gsvc := group.NewService(pool)
			g, err := gsvc.Create(ctx, group.CreateInput{
				Name: "merged-group", Kind: group.KindSite, Membership: group.MembershipManual,
			})
			if err != nil {
				t.Fatalf("create group: %v", err)
			}
			if err := gsvc.AddMember(ctx, g.ID, hostID); err != nil {
				t.Fatalf("add member: %v", err)
			}
			groups, err := gsvc.List(ctx, "")
			if err != nil {
				t.Fatalf("list groups: %v", err)
			}
			var avg *int
			for _, gg := range groups {
				if gg.ID == g.ID {
					avg = gg.AvgCompliancePct
				}
			}
			if avg == nil {
				t.Fatal("group average is nil for a group holding a scanned host")
			}
			if *avg != 100 {
				t.Errorf("group average = %d, want 100. The host's only current rule passes; "+
					"33 is the two dead predecessors dragging the same host down on a third "+
					"surface", *avg)
			}
		})
	})
}

// @ac AC-06
// AC-06: the work list drops the retired rule.
//
// This is the criterion that stops the product offering an operator an
// item that no scan can clear and no remediation can fix. Both halves
// matter: the rule absent from the list, and total_failing excluding it,
// because the count is computed pre-limit and a surface could filter the
// page while still reporting the inflated total in the header.
func TestCorpusSurfaces_FailedRulesDropsTheRetiredRule(t *testing.T) {
	t.Run("system-current-corpus/AC-06", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		created := createHostAPI(t, url, "worklist-host", "production")
		idStr := created["id"].(string)
		hostID, _ := uuid.Parse(idStr)
		seedMergedFixture(t, pool, hostID)

		// One CURRENT failing rule, so the endpoint has something real to
		// return. An empty list would satisfy "does not list the retired
		// rule" for the wrong reason.
		recent := time.Now().UTC().Add(-1 * time.Hour)
		var latest uuid.UUID
		if err := pool.QueryRow(context.Background(), `
			SELECT id FROM scan_runs WHERE host_id = $1 AND status = 'completed'
			 ORDER BY finished_at DESC NULLS LAST, id DESC LIMIT 1`, hostID).Scan(&latest); err != nil {
			t.Fatalf("read latest run: %v", err)
		}
		_ = recent
		corpustest.SeedRules(t, pool, hostID, latest,
			corpustest.Rule{RuleID: "sshd-permit-root-no", Status: "fail",
				Severity: "critical", FrameworkRefs: cisRefs},
		)

		status, body := getFailedRules(t, url, auth.RoleAdmin, idStr, "")
		if status != 200 {
			t.Fatalf("status = %d, want 200", status)
		}
		for _, r := range body.Rules {
			if r.RuleID == retiredA || r.RuleID == retiredB {
				t.Errorf("failed-rules lists %s, a rule the current scan does not evaluate. "+
					"No scan clears it and no remediation fixes it, so it is an item on an "+
					"operator's work list that can never be completed", r.RuleID)
			}
		}
		if len(body.Rules) != 1 || (len(body.Rules) == 1 && body.Rules[0].RuleID != "sshd-permit-root-no") {
			t.Errorf("failed-rules returned %d rules, want the one current failing rule; "+
				"an empty list would satisfy the check above for the wrong reason", len(body.Rules))
		}
		if body.TotalFailing != 1 {
			t.Errorf("total_failing = %d, want 1. The count is computed pre-limit, so a surface "+
				"can filter the page and still report the inflated total in the header",
				body.TotalFailing)
		}
	})
}

// @ac AC-18
// AC-18: an empty corpus reads as never scanned, never as zero percent.
//
// Zero percent is a statement about a host that nothing measured. The
// group half is the sharpest: averaging an unmeasured host in as a zero
// does not just mislabel that host, it drags down a number an operator
// reads as their team's posture.
func TestCorpusSurfaces_EmptyCorpusReadsAsNeverScanned(t *testing.T) {
	t.Run("system-current-corpus/AC-18", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()

		// A host with rule state and NO completed run.
		emptyCreated := createHostAPI(t, url, "empty-corpus-host", "production")
		emptyID, _ := uuid.Parse(emptyCreated["id"].(string))
		running := corpustest.SeedRun(t, pool, emptyID, "running",
			time.Now().UTC().Add(-time.Hour), time.Time{})
		corpustest.SeedRules(t, pool, emptyID, running,
			corpustest.Rule{RuleID: "rule-a", Status: "fail", Severity: "high", FrameworkRefs: cisRefs},
			corpustest.Rule{RuleID: "rule-b", Status: "fail", Severity: "high", FrameworkRefs: cisRefs},
		)

		// A properly scanned host, all passing, to compare against.
		scoredCreated := createHostAPI(t, url, "scored-host", "production")
		scoredID, _ := uuid.Parse(scoredCreated["id"].(string))
		corpustest.SeedScanned(t, pool, scoredID,
			corpustest.Rule{RuleID: "rule-a", Status: "pass", Severity: "high", FrameworkRefs: cisRefs},
		)

		t.Run("the single-host summary returns zero counts, not a score", func(t *testing.T) {
			got := getHostDetail(t, url, emptyCreated["id"].(string))
			s := got.ComplianceSummary
			if s.Total != 0 || s.Passing != 0 || s.Failing != 0 {
				t.Errorf("compliance_summary = %+v, want all zeros. This host has two failing "+
					"rows and no completed scan; reporting them would present a partial run as "+
					"the host's posture", s)
			}
		})

		t.Run("the empty host is excluded from a group average", func(t *testing.T) {
			gsvc := group.NewService(pool)
			g, err := gsvc.Create(ctx, group.CreateInput{
				Name: "mixed-group", Kind: group.KindSite, Membership: group.MembershipManual,
			})
			if err != nil {
				t.Fatalf("create group: %v", err)
			}
			for _, h := range []uuid.UUID{emptyID, scoredID} {
				if err := gsvc.AddMember(ctx, g.ID, h); err != nil {
					t.Fatalf("add member: %v", err)
				}
			}
			groups, err := gsvc.List(ctx, "")
			if err != nil {
				t.Fatalf("list groups: %v", err)
			}
			var avg *int
			for _, gg := range groups {
				if gg.ID == g.ID {
					avg = gg.AvgCompliancePct
				}
			}
			if avg == nil {
				t.Fatal("group average is nil, but one member host was scanned and passes")
			}
			if *avg != 100 {
				t.Errorf("group average = %d, want 100, the scored host's own score. Anything "+
					"lower means the unmeasured host entered the calculation, which reports an "+
					"absence of data as a total failure and drags down a number an operator "+
					"reads as their team's posture. Measured at 33 with the rollup unscoped, "+
					"not the 50 a per-host average would give, because the rollup weights by "+
					"rule rather than by host", *avg)
			}
		})

		t.Run("the empty host contributes nothing to the fleet score", func(t *testing.T) {
			sc, err := fleetrollup.NewService(pool).FleetComplianceScore(ctx)
			if err != nil {
				t.Fatalf("fleet score: %v", err)
			}
			// One evaluation, from the scored host alone. Two would mean
			// the unmeasured host entered the denominator.
			if sc.TotalEvaluations != 1 {
				t.Errorf("fleet evaluations = %d, want 1. The host with no completed scan must "+
					"contribute to neither the numerator nor the denominator", sc.TotalEvaluations)
			}
			if sc.PassingFraction != 1 {
				t.Errorf("fleet passing fraction = %v, want 1", sc.PassingFraction)
			}
		})
	})
}
