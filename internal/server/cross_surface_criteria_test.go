// @spec system-compliance-scoring
//
// Cross-surface equality: surfaces of the SAME scope report the same number.
//
// Before one definition of a score, the host lens, the fleet rollup and the
// posture snapshot each used their own formula, and the live fleet number
// disagreed with its own trend line by about 20 points. A host and a fleet
// are different scopes and are expected to differ; two views of one scope
// are not.
package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/db/corpustest"
	"github.com/Hanalyx/openwatch/internal/posture"
	"github.com/Hanalyx/openwatch/internal/report"
	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// seedLensHost seeds one RHEL 9 host carrying pass/fail rule states under a
// framework, and the matching scan_results rows the attestation report reads.
//
// Both stores are written from the SAME counts on purpose. The attestation
// report reads frozen scan_results and every other surface reads rule state,
// so seeding them independently would let the two disagree for a reason the
// product does not have.
func seedLensHost(t *testing.T, pool *pgxpool.Pool, user uuid.UUID,
	framework string, pass, fail int, engine string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	hostID := seedFleetHost(t, pool, user)
	if _, err := pool.Exec(ctx,
		`UPDATE hosts SET os_family='rhel', os_version='9.6' WHERE id=$1`, hostID); err != nil {
		t.Fatalf("set host os: %v", err)
	}
	runID := corpustest.CurrentRun(t, pool, hostID)
	if _, err := pool.Exec(ctx,
		`UPDATE scan_runs SET engine_version=$2 WHERE id=$1`, runID, engine); err != nil {
		t.Fatalf("set engine: %v", err)
	}
	refs := `{"` + framework + `": ["x"]}`
	write := func(status string, n int) {
		for i := 0; i < n; i++ {
			ruleID := status + "-" + uuid.NewString()
			seedFleetRuleStateWithFrameworks(t, pool, hostID, ruleID, status,
				map[string]string{framework: "x"})
			if _, err := pool.Exec(ctx, `
				INSERT INTO scan_results
					(scan_id, host_id, rule_id, status, severity, framework_refs)
				VALUES ($1, $2, $3, $4, 'medium', $5::jsonb)`,
				runID, hostID, ruleID, status, refs); err != nil {
				t.Fatalf("seed scan_result: %v", err)
			}
		}
	}
	write("pass", pass)
	write("fail", fail)
	return hostID, runID
}

// oneDecimal reads a nullable score, failing when it is absent.
func oneDecimal(t *testing.T, v *float64, label string) float64 {
	t.Helper()
	if v == nil {
		t.Fatalf("%s: score_pct is null, want a value", label)
	}
	return *v
}

// @ac AC-08
// AC-08: surfaces of the same scope agree, asserted on the RENDERED
// one-decimal value rather than on raw floats.
func TestCrossSurface_SameScopeSurfacesAgree(t *testing.T) {
	t.Run("system-compliance-scoring/AC-08", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-08")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		ctx := context.Background()
		url, pool := freshAPIServer(t)
		user := firstSeededUserID(t, pool)
		lens := in.Str("lens")
		engine := "kensa-0.9.0-ac08"

		hosts := map[string]uuid.UUID{}
		for _, h := range in.MapList("hosts") {
			c := h.Map("counts")
			id, _ := seedLensHost(t, pool, user, lens, c.Int("pass"), c.Int("fail"), engine)
			hosts[h.Str("id")] = id
			c.AllConsumed()
			h.AllConsumed()
		}

		// The group holds exactly the fixture's members, so a group aggregate
		// and a fleet aggregate are over the same population.
		groupID := createManualGroup(t, url, "AC-08 group")
		for _, member := range in.StrList("group_membership") {
			id, ok := hosts[member]
			if !ok {
				t.Fatalf("group_membership names host %q, which the fixture does not seed", member)
			}
			addGroupMember(t, url, groupID, id)
		}
		setGroupTarget(t, url, groupID, lens)

		// Today's snapshots are DERIVED by the real rollup, not hand-seeded.
		// Hand-seeding them would assert that two numbers this test wrote are
		// equal, which is the one thing this criterion is not about.
		if _, err := posture.Rollup(ctx, pool, time.Now().UTC()); err != nil {
			t.Fatalf("posture rollup: %v", err)
		}

		q := "?framework=" + lens
		got := map[string]float64{}

		got["host_A_current"] = oneDecimal(t,
			getLensSummary(t, url, hosts["A"], q).Summary.ScorePct, "host_A_current")
		got["host_A_trend_today"] = oneDecimal(t,
			latestTrendScore(t, url, "/api/v1/hosts/"+hosts["A"].String()+"/compliance/trend"+q),
			"host_A_trend_today")

		_, fleet := getAggregateScore(t, url, q)
		got["fleet_current"] = oneDecimal(t, fleet.ScorePct, "fleet_current")
		got["fleet_trend_today"] = oneDecimal(t,
			latestTrendScore(t, url, "/api/v1/fleet/compliance/trend"+q), "fleet_trend_today")

		got["group_current"] = oneDecimal(t,
			getGroupRollup(t, url, groupID).Rollup.Score.ScorePct, "group_current")

		// The two signed artifacts, generated from the same data.
		svc := report.NewService(pool)
		execRep, err := svc.Generate(ctx, "ac08@example.com",
			report.GenerateRequest{Framework: lens})
		if err != nil {
			t.Fatalf("generate executive: %v", err)
		}
		var execContent report.ExecutiveContent
		if err := json.Unmarshal(execRep.Content, &execContent); err != nil {
			t.Fatalf("decode executive: %v", err)
		}
		got["executive_report_fleet_score"] = oneDecimal(t, execContent.ScorePct,
			"executive_report_fleet_score")

		attRep, err := svc.Generate(ctx, "ac08@example.com",
			report.GenerateRequest{Kind: report.KindAttestation, Framework: lens})
		if err != nil {
			t.Fatalf("generate attestation: %v", err)
		}
		var attContent report.AttestationContent
		if err := json.Unmarshal(attRep.Content, &attContent); err != nil {
			t.Fatalf("decode attestation: %v", err)
		}
		got["attestation_report_fleet_score"] = oneDecimal(t, attContent.Rollup.ScorePct,
			"attestation_report_fleet_score")

		// fleet_trend_at_freeze is today's fleet trend point: the reports were
		// generated from the state the rollup summarized, so the freeze
		// instant and today are the same point.
		got["fleet_trend_at_freeze"] = got["fleet_trend_today"]

		// Absolute values first. Two surfaces can agree on a wrong number, so
		// equality alone would not catch a formula change applied everywhere.
		for _, name := range []string{
			"host_A_current", "host_A_trend_today", "fleet_current", "fleet_trend_today",
			"group_current", "executive_report_fleet_score", "attestation_report_fleet_score",
		} {
			if got[name] != exp.Num(name) {
				t.Errorf("%s = %v, want %v", name, got[name], exp.Num(name))
			}
		}

		if !exp.Bool("all_pairs_equal") {
			t.Fatal("fixture must require the pairs to agree")
		}
		for _, pair := range in.List("pairs") {
			entries, ok := pair.([]any)
			if !ok || len(entries) != 2 {
				t.Fatalf("pairs entry %v is not a two-element list", pair)
			}
			left, lok := entries[0].(string)
			right, rok := entries[1].(string)
			if !lok || !rok {
				t.Fatalf("pairs entry %v does not name two surfaces", pair)
			}
			lv, lseen := got[left]
			rv, rseen := got[right]
			if !lseen || !rseen {
				t.Fatalf("pair (%s, %s) names a surface this test does not read", left, right)
			}
			if lv != rv {
				t.Errorf("%s = %v but %s = %v; two views of one scope must not be two numbers",
					left, lv, right, rv)
			}
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// latestTrendScore GETs a trend endpoint and returns the most recent point's
// score.
func latestTrendScore(t *testing.T, url, path string) *float64 {
	t.Helper()
	req := asRole(t, "GET", url+path, auth.RoleViewer, nil)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s = %d: %s", path, resp.StatusCode, b)
	}
	// One field name now. The fleet trend called it avg_score_pct until
	// 2026-09-06 while every other surface called it score_pct, and reading
	// only one of them silently returned null for the other endpoint, which
	// is how this helper first "found" a missing fleet score.
	var body struct {
		Days []struct {
			Date     string   `json:"date"`
			ScorePct *float64 `json:"score_pct"`
		} `json:"days"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if len(body.Days) == 0 {
		t.Fatalf("%s returned no points although the rollup ran", path)
	}
	return body.Days[len(body.Days)-1].ScorePct
}

// setGroupTarget points a group at a compliance target framework.
func setGroupTarget(t *testing.T, url string, groupID uuid.UUID, framework string) {
	t.Helper()
	req := asRole(t, "POST", url+"/api/v1/groups/"+groupID.String()+":target",
		auth.RoleOpsLead, map[string]any{"target_framework": framework})
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("set group target = %d: %s", resp.StatusCode, b)
	}
}
