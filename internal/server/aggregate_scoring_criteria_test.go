// @spec system-compliance-scoring
//
// Aggregation: one host, one vote.
//
// Pooling rule rows across an estate is the defect these criteria exist to
// prevent. A host carrying 700 rules outvoted one carrying 50, so the fleet
// number tracked the biggest corpus rather than the fleet, and no operator
// could reconcile it with any host they opened.
package server

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/db/corpustest"
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// seedFleetHostScored seeds one fleet host whose completed scan recorded
// engineVersion, with rule states matching a counts block.
func seedFleetHostScored(t *testing.T, pool *pgxpool.Pool, user uuid.UUID,
	counts map[string]int, engineVersion string, frameworks map[string]string) uuid.UUID {
	t.Helper()
	hostID := seedFleetHost(t, pool, user)
	runID := corpustest.CurrentRun(t, pool, hostID)
	if _, err := pool.Exec(t.Context(),
		`UPDATE scan_runs SET engine_version = $2 WHERE id = $1`, runID, engineVersion); err != nil {
		t.Fatalf("set engine_version: %v", err)
	}
	for _, status := range []string{"pass", "fail", "skipped", "error"} {
		for i := 0; i < counts[status]; i++ {
			seedFleetRuleStateWithFrameworks(t, pool, hostID,
				status+"-"+uuid.NewString(), status, frameworks)
		}
	}
	return hostID
}

// getAggregateScore GETs the fleet score endpoint.
func getAggregateScore(t *testing.T, url, query string) (int, api.AggregateScore) {
	t.Helper()
	req := asRole(t, "GET", url+"/api/v1/fleet/score"+query, auth.RoleViewer, nil)
	resp := doReq(t, req)
	defer resp.Body.Close()
	var out api.AggregateScore
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode fleet score: %v", err)
		}
	}
	return resp.StatusCode, out
}

// readHostsByCounts reads a fixture's hosts list and seeds one host each,
// returning them keyed by the fixture's own id so assertions can name them.
func readHostsByCounts(t *testing.T, pool *pgxpool.Pool, user uuid.UUID,
	entries []*specfixture.Fields, engine string) map[string]uuid.UUID {
	t.Helper()
	out := map[string]uuid.UUID{}
	for _, h := range entries {
		id := h.Str("id")
		c := h.Map("counts")
		counts := map[string]int{"pass": c.Int("pass"), "fail": c.Int("fail")}
		if c.Has("skipped") {
			counts["skipped"] = c.Int("skipped")
		}
		if c.Has("error") {
			counts["error"] = c.Int("error")
		}
		c.AllConsumed()
		h.AllConsumed()
		out[id] = seedFleetHostScored(t, pool, user, counts, engine, nil)
	}
	return out
}

// assertAggregateEnvelope checks the envelope fields the aggregate criteria
// state, with the seeded engine substituted for the fixture sentinel.
func assertAggregateEnvelope(t *testing.T, env api.ScoreEnvelope, exp *specfixture.Fields, engine string) {
	t.Helper()
	if env.Lens != exp.Str("lens") {
		t.Errorf("lens = %q, want %q", env.Lens, exp.Str("lens"))
	}
	if env.FormulaVersion == nil || *env.FormulaVersion != exp.Int("formula_version") {
		t.Errorf("formula_version = %v, want %d", env.FormulaVersion, exp.Int("formula_version"))
	}
	if string(env.AggregationMethod) != exp.Str("aggregation_method") {
		t.Errorf("aggregation_method = %q, want %q; the name is part of the claim, because a "+
			"pooled ratio and an equal-host mean are different numbers",
			env.AggregationMethod, exp.Str("aggregation_method"))
	}
	if string(env.EngineIdentityStatus) != exp.Str("engine_identity_status") {
		t.Errorf("engine_identity_status = %q, want %q",
			env.EngineIdentityStatus, exp.Str("engine_identity_status"))
	}
	if env.HostsWithoutEngineIdentity != exp.Int("hosts_without_engine_identity") {
		t.Errorf("hosts_without_engine_identity = %d, want %d",
			env.HostsWithoutEngineIdentity, exp.Int("hosts_without_engine_identity"))
	}
	wantEngines := exp.MapList("engines")
	if len(env.Engines) != len(wantEngines) {
		t.Fatalf("engines = %+v, want %d entries", env.Engines, len(wantEngines))
	}
	for i, w := range wantEngines {
		want := w.Str("engine_version")
		if want == seededEngine {
			want = engine
		}
		if env.Engines[i].EngineVersion != want {
			t.Errorf("engines[%d].engine_version = %q, want %q",
				i, env.Engines[i].EngineVersion, want)
		}
		// The count is the point: it says how many SCORED hosts that engine
		// speaks for, which is what makes the identity checkable.
		if env.Engines[i].ContributorsScored != w.Int("contributors_scored") {
			t.Errorf("engines[%d].contributors_scored = %d, want %d",
				i, env.Engines[i].ContributorsScored, w.Int("contributors_scored"))
		}
		w.AllConsumed()
	}
	want := exp.Str("engine_version")
	if want == seededEngine {
		want = engine
	}
	if env.EngineVersion == nil || *env.EngineVersion != want {
		t.Errorf("engine_version = %v, want %q", env.EngineVersion, want)
	}
}

// @ac AC-05
// AC-05: pooled versus equal-host aggregation. Host A contributes ten rule
// rows and host B two, so pooling gives A five times the weight.
func TestAggregate_EqualHostMeanNotPooled(t *testing.T) {
	t.Run("system-compliance-scoring/AC-05", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-05")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		url, pool := freshAPIServer(t)
		user := firstSeededUserID(t, pool)
		if in.Str("lens") != "all_rules" || in.Str("engine_version") != seededEngine {
			t.Fatal("fixture shape changed")
		}
		engine := "kensa-0.9.0-ac05"
		readHostsByCounts(t, pool, user, in.MapList("hosts"), engine)

		status, score := getAggregateScore(t, url, "")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if score.ScorePct == nil {
			t.Fatal("score_pct is null although two hosts produced verdicts")
		}
		if *score.ScorePct != exp.Num("fleet_score_pct") {
			t.Errorf("score_pct = %v, want %v", *score.ScorePct, exp.Num("fleet_score_pct"))
		}
		// The named pooled answer. Ten passes over twelve outcomes is 83.3,
		// which is host A's score wearing the fleet's name.
		if *score.ScorePct == exp.Num("forbidden_fleet_score_pct") {
			t.Errorf("score_pct = %v, the pooled ratio; host A carries five times host B's "+
				"rule rows, so pooling reports A and calls it the fleet",
				exp.Num("forbidden_fleet_score_pct"))
		}
		assertAggregateEnvelope(t, score.Envelope, exp, engine)

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-06
// AC-06: an unscored host is omitted from the mean and counted separately.
// It must not be averaged in as zero, which would drag the fleet number down
// for a host nothing could measure.
func TestAggregate_UnscoredHostIsCountedNotAveraged(t *testing.T) {
	t.Run("system-compliance-scoring/AC-06", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-06")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		url, pool := freshAPIServer(t)
		user := firstSeededUserID(t, pool)
		if in.Str("lens") != "all_rules" || in.Str("engine_version") != seededEngine {
			t.Fatal("fixture shape changed")
		}
		engine := "kensa-0.9.0-ac06"
		readHostsByCounts(t, pool, user, in.MapList("hosts"), engine)

		status, score := getAggregateScore(t, url, "")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if score.ScorePct == nil {
			t.Fatal("score_pct is null although two hosts produced verdicts")
		}
		if *score.ScorePct != exp.Num("fleet_score_pct") {
			t.Errorf("score_pct = %v, want %v; the third host produced no verdict and belongs "+
				"in neither side of the mean", *score.ScorePct, exp.Num("fleet_score_pct"))
		}
		// Averaging the unscored host in as zero gives 46.7, a number that
		// reports a measurement failure as a compliance collapse. This is the
		// shape of OW-023 at fleet scale.
		if *score.ScorePct == exp.Num("forbidden_fleet_score_pct") {
			t.Errorf("score_pct = %v, which averages the unmeasurable host in as zero",
				exp.Num("forbidden_fleet_score_pct"))
		}
		// Omitted from the mean is not omitted from the response. The operator
		// has to see that a host went unmeasured.
		if score.HostsScored != exp.Int("hosts_scored") {
			t.Errorf("hosts_scored = %d, want %d", score.HostsScored, exp.Int("hosts_scored"))
		}
		if score.HostsWithoutScore != exp.Int("hosts_without_score") {
			t.Errorf("hosts_without_score = %d, want %d; a mean over 2 of 3 hosts and a mean "+
				"over 3 of 3 are different claims and a percentage alone cannot tell them apart",
				score.HostsWithoutScore, exp.Int("hosts_without_score"))
		}
		assertAggregateEnvelope(t, score.Envelope, exp, engine)

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-07
// AC-07: a group aggregate uses the same rule as a fleet aggregate, so the
// two agree for the same members and lens.
func TestAggregate_GroupAgreesWithFleet(t *testing.T) {
	t.Run("system-compliance-scoring/AC-07", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-07")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		url, pool := freshAPIServer(t)
		user := firstSeededUserID(t, pool)
		if in.Str("lens") != "all_rules" || in.Str("engine_version") != seededEngine {
			t.Fatal("fixture shape changed")
		}
		engine := "kensa-0.9.0-ac07"
		members := readHostsByCounts(t, pool, user, in.MapList("group_members"), engine)

		groupID := createManualGroup(t, url, "AC-07 group")
		for _, hostID := range members {
			addGroupMember(t, url, groupID, hostID)
		}

		rollup := getGroupRollup(t, url, groupID)
		if rollup.Rollup.Score.ScorePct == nil {
			t.Fatal("group score_pct is null although both members produced verdicts")
		}
		if *rollup.Rollup.Score.ScorePct != exp.Num("group_score_pct") {
			t.Errorf("group score_pct = %v, want %v",
				*rollup.Rollup.Score.ScorePct, exp.Num("group_score_pct"))
		}
		assertAggregateEnvelope(t, rollup.Rollup.Score.Envelope, exp, engine)

		// The agreement itself. The group holds every host in the fleet, so a
		// group aggregate computed by a different rule would show here.
		_, fleet := getAggregateScore(t, url, "")
		if fleet.ScorePct == nil {
			t.Error("group scored the population but fleet returned null over the same members")
		} else if *fleet.ScorePct != *rollup.Rollup.Score.ScorePct {
			// Dereferenced: a *float64 under %v prints an address, which tells
			// whoever reads the failure nothing about the disagreement.
			t.Errorf("group = %v but fleet = %v over the same members and lens; two aggregates "+
				"of one population must not be two numbers",
				*rollup.Rollup.Score.ScorePct, *fleet.ScorePct)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-10
// AC-10: lens blending. Two lenses over one host give two different scores,
// and no response carries their mean, because a percentage that names no
// lens cannot be reconciled with any rule list.
func TestHostScore_LensesAreNeverBlended(t *testing.T) {
	t.Run("system-compliance-scoring/AC-10", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-10")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		url, pool := freshAPIServer(t)
		byLens := in.Map("host_counts_by_lens")
		in.IsNull("aggregate_request_lens")

		hostID := seedHostForIntel(t, pool)
		runID := corpustest.CurrentRun(t, pool, hostID)
		if _, err := pool.Exec(t.Context(),
			`UPDATE scan_runs SET engine_version = 'kensa-0.9.0-ac10' WHERE id = $1`, runID); err != nil {
			t.Fatalf("set engine_version: %v", err)
		}
		base := time.Now().UTC().Truncate(time.Second)
		for _, lens := range []string{"cis_rhel9", "stig_rhel9"} {
			c := byLens.Map(lens)
			for _, spec := range []struct {
				status string
				n      int
			}{{"pass", c.Int("pass")}, {"fail", c.Int("fail")}} {
				for i := 0; i < spec.n; i++ {
					seedRuleState(t, pool, hostID, lens+"-"+spec.status+"-"+uuid.NewString(),
						spec.status, "medium", base, 1, `{"`+lens+`":"x"}`)
				}
			}
			c.AllConsumed()
		}
		byLens.AllConsumed()

		forbidden := exp.Num("forbidden_score_pct")
		for _, tc := range []struct{ lens, key string }{
			{"cis_rhel9", "cis_rhel9_score_pct"},
			{"stig_rhel9", "stig_rhel9_score_pct"},
		} {
			body := getLensSummary(t, url, hostID, "?framework="+tc.lens)
			s := body.Summary
			if s.ScorePct == nil {
				t.Fatalf("%s: score_pct is null", tc.lens)
			}
			if *s.ScorePct != exp.Num(tc.key) {
				t.Errorf("%s: score_pct = %v, want %v", tc.lens, *s.ScorePct, exp.Num(tc.key))
			}
			if *s.ScorePct == forbidden {
				t.Errorf("%s: score_pct = %v, the mean of the two lenses; that number belongs "+
					"to no rule list an operator can open", tc.lens, forbidden)
			}
			if body.Summary.Envelope.Lens != tc.lens {
				t.Errorf("%s: envelope names lens %q; a score that names the wrong lens is "+
					"worse than one that names none", tc.lens, body.Summary.Envelope.Lens)
			}
		}

		// An aggregate request with NO lens is not an absence. It follows
		// endpoint precedence and terminates at all_rules, because rejecting
		// the default path would fail every deployment with no org default set.
		status, score := getAggregateScore(t, url, "")
		if status != exp.Int("aggregate_no_lens_http_status") {
			t.Errorf("aggregate with no lens = %d, want %d",
				status, exp.Int("aggregate_no_lens_http_status"))
		}
		if score.Envelope.Lens != exp.Str("aggregate_no_lens_resolved_lens") {
			t.Errorf("resolved lens = %q, want %q; the response must name the lens it "+
				"terminated at rather than leaving it blank",
				score.Envelope.Lens, exp.Str("aggregate_no_lens_resolved_lens"))
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-11
// AC-11: the all-rules floor misconception. A narrow framework can score
// below the broad baseline, because a small rule set concentrates a failure.
// Neither number may be clamped toward the other.
func TestHostScore_NarrowLensMayScoreBelowAllRules(t *testing.T) {
	t.Run("system-compliance-scoring/AC-11", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-11")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		url, pool := freshAPIServer(t)
		byLens := in.Map("host_counts_by_lens")
		all := byLens.Map("all_rules")
		narrow := byLens.Map("framework_F")

		hostID := seedHostForIntel(t, pool)
		base := time.Now().UTC().Truncate(time.Second)
		// The narrow lens is a SUBSET of the broad one, which is what makes
		// the comparison meaningful: the single failing rule is counted by
		// both, and it is the whole of framework_F.
		narrowFail := narrow.Int("fail")
		for i := 0; i < narrowFail; i++ {
			seedRuleState(t, pool, hostID, "ff-fail-"+uuid.NewString(), "fail", "medium",
				base, 1, `{"framework_F":"x"}`)
		}
		for i := 0; i < narrow.Int("pass"); i++ {
			seedRuleState(t, pool, hostID, "ff-pass-"+uuid.NewString(), "pass", "medium",
				base, 1, `{"framework_F":"x"}`)
		}
		for i := 0; i < all.Int("pass"); i++ {
			seedRuleState(t, pool, hostID, "all-pass-"+uuid.NewString(), "pass", "medium",
				base, 1, "")
		}
		if extra := all.Int("fail") - narrowFail; extra > 0 {
			for i := 0; i < extra; i++ {
				seedRuleState(t, pool, hostID, "all-fail-"+uuid.NewString(), "fail", "medium",
					base, 1, "")
			}
		}
		all.AllConsumed()
		narrow.AllConsumed()
		byLens.AllConsumed()

		broad := getLensSummary(t, url, hostID, "").Summary
		if broad.ScorePct == nil {
			t.Fatal("all_rules score_pct is null")
		}
		if *broad.ScorePct != exp.Num("all_rules_score_pct") {
			t.Errorf("all_rules score_pct = %v, want %v",
				*broad.ScorePct, exp.Num("all_rules_score_pct"))
		}
		if *broad.ScorePct == exp.Num("forbidden_all_rules_score_pct") {
			t.Errorf("all_rules score_pct = %v, clamped down to the narrow lens; the broad "+
				"set has nine passing rules and they are not erased by framework_F",
				exp.Num("forbidden_all_rules_score_pct"))
		}

		narrowResp := getLensSummary(t, url, hostID, "?framework=framework_F").Summary
		if narrowResp.ScorePct == nil {
			t.Fatal("framework_F score_pct is null; one rule produced a verdict")
		}
		if *narrowResp.ScorePct != exp.Num("framework_F_score_pct") {
			t.Errorf("framework_F score_pct = %v, want %v",
				*narrowResp.ScorePct, exp.Num("framework_F_score_pct"))
		}
		if *narrowResp.ScorePct == exp.Num("forbidden_framework_F_score_pct") {
			t.Errorf("framework_F score_pct = %v, clamped up to the broad baseline; a small "+
				"rule set concentrates a failure and that is the real answer",
				exp.Num("forbidden_framework_F_score_pct"))
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// createManualGroup creates an empty manual site group and returns its id.
func createManualGroup(t *testing.T, url, name string) uuid.UUID {
	t.Helper()
	body := map[string]any{"name": name, "kind": "site", "membership": "manual"}
	req := asRole(t, "POST", url+"/api/v1/groups", auth.RoleOpsLead, body)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create group = %d: %s", resp.StatusCode, b)
	}
	var out struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode group: %v", err)
	}
	return out.ID
}

func addGroupMember(t *testing.T, url string, groupID, hostID uuid.UUID) {
	t.Helper()
	req := asRole(t, "POST", url+"/api/v1/groups/"+groupID.String()+"/members",
		auth.RoleOpsLead, map[string]any{"host_id": hostID.String()})
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent &&
		resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("add member = %d: %s", resp.StatusCode, b)
	}
}

func getGroupRollup(t *testing.T, url string, groupID uuid.UUID) api.GroupWithRollup {
	t.Helper()
	req := asRole(t, "GET", url+"/api/v1/groups", auth.RoleViewer, nil)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("list groups = %d: %s", resp.StatusCode, b)
	}
	var out api.GroupListResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode groups: %v", err)
	}
	for _, g := range out.Groups {
		if g.Id == groupID {
			return g
		}
	}
	t.Fatalf("group %s not in the list", groupID)
	return api.GroupWithRollup{}
}
