// @spec system-compliance-scoring
//
// The host score end to end: what the denominator counts, what a host with
// no verdict reports, and how those two stay distinguishable on the wire.
//
// AC-02 and AC-03 are the pair that matters. One host produced no verdict
// and one failed everything it evaluated. Both read as a very low number
// under the replaced formula, and an operator cannot act on them the same
// way, so score_pct alone has to tell them apart.
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
	"github.com/Hanalyx/openwatch/internal/server/api"
	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// seededEngine is the sentinel the fixtures write where they mean "whatever
// engine version this test seeded". Comparing against the literal would
// assert the placeholder rather than the value.
const seededEngine = "<seeded>"

// seedScoredHost seeds one host whose completed scan recorded engineVersion,
// with rule states matching a fixture's counts block.
//
// Rule ids are distinct per status so nothing collapses on the primary key,
// and every row hangs off the SAME scan run, which is what binds the engine
// version to these counts rather than to a run that finished later.
func seedScoredHost(t *testing.T, pool *pgxpool.Pool, counts map[string]int,
	engineVersion string, frameworkRefs string) uuid.UUID {
	t.Helper()
	hostID := seedHostForIntel(t, pool)
	runID := corpustest.CurrentRun(t, pool, hostID)
	if _, err := pool.Exec(context.Background(),
		`UPDATE scan_runs SET engine_version = $2 WHERE id = $1`, runID, engineVersion); err != nil {
		t.Fatalf("set engine_version: %v", err)
	}
	base := time.Now().UTC().Truncate(time.Second)
	for _, status := range []string{"pass", "fail", "skipped", "error"} {
		for i := 0; i < counts[status]; i++ {
			seedRuleState(t, pool, hostID,
				status+"-"+uuid.NewString(), status, "medium", base, 1, frameworkRefs)
		}
	}
	return hostID
}

// getLensSummary GETs the host compliance lens and returns the decoded
// response, including the envelope the narrower lensResp in the neighboring
// file does not carry.
func getLensSummary(t *testing.T, url string, hostID uuid.UUID, query string) api.HostComplianceLensResponse {
	t.Helper()
	req := asRole(t, "GET", url+"/api/v1/hosts/"+hostID.String()+"/compliance"+query,
		auth.RoleViewer, nil)
	resp := doReq(t, req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET compliance%s = %d: %s", query, resp.StatusCode, b)
	}
	var out api.HostComplianceLensResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode lens: %v", err)
	}
	return out
}

// readFixtureCounts reads a counts block into a status-keyed map.
func readFixtureCounts(t *testing.T, in *specfixture.Fields) map[string]int {
	t.Helper()
	c := in.Map("counts")
	out := map[string]int{
		"pass": c.Int("pass"), "fail": c.Int("fail"),
		"skipped": c.Int("skipped"), "error": c.Int("error"),
	}
	c.AllConsumed()
	return out
}

// assertEnvelopeCommon checks the envelope fields every host-level criterion
// states: lens, formula version, aggregation method and engine identity.
func assertEnvelopeCommon(t *testing.T, env api.ScoreEnvelope, exp *specfixture.Fields, engine string) {
	t.Helper()
	if env.Lens != exp.Str("lens") {
		t.Errorf("lens = %q, want %q; a percentage that names no lens cannot be reconciled "+
			"with any rule list", env.Lens, exp.Str("lens"))
	}
	if env.FormulaVersion == nil || *env.FormulaVersion != exp.Int("formula_version") {
		t.Errorf("formula_version = %v, want %d", env.FormulaVersion, exp.Int("formula_version"))
	}
	if string(env.AggregationMethod) != exp.Str("aggregation_method") {
		t.Errorf("aggregation_method = %q, want %q; one host averages nothing",
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
			t.Errorf("engines[%d].engine_version = %q, want %q; it is copied from the scan "+
				"run, never from the process answering the request",
				i, env.Engines[i].EngineVersion, want)
		}
		if env.Engines[i].ContributorsScored != w.Int("contributors_scored") {
			t.Errorf("engines[%d].contributors_scored = %d, want %d",
				i, env.Engines[i].ContributorsScored, w.Int("contributors_scored"))
		}
		w.AllConsumed()
	}

	if exp.IsNullable("engine_version") {
		// IsNull, not IsNullable: the branch predicate does not count as
		// consuming the key, so asserting through it left engine_version
		// unread on every null fixture.
		exp.IsNull("engine_version")
		if env.EngineVersion != nil {
			t.Errorf("engine_version = %q, want null; the singular field carries a value only "+
				"when one engine accounts for every scored host", *env.EngineVersion)
		}
		return
	}
	want := exp.Str("engine_version")
	if want == seededEngine {
		want = engine
	}
	if env.EngineVersion == nil || *env.EngineVersion != want {
		t.Errorf("engine_version = %v, want %q", env.EngineVersion, want)
	}
}

// @ac AC-01
// AC-01: the host score counts only confirmed verdicts. The legacy
// denominator counted every outcome and read 53.3 for this fixture, treating
// three inapplicable rules and two unknown ones as failures.
func TestHostScore_CountsOnlyConfirmedVerdicts(t *testing.T) {
	t.Run("system-compliance-scoring/AC-01", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-01")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		url, pool := freshAPIServer(t)
		if in.Str("lens") != "all_rules" {
			t.Fatalf("fixture lens %q; this test drives the unnarrowed lens", in.Str("lens"))
		}
		if in.Str("engine_version") != seededEngine {
			t.Fatalf("fixture engine_version %q, want the seeded sentinel", in.Str("engine_version"))
		}
		engine := "kensa-0.9.0-ac01"
		counts := readFixtureCounts(t, in)
		hostID := seedScoredHost(t, pool, counts, engine, "")

		body := getLensSummary(t, url, hostID, "")
		s := body.Summary

		if s.ScorePct == nil {
			t.Fatal("score_pct is null although ten rules produced a verdict")
		}
		if *s.ScorePct != exp.Num("score_pct") {
			t.Errorf("score_pct = %v, want %v", *s.ScorePct, exp.Num("score_pct"))
		}
		// The named wrong answer, not merely "something else". A guard that
		// only checked inequality would pass on any other broken formula.
		if *s.ScorePct == exp.Num("forbidden_score_pct") {
			t.Errorf("score_pct = %v, the passing-over-every-outcome answer this replaces; it "+
				"counts %d skipped and %d errored rules as failures",
				*s.ScorePct, counts["skipped"], counts["error"])
		}
		assertEnvelopeCommon(t, s.Envelope, exp, engine)

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-02
// AC-02: a host that produced no verdict has no score. The response carries
// the raw counts and the interim coverage status, and no assessment_state.
func TestHostScore_NoVerdictHasNoScore(t *testing.T) {
	t.Run("system-compliance-scoring/AC-02", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-02")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		url, pool := freshAPIServer(t)
		if in.Str("lens") != "all_rules" || in.Str("engine_version") != seededEngine {
			t.Fatal("fixture shape changed")
		}
		engine := "kensa-0.9.0-ac02"
		counts := readFixtureCounts(t, in)
		hostID := seedScoredHost(t, pool, counts, engine, "")

		body := getLensSummary(t, url, hostID, "")
		s := body.Summary

		exp.IsNull("score_pct")
		if s.ScorePct != nil {
			t.Errorf("score_pct = %v, want null; nothing was evaluated, so there is no "+
				"percentage of evaluated rules that passed", *s.ScorePct)
		}
		// Read unconditionally. Guarded by ScorePct != nil it was never read
		// on the very fixture it describes, so the value went unasserted.
		forbidden := exp.Num("forbidden_score_pct")
		if s.ScorePct != nil && *s.ScorePct == forbidden {
			t.Errorf("score_pct = %v, which is the verdict AC-03 describes and this host did "+
				"not produce; the two cases must stay distinguishable by score_pct alone",
				forbidden)
		}
		// The counts survive. Withholding them too would leave the operator
		// with a blank tile and no signal at all.
		if s.Skipped != int64(exp.Int("skipped")) {
			t.Errorf("skipped = %d, want %d", s.Skipped, exp.Int("skipped"))
		}
		if string(s.CoverageStatus) != exp.Str("coverage_status") {
			t.Errorf("coverage_status = %q, want %q", s.CoverageStatus, exp.Str("coverage_status"))
		}
		exp.IsNull("assessment_coverage_pct")
		if s.CoveragePct != nil {
			t.Errorf("coverage_pct = %v, want null under %q", *s.CoveragePct, s.CoverageStatus)
		}
		// A host with no score names no engine: the envelope counts
		// contributors to a SCORE, and this host contributed none.
		assertEnvelopeCommon(t, s.Envelope, exp, engine)
		assertFieldsAbsent(t, url, hostID, exp.StrList("absent_fields"))

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-03
// AC-03: genuine zero percent. Every evaluated rule failed, which is a real
// verdict and not an absence, and it must be distinguishable from AC-02 by
// score_pct alone.
func TestHostScore_ZeroIsAVerdictNotAnAbsence(t *testing.T) {
	t.Run("system-compliance-scoring/AC-03", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-03")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		url, pool := freshAPIServer(t)
		if in.Str("lens") != "all_rules" || in.Str("engine_version") != seededEngine {
			t.Fatal("fixture shape changed")
		}
		engine := "kensa-0.9.0-ac03"
		counts := readFixtureCounts(t, in)
		hostID := seedScoredHost(t, pool, counts, engine, "")

		body := getLensSummary(t, url, hostID, "")
		s := body.Summary

		if s.ScorePct == nil {
			t.Fatal("score_pct is null although five rules returned a verdict; every one of " +
				"them failing is an answer, not a missing answer")
		}
		if *s.ScorePct != exp.Num("score_pct") {
			t.Errorf("score_pct = %v, want %v", *s.ScorePct, exp.Num("score_pct"))
		}
		assertEnvelopeCommon(t, s.Envelope, exp, engine)
		assertFieldsAbsent(t, url, hostID, exp.StrList("absent_fields"))

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-13
// AC-13: coverage is null when a lens produced no outcomes at all, with its
// own status so the reason is stated rather than inferred from a null.
//
// The lens produced no outcomes, so there is no score and therefore no
// engine contributor: the identity is unavailable with an empty list and a
// null version, even though the seeded scan recorded an engine.
func TestHostScore_LensWithNoOutcomes(t *testing.T) {
	t.Run("system-compliance-scoring/AC-13", func(t *testing.T) {
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/system/compliance-scoring.spec.yaml", "system-compliance-scoring"), "AC-13")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		url, pool := freshAPIServer(t)
		lens := in.Str("lens")
		if in.Str("engine_version") != seededEngine {
			t.Fatal("fixture shape changed")
		}
		engine := "kensa-0.9.0-ac13"
		counts := readFixtureCounts(t, in)
		for status, n := range counts {
			if n != 0 {
				t.Fatalf("fixture seeds %d %s outcomes; this criterion is the empty lens", n, status)
			}
		}
		// Rules exist on the host, under a DIFFERENT framework. The lens
		// matching nothing is the subject; a host with no rows at all would
		// pass this test without the lens filter doing any work.
		hostID := seedScoredHost(t, pool, map[string]int{"pass": 2, "fail": 1},
			engine, `{"framework_other":"x"}`)

		unfiltered := getLensSummary(t, url, hostID, "")
		if unfiltered.Summary.ScorePct == nil {
			t.Fatal("the host has no score without the lens filter, so the filter is not what " +
				"produces the empty result below")
		}

		body := getLensSummary(t, url, hostID, "?framework="+lens)
		s := body.Summary

		exp.IsNull("score_pct")
		if s.ScorePct != nil {
			t.Errorf("score_pct = %v, want null; the lens matched no rule on this host",
				*s.ScorePct)
		}
		if string(s.CoverageStatus) != exp.Str("coverage_status") {
			t.Errorf("coverage_status = %q, want %q; zero counts cannot tell \"no rule "+
				"applies\" from \"never scanned\" from \"the scan aborted\"",
				s.CoverageStatus, exp.Str("coverage_status"))
		}
		exp.IsNull("assessment_coverage_pct")
		if s.CoveragePct != nil {
			t.Errorf("coverage_pct = %v, want null", *s.CoveragePct)
		}
		assertEnvelopeCommon(t, s.Envelope, exp, engine)

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// assertFieldsAbsent re-reads the raw response body and checks that no named
// field is present as a key.
//
// Decoding into the generated struct cannot see this: a field absent from
// the contract is absent from the struct, so a handler that added one would
// be invisible to every typed assertion above.
func assertFieldsAbsent(t *testing.T, url string, hostID uuid.UUID, fields []string) {
	t.Helper()
	if len(fields) == 0 {
		t.Fatal("no fields named; an absence check over nothing proves nothing")
	}
	req := asRole(t, "GET", url+"/api/v1/hosts/"+hostID.String()+"/compliance", auth.RoleViewer, nil)
	resp := doReq(t, req)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse body: %v", err)
	}
	keys := map[string]bool{}
	var walk func(any)
	walk = func(n any) {
		switch v := n.(type) {
		case map[string]any:
			for k, child := range v {
				keys[k] = true
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(doc)
	if !keys["score_pct"] {
		t.Fatal("the key walker cannot see score_pct, which the response does carry; its " +
			"clean result would mean nothing")
	}
	for _, f := range fields {
		if keys[f] {
			t.Errorf("the response carries %q; it is part of the reason vocabulary KN-OW-021 "+
				"defines and must be absent, not null and not defaulted", f)
		}
	}
}
