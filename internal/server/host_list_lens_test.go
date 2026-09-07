// @spec api-host-compliance
//
// Which lens a host-list envelope names.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/Hanalyx/openwatch/internal/auth"
	"github.com/Hanalyx/openwatch/internal/specfixture"
	"github.com/google/uuid"
)

// @ac AC-20
// AC-20: each host-list envelope names the lens THAT HOST was scored under.
//
// The query already resolved it per host, including overrides. The mapper used
// to re-derive a single lens from the caller's variables, so a host filtered by
// its own stig target came back labeled all_rules. Two hosts in one response,
// one with an override and one without, is the only shape that catches it: with
// one host the wrong answer and the right answer can coincide.
func TestHostList_EnvelopeNamesTheHostsOwnLens(t *testing.T) {
	t.Run("api-host-compliance/AC-20", func(t *testing.T) {
		url, pool := freshAPIServer(t)
		ctx := context.Background()
		ac := specfixture.Get(t, specfixture.Load(t,
			"../../specs/api/host-compliance.spec.yaml", "api-host-compliance"), "AC-20")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		// The host with its own compliance target. Its stig rules score 50; its
		// cis rules would score 100, so a wrong lens gives a different number as
		// well as a different label.
		over := in.Map("overridden_host")
		overridden := seedHostForIntel(t, pool)
		if _, err := pool.Exec(ctx,
			`UPDATE hosts SET os_family='rhel', os_version='9.6', target_framework=$2 WHERE id=$1`,
			overridden, over.Str("target_framework")); err != nil {
			t.Fatalf("set host target: %v", err)
		}
		for i := 0; i < over.Int("stig_pass"); i++ {
			seedRuleStateForHostWithFrameworks(t, pool, overridden, fmt.Sprintf("sp%d", i), "pass",
				map[string]string{"stig_rhel9": "V-1"})
		}
		for i := 0; i < over.Int("stig_fail"); i++ {
			seedRuleStateForHostWithFrameworks(t, pool, overridden, fmt.Sprintf("sf%d", i), "fail",
				map[string]string{"stig_rhel9": "V-2"})
		}
		for i := 0; i < over.Int("cis_pass"); i++ {
			seedRuleStateForHostWithFrameworks(t, pool, overridden, fmt.Sprintf("cp%d", i), "pass",
				map[string]string{"cis_rhel9": "1.1"})
		}
		over.AllConsumed()

		// The host with no override. It falls through to all rules.
		plainFix := in.Map("plain_host")
		plain := seedHostForIntel(t, pool)
		if _, err := pool.Exec(ctx,
			`UPDATE hosts SET os_family='rhel', os_version='9.6' WHERE id=$1`, plain); err != nil {
			t.Fatalf("set plain host os: %v", err)
		}
		for i := 0; i < plainFix.Int("cis_pass"); i++ {
			seedRuleStateForHostWithFrameworks(t, pool, plain, fmt.Sprintf("pp%d", i), "pass",
				map[string]string{"cis_rhel9": "1.1"})
		}
		for i := 0; i < plainFix.Int("cis_fail"); i++ {
			seedRuleStateForHostWithFrameworks(t, pool, plain, fmt.Sprintf("pf%d", i), "fail",
				map[string]string{"cis_rhel9": "1.2"})
		}
		plainFix.AllConsumed()

		// No request lens and no org default, which is exactly the case the old
		// mapper labeled all_rules for everyone.
		if q := in.Str("request_lens"); q != "" {
			t.Fatalf("fixture sets a request lens %q; this criterion is about the defaulted path", q)
		}
		if d := in.Str("org_default"); d != "" {
			t.Fatalf("fixture sets an org default %q; this criterion is about the defaulted path", d)
		}

		req := asRole(t, "GET", url+"/api/v1/hosts?limit=50", auth.RoleViewer, nil)
		resp := doReq(t, req)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var body struct {
			Hosts []struct {
				ID                string `json:"id"`
				ComplianceSummary *struct {
					ScorePct *float64 `json:"score_pct"`
					Envelope struct {
						Lens string `json:"lens"`
					} `json:"envelope"`
				} `json:"compliance_summary"`
			} `json:"hosts"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}

		find := func(id uuid.UUID) (string, *float64) {
			t.Helper()
			for _, it := range body.Hosts {
				if it.ID != id.String() {
					continue
				}
				if it.ComplianceSummary == nil {
					t.Fatalf("host %s has no compliance summary", id)
				}
				return it.ComplianceSummary.Envelope.Lens, it.ComplianceSummary.ScorePct
			}
			t.Fatalf("host %s not in the list", id)
			return "", nil
		}

		overLens, overScore := find(overridden)
		if overLens != exp.Str("overridden_host_lens") {
			t.Errorf("overridden host envelope lens = %q, want %q; the query filtered it by that "+
				"lens, so the envelope must name it", overLens, exp.Str("overridden_host_lens"))
		}
		if bad := exp.Str("forbidden_overridden_host_lens"); overLens == bad {
			t.Errorf("overridden host envelope lens = %q, which is the caller's default rather "+
				"than the lens this host was scored under", bad)
		}
		if overScore == nil || *overScore != exp.Num("overridden_host_score_pct") {
			t.Errorf("overridden host score = %v, want %v (its stig rules only)",
				overScore, exp.Num("overridden_host_score_pct"))
		}

		plainLens, plainScore := find(plain)
		if plainLens != exp.Str("plain_host_lens") {
			t.Errorf("plain host envelope lens = %q, want %q", plainLens, exp.Str("plain_host_lens"))
		}
		if plainScore == nil || *plainScore != exp.Num("plain_host_score_pct") {
			t.Errorf("plain host score = %v, want %v", plainScore, exp.Num("plain_host_score_pct"))
		}

		// The point of seeding two hosts: one response must carry two different
		// lenses, which a single re-derived value cannot produce.
		if !exp.Bool("lenses_differ") {
			t.Fatal("fixture must require the two lenses to differ")
		}
		if overLens == plainLens {
			t.Errorf("both hosts reported lens %q; a per-host envelope cannot be one value "+
				"derived from the request", overLens)
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}
