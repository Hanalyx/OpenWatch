// @spec api-reports
//
// Pure (no-DB) coverage for the report service. These cases exercise the
// content-shaping and value contracts that do NOT touch Postgres:
//
//	AC-01  TestExecutiveContent_JSONShape   (stored JSON document shape)
//	AC-02  TestCompliancePct_Rounding       (round-half-up + nil-when-unevaluated)
//	AC-03  TestExecutiveConstants_Derivation (fixed title/scope/kind/format)
//
// The DB-backed generation, list, and fetch paths run against a real
// schema and are OPENWATCH_TEST_DSN-gated in service_db_test.go.

package report

import (
	"encoding/json"
	"testing"
)

// @ac AC-01
// The executive summary is frozen as a JSON document at generation time,
// so its on-the-wire shape is a contract: the detail view and any later
// renderer read these exact keys. This marshals an ExecutiveContent and
// asserts the field names, the nil compliance encoding, and that the
// top-failing list preserves the service's order (most-failing first).
func TestExecutiveContent_JSONShape(t *testing.T) {
	t.Run("api-reports/AC-01", func(t *testing.T) {
		pct := 82
		c := ExecutiveContent{
			CompliancePct:  &pct,
			HostCount:      7,
			PassingRules:   140,
			FailingRules:   31,
			CriticalIssues: 4,
			TopFailingRules: []TopFailingRule{
				{RuleID: "rule-a", FailingHostCount: 6},
				{RuleID: "rule-b", FailingHostCount: 2},
			},
		}

		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("marshal ExecutiveContent: %v", err)
		}

		var got map[string]json.RawMessage
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal to map: %v", err)
		}
		for _, key := range []string{
			"compliance_pct", "host_count", "passing_rules",
			"failing_rules", "critical_issues", "top_failing_rules",
		} {
			if _, ok := got[key]; !ok {
				t.Errorf("missing JSON key %q in %s", key, raw)
			}
		}

		// Round-trip the whole document so a renaming of a Go field (without
		// updating its json tag) is caught, and ordering is preserved.
		var back ExecutiveContent
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatalf("round-trip unmarshal: %v", err)
		}
		if back.CompliancePct == nil || *back.CompliancePct != 82 {
			t.Errorf("compliance_pct round-trip = %v, want 82", back.CompliancePct)
		}
		if back.HostCount != 7 || back.PassingRules != 140 ||
			back.FailingRules != 31 || back.CriticalIssues != 4 {
			t.Errorf("counts round-trip = %+v", back)
		}
		if len(back.TopFailingRules) != 2 ||
			back.TopFailingRules[0].RuleID != "rule-a" ||
			back.TopFailingRules[0].FailingHostCount != 6 ||
			back.TopFailingRules[1].RuleID != "rule-b" {
			t.Errorf("top_failing_rules order/shape = %+v", back.TopFailingRules)
		}

		// A never-evaluated fleet encodes compliance_pct as JSON null (not 0,
		// and not omitted): the UI distinguishes "unknown" from "0%".
		var nilC ExecutiveContent
		nilRaw, err := json.Marshal(nilC)
		if err != nil {
			t.Fatalf("marshal nil-compliance content: %v", err)
		}
		var nilMap map[string]json.RawMessage
		if err := json.Unmarshal(nilRaw, &nilMap); err != nil {
			t.Fatalf("unmarshal nil content: %v", err)
		}
		if string(nilMap["compliance_pct"]) != "null" {
			t.Errorf("nil compliance_pct = %s, want null", nilMap["compliance_pct"])
		}
		// An unset top-failing slice still serializes as [] (never JSON null)
		// is only guaranteed by the service initialising it; the zero value
		// here is nil and serializes as null, which the service avoids by
		// assigning an empty slice. Assert the service's contract indirectly:
		// an explicitly empty slice serializes as [].
		emptyRaw, _ := json.Marshal(ExecutiveContent{TopFailingRules: []TopFailingRule{}})
		var emptyMap map[string]json.RawMessage
		if err := json.Unmarshal(emptyRaw, &emptyMap); err != nil {
			t.Fatalf("unmarshal empty content: %v", err)
		}
		if string(emptyMap["top_failing_rules"]) != "[]" {
			t.Errorf("empty top_failing_rules = %s, want []", emptyMap["top_failing_rules"])
		}
	})
}

// @ac AC-02
// compliancePct is the rounding contract behind the headline number. It
// must round half up and return nil (not 0) when nothing was evaluated, so
// the document can distinguish an unscanned fleet from a fully failing one.
func TestCompliancePct_Rounding(t *testing.T) {
	t.Run("api-reports/AC-02", func(t *testing.T) {
		cases := []struct {
			name    string
			passing int
			eval    int
			wantNil bool
			wantPct int
		}{
			{name: "unevaluated -> nil", passing: 0, eval: 0, wantNil: true},
			{name: "all passing -> 100", passing: 4, eval: 4, wantPct: 100},
			{name: "none passing -> 0 (not nil)", passing: 0, eval: 4, wantPct: 0},
			{name: "exact 75", passing: 3, eval: 4, wantPct: 75},
			{name: "round half up (1/3 = 33.3 -> 33)", passing: 1, eval: 3, wantPct: 33},
			{name: "round half up (2/3 = 66.7 -> 67)", passing: 2, eval: 3, wantPct: 67},
			{name: "round half up (1/8 = 12.5 -> 13)", passing: 1, eval: 8, wantPct: 13},
			{name: "negative evaluated -> nil", passing: 5, eval: -1, wantNil: true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got := compliancePct(tc.passing, tc.eval)
				if tc.wantNil {
					if got != nil {
						t.Fatalf("compliancePct(%d,%d) = %v, want nil", tc.passing, tc.eval, *got)
					}
					return
				}
				if got == nil {
					t.Fatalf("compliancePct(%d,%d) = nil, want %d", tc.passing, tc.eval, tc.wantPct)
				}
				if *got != tc.wantPct {
					t.Errorf("compliancePct(%d,%d) = %d, want %d", tc.passing, tc.eval, *got, tc.wantPct)
				}
			})
		}
	})
}

// @ac AC-03
// The MVP generates exactly one kind. The fixed title, scope, kind, and the
// top-failing cap are part of the artifact's identity (the library lists
// them, and signing later depends on them being stable), so pin them here.
func TestExecutiveConstants_Derivation(t *testing.T) {
	t.Run("api-reports/AC-03", func(t *testing.T) {
		if executiveTitle != "Fleet Compliance - Executive Summary" {
			t.Errorf("executiveTitle = %q", executiveTitle)
		}
		if executiveScope != "All hosts" {
			t.Errorf("executiveScope = %q", executiveScope)
		}
		if KindExecutive != "executive" {
			t.Errorf("KindExecutive = %q, want executive", KindExecutive)
		}
		// The leadership-facing list is intentionally short.
		if topFailingLimit != 5 {
			t.Errorf("topFailingLimit = %d, want 5", topFailingLimit)
		}
	})
}
