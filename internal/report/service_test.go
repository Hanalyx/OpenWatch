// @spec api-reports
//
// Pure (no-DB) coverage for the report service. These cases exercise the
// content-shaping and value contracts that do NOT touch Postgres:
//
//	AC-01  TestExecutiveContent_JSONShape   (stored JSON document shape)
//	AC-02  TestScorePct_OneDecimalOrNull    (equal-host mean, null when unscored)
//	AC-03  TestExecutiveConstants_Derivation (fixed title/scope/kind/format)
//	AC-07  TestScopeLabel_Derivation         (scope_label + framework family)
//
// The DB-backed generation, list, and fetch paths run against a real
// schema and are OPENWATCH_TEST_DSN-gated in service_db_test.go.

package report

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/Hanalyx/openwatch/internal/compliance"
)

// @ac AC-01
// The executive summary is frozen as a JSON document at generation time,
// so its on-the-wire shape is a contract: the detail view and any later
// renderer read these exact keys. This marshals an ExecutiveContent and
// asserts the field names, the nil compliance encoding, and that the
// top-failing list preserves the service's order (most-failing first).
func TestExecutiveContent_JSONShape(t *testing.T) {
	t.Run("api-reports/AC-01", func(t *testing.T) {
		pct := 82.0
		c := ExecutiveContent{
			ScorePct:       &pct,
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
			"score_pct", "host_count", "passing_rules",
			"failing_rules", "critical_issues", "top_failing_rules", "coverage",
		} {
			if _, ok := got[key]; !ok {
				t.Errorf("missing JSON key %q in %s", key, raw)
			}
		}
		// The replaced key must be gone from a current artifact, not merely
		// unused. It is omitempty and decode-only, so a generated document
		// carries exactly one score.
		if _, present := got["compliance_pct"]; present {
			t.Errorf("compliance_pct is still emitted in %s; a current artifact must expose "+
				"one authoritative number, not two plausible ones", raw)
		}
		// coverage is an object carrying its own fixed keys.
		var cov map[string]json.RawMessage
		if err := json.Unmarshal(got["coverage"], &cov); err != nil {
			t.Fatalf("coverage is not an object: %v", err)
		}
		for _, key := range []string{"hosts_total", "hosts_fresh", "hosts_stale", "hosts_unreachable"} {
			if _, ok := cov[key]; !ok {
				t.Errorf("missing coverage key %q in %s", key, got["coverage"])
			}
		}

		// Round-trip the whole document so a renaming of a Go field (without
		// updating its json tag) is caught, and ordering is preserved.
		var back ExecutiveContent
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatalf("round-trip unmarshal: %v", err)
		}
		if back.ScorePct == nil || *back.ScorePct != 82 {
			t.Errorf("score_pct round-trip = %v, want 82", back.ScorePct)
		}
		// The replaced key must not reappear. It is decode-only, so nothing
		// sets it and omitempty keeps it out of every generated artifact.
		if back.LegacyCompliancePct != nil {
			t.Errorf("compliance_pct = %v on a current artifact; the pooled whole percent is "+
				"decode-only and a current artifact carries exactly one score",
				*back.LegacyCompliancePct)
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
		// Null, not omitted and not zero. A fleet nothing could measure and a
		// fleet that failed everything are different facts.
		if string(nilMap["score_pct"]) != "null" {
			t.Errorf("nil score_pct = %s, want null", nilMap["score_pct"])
		}
		// An unset top-failing slice still serializes as [] (never JSON null)
		// is only guaranteed by the service initializing it; the zero value
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
// scorePtr is the rendering contract behind the headline number: the
// canonical one-decimal value, or null when no host produced a verdict.
//
// It replaced compliancePct, which returned a POOLED whole percent. Both
// halves of that were wrong. Pooling weighted a host by how many rules it
// carried, and a whole percent could never equal the one-decimal score the
// rest of the product reports, so a signed artifact disagreed with the app
// by construction.
func TestScorePct_OneDecimalOrNull(t *testing.T) {
	t.Run("api-reports/AC-02", func(t *testing.T) {
		cases := []struct {
			name    string
			hosts   []compliance.Counts
			wantNil bool
			wantPct float64
		}{
			{name: "no hosts -> null", wantNil: true},
			{name: "no host produced a verdict -> null",
				hosts: []compliance.Counts{{Skipped: 40}}, wantNil: true},
			{name: "every evaluated rule failed -> 0, not null",
				hosts: []compliance.Counts{{Fail: 5}}, wantPct: 0},
			{name: "all passing -> 100",
				hosts: []compliance.Counts{{Pass: 4}}, wantPct: 100},
			// The counterexample the whole change exists for. Pooling gives
			// 10 passes over 12 outcomes, 83.3; one host one vote gives 70.0.
			{name: "equal-host mean, not pooled",
				hosts:   []compliance.Counts{{Pass: 9, Fail: 1}, {Pass: 1, Fail: 1}},
				wantPct: 70},
			// One decimal is kept, not rounded away to a whole percent.
			{name: "one decimal survives",
				hosts: []compliance.Counts{{Pass: 2, Fail: 1}}, wantPct: 66.7},
			// An unscored host is counted, never averaged in as zero.
			{name: "unscored host omitted from the mean",
				hosts: []compliance.Counts{{Pass: 9, Fail: 1}, {Pass: 1, Fail: 1},
					{Skipped: 40}},
				wantPct: 70},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				scores := make([]compliance.Score, 0, len(tc.hosts))
				for _, h := range tc.hosts {
					scores = append(scores, compliance.HostScore(h))
				}
				got := scorePtr(compliance.MeanOfHostScores(scores).Score)
				if tc.wantNil {
					if got != nil {
						t.Fatalf("score_pct = %v, want null; no host produced a verdict and "+
							"a number here would report a measurement failure as a verdict",
							*got)
					}
					return
				}
				if got == nil {
					t.Fatalf("score_pct = null, want %v", tc.wantPct)
				}
				if *got != tc.wantPct {
					t.Errorf("score_pct = %v, want %v", *got, tc.wantPct)
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
		// The default (unscoped) label is "All hosts".
		if allHostsLabel != "All hosts" {
			t.Errorf("allHostsLabel = %q", allHostsLabel)
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

// @ac AC-07
// scope_label is derived from the resolved scope: the group name (or "All
// hosts") optionally suffixed with the framework family. The framework key
// is shortened to its family token (before the first underscore),
// uppercased. Pure, so the labeling contract is unit-tested directly.
func TestScopeLabel_Derivation(t *testing.T) {
	t.Run("api-reports/AC-07", func(t *testing.T) {
		gid := uuid.New()
		cases := []struct {
			name  string
			scope Scope
			want  string
		}{
			{"unscoped", Scope{}, "All hosts"},
			{"framework only", Scope{Framework: "cis_rhel9_v2.0.0"}, "All hosts · CIS"},
			{"group only", Scope{GroupID: &gid, GroupName: "Production"}, "Production"},
			{"group and framework", Scope{GroupID: &gid, GroupName: "Production", Framework: "stig_rhel9_v2r7"}, "Production · STIG"},
			{"framework no underscore", Scope{Framework: "pci"}, "All hosts · PCI"},
		}
		for _, tc := range cases {
			if got := scopeLabel(tc.scope); got != tc.want {
				t.Errorf("%s: scopeLabel = %q, want %q", tc.name, got, tc.want)
			}
		}
		// frameworkFamilyLabel directly: empty in -> empty out.
		if got := frameworkFamilyLabel(""); got != "" {
			t.Errorf("frameworkFamilyLabel(\"\") = %q, want empty", got)
		}
		if got := frameworkFamilyLabel("nist_800_53_r5"); got != "NIST" {
			t.Errorf("frameworkFamilyLabel(nist...) = %q, want NIST", got)
		}
	})
}
