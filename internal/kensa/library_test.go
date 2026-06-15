// @spec api-rules
//
// AC traceability (this file):
//   AC-01  TestGroupRefs
//   AC-02  TestFromSummary
//   (TestRuleLibrary_RealCorpus is an un-annotated corpus-gated bonus)

package kensa

import (
	"os"
	"reflect"
	"testing"

	kensaapi "github.com/Hanalyx/kensa/api"
	pkgkensa "github.com/Hanalyx/kensa/pkg/kensa"
)

// @ac AC-01
func TestGroupRefs(t *testing.T) {
	t.Run("api-rules/AC-01", func(t *testing.T) {
		// kensa already normalizes References into FrameworkRef{id, control};
		// we only group them by framework id into the wire shape, sorted.
		refs := []kensaapi.FrameworkRef{
			{FrameworkID: "cis_rhel9", ControlID: "6.3.1.4"},
			{FrameworkID: "nist_800_53", ControlID: "AU-3"},
			{FrameworkID: "nist_800_53", ControlID: "AU-2"},
			{FrameworkID: "nist_800_53", ControlID: "AU-12"},
			{FrameworkID: "stig_rhel9", ControlID: "V-258151"},
			{FrameworkID: "", ControlID: "skip-me"}, // empty id dropped
		}
		got := groupRefs(refs)
		want := map[string][]string{
			"cis_rhel9":   {"6.3.1.4"},
			"stig_rhel9":  {"V-258151"},
			"nist_800_53": {"AU-12", "AU-2", "AU-3"}, // grouped + sorted
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("groupRefs =\n  %v\nwant\n  %v", got, want)
		}
	})
}

// @ac AC-02
func TestFromSummary(t *testing.T) {
	t.Run("api-rules/AC-02", func(t *testing.T) {
		s := pkgkensa.RuleSummary{
			ID: "auditd-enabled", Title: "Install and enable auditd",
			Description: "The audit daemon must be installed and running.",
			Severity:    "high", Category: "audit", Tags: []string{"audit"},
			FrameworkRefs: []kensaapi.FrameworkRef{
				{FrameworkID: "cis_rhel9", ControlID: "6.3.1.4"},
				{FrameworkID: "nist_800_53", ControlID: "AU-2"},
			},
			Transactional: true,
			Remediation: pkgkensa.RemediationSummary{
				Available:        true,
				Mechanisms:       []string{"service_enabled"},
				RestartsServices: []string{"auditd"},
				RebootBehavior:   "none",
			},
		}
		got := fromSummary(s)
		want := RuleListItem{
			ID: "auditd-enabled", Title: "Install and enable auditd",
			Description: "The audit daemon must be installed and running.",
			Severity:    "high", Category: "audit", Tags: []string{"audit"},
			FrameworkRefs: map[string][]string{"cis_rhel9": {"6.3.1.4"}, "nist_800_53": {"AU-2"}},
			Transactional: true,
			Remediation: RemediationSummary{
				Available:        true,
				Mechanisms:       []string{"service_enabled"},
				RestartsServices: []string{"auditd"},
				RebootBehavior:   "none",
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("fromSummary =\n  %+v\nwant\n  %+v", got, want)
		}
	})
}

// TestRuleLibrary_RealCorpus loads the actual rule corpus via kensa's read
// model when OPENWATCH_KENSA_RULES_DIR is set; not an AC gate so coverage
// never depends on the corpus being present.
func TestRuleLibrary_RealCorpus(t *testing.T) {
	dir := os.Getenv("OPENWATCH_KENSA_RULES_DIR")
	if dir == "" {
		t.Skip("set OPENWATCH_KENSA_RULES_DIR to exercise the real corpus")
	}
	lib, err := NewRuleLibrary(dir)
	if err != nil {
		t.Fatalf("NewRuleLibrary: %v", err)
	}
	if lib.Len() < 400 {
		t.Errorf("rule library Len() = %d, want >= 400 (full corpus)", lib.Len())
	}
	for _, r := range lib.List() {
		if r.Title == "" || r.Severity == "" {
			t.Errorf("rule %s missing title/severity", r.ID)
		}
		if r.ID == "auditd-enabled" && len(r.FrameworkRefs) == 0 {
			t.Errorf("auditd-enabled has no framework refs")
		}
	}
}
