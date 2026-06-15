// @spec api-rules
//
// AC traceability (this file):
//   AC-01  TestNormalizeFrameworkRefs
//   AC-02  TestSummarizeRemediation
//   (TestRuleLibrary_RealCorpus is an un-annotated corpus-gated bonus)

package kensa

import (
	"os"
	"reflect"
	"testing"

	kensaapi "github.com/Hanalyx/kensa/api"
)

// @ac AC-01
func TestNormalizeFrameworkRefs(t *testing.T) {
	t.Run("api-rules/AC-01", func(t *testing.T) {
		refs := map[string]interface{}{
			// CIS: nested per-distro object, control id = section.
			"cis": map[string]interface{}{
				"rhel8": map[string]interface{}{"section": "6.3.1.4", "level": "L2"},
				"rhel9": map[string]interface{}{"section": "6.3.1.4", "level": "L1"},
			},
			// STIG: nested object, prefer vuln_id over stig_id.
			"stig": map[string]interface{}{
				"rhel9": map[string]interface{}{"vuln_id": "V-258151", "stig_id": "RHEL-09-653010"},
			},
			// NIST: top-level array, verbatim (deduped + sorted).
			"nist_800_53": []interface{}{"AU-3", "AU-2", "AU-12", "AU-2"},
		}
		got := normalizeFrameworkRefs(refs)
		want := map[string][]string{
			"cis_rhel8":   {"6.3.1.4"},
			"cis_rhel9":   {"6.3.1.4"},
			"stig_rhel9":  {"V-258151"},              // vuln_id wins over stig_id
			"nist_800_53": {"AU-12", "AU-2", "AU-3"}, // deduped + sorted
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("normalizeFrameworkRefs =\n  %v\nwant\n  %v", got, want)
		}
	})
}

// @ac AC-02
func TestSummarizeRemediation(t *testing.T) {
	t.Run("api-rules/AC-02", func(t *testing.T) {
		cases := []struct {
			name string
			imps []kensaapi.Implementation
			want RemediationSummary
		}{
			{
				name: "default impl mechanism wins",
				imps: []kensaapi.Implementation{
					{Remediation: kensaapi.Remediation{Mechanism: "config_set"}},
					{Default: true, Remediation: kensaapi.Remediation{Mechanism: "service_enabled"}},
				},
				want: RemediationSummary{Mechanism: "service_enabled", Manual: false},
			},
			{
				name: "no default falls back to first",
				imps: []kensaapi.Implementation{
					{Remediation: kensaapi.Remediation{Mechanism: "package_present"}},
				},
				want: RemediationSummary{Mechanism: "package_present", Manual: false},
			},
			{
				name: "manual mechanism marks Manual",
				imps: []kensaapi.Implementation{
					{Default: true, Remediation: kensaapi.Remediation{Mechanism: "manual"}},
				},
				want: RemediationSummary{Mechanism: "manual", Manual: true},
			},
			{
				name: "no implementations is manual",
				imps: nil,
				want: RemediationSummary{Mechanism: "", Manual: true},
			},
		}
		for _, c := range cases {
			if got := summarizeRemediation(c.imps); got != c.want {
				t.Errorf("%s: summarizeRemediation = %+v, want %+v", c.name, got, c.want)
			}
		}
	})
}

// TestRuleLibrary_RealCorpus loads the actual rule corpus when
// OPENWATCH_KENSA_RULES_DIR is set (a dev/CI convenience); it is NOT an AC
// gate so coverage never depends on the corpus being present.
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
	var found bool
	for _, r := range lib.List() {
		if r.ID == "auditd-enabled" {
			found = true
			if len(r.FrameworkRefs["nist_800_53"]) == 0 || r.Remediation.Mechanism == "" {
				t.Errorf("auditd-enabled normalized poorly: refs=%v rem=%+v", r.FrameworkRefs, r.Remediation)
			}
		}
		if r.Title == "" || r.Severity == "" {
			t.Errorf("rule %s missing title/severity", r.ID)
		}
	}
	if !found {
		t.Error("auditd-enabled rule not found in corpus")
	}
}
