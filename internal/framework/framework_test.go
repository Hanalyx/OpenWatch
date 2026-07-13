// @spec system-compliance-lens
package framework

import "testing"

// @ac AC-02
// AC-02: FamilyOf strips a trailing OS suffix (rhel/ubuntu + digits) to
// group OS-specific baselines into one family, and leaves OS-agnostic keys
// as their own family — so the default-lens picker offers coarse families
// (STIG, CIS) that resolve per-host.
func TestFamilyOf(t *testing.T) {
	t.Run("system-compliance-lens/AC-02", func(t *testing.T) {
		cases := map[string]string{
			"stig_rhel9":    "stig",
			"stig_rhel10":   "stig",
			"stig_ubuntu22": "stig",
			"cis_rhel8":     "cis",
			"cis_ubuntu24":  "cis",
			"nist_800_53":   "nist_800_53", // OS-agnostic: digits not stripped
			"pci_dss_4":     "pci_dss_4",   // trailing _4 is not an OS suffix
			"srg":           "srg",
		}
		for key, want := range cases {
			if got := FamilyOf(key); got != want {
				t.Errorf("FamilyOf(%q) = %q, want %q", key, got, want)
			}
		}
		// Labels: known families render nicely, unknown upper-cases.
		if Label("stig") != "STIG" || Label("nist_800_53") != "NIST 800-53" {
			t.Errorf("Label mismatch: stig=%q nist=%q", Label("stig"), Label("nist_800_53"))
		}
	})
}
