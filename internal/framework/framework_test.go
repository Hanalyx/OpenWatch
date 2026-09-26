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
			"nist_800_171":  "nist_800_171", // Kensa v0.10.0
			"cmmc_l2":       "cmmc_l2",      // _l2 is a level, not an OS suffix
		}
		for key, want := range cases {
			if got := FamilyOf(key); got != want {
				t.Errorf("FamilyOf(%q) = %q, want %q", key, got, want)
			}
		}
		// Labels come from Kensa (D-2 S-7): one vocabulary, and the three
		// frameworks that used to collapse stay distinct. An unknown id is
		// returned as it is, never relabeled.
		for id, want := range map[string]string{
			"stig":         "STIG",
			"cis":          "CIS",
			"nist_800_53":  "NIST 800-53",
			"nist_800_171": "NIST SP 800-171 Rev 2",
			"cmmc_l2":      "CMMC Level 2",
			"pci_dss_4":    "PCI DSS 4.0",
			"not_a_family": "not_a_family",
		} {
			if got := Label(id); got != want {
				t.Errorf("Label(%q) = %q, want %q", id, got, want)
			}
		}
	})
}
