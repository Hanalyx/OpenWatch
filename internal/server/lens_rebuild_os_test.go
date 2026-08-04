// @spec system-compliance-lens
//
//	AC-13  TestFrameworkCompatibleWithOS_RebuildsOfferedFedoraNot
package server

import "testing"

// @ac AC-13
// AC-13, the lens-offer half: an EL rebuild must be OFFERED the upstream's
// benchmarks, and a non-rebuild must not be.
//
// This function is why the live defect looked benign. It decides which lenses
// appear in the picker, so comparing the raw distro id did not produce a STIG
// score of zero on an AlmaLinux host -- it produced a page with no STIG option
// at all, next to 391 rule results carrying stig_rhel9. Nothing on screen said
// anything was missing.
func TestFrameworkCompatibleWithOS_RebuildsOfferedFedoraNot(t *testing.T) {
	t.Run("system-compliance-lens/AC-13", func(t *testing.T) {
		cases := []struct {
			frameworkID, osFamily, osVersion string
			want                             bool
			why                              string
		}{
			// The live host. Kensa ran the EL 9 rules on it and its results
			// carry stig_rhel9, so the STIG lens must be reachable.
			{"stig_rhel9", "almalinux", "9.8", true, "AlmaLinux 9 is graded as EL 9"},
			{"cis_rhel9", "almalinux", "9.8", true, "same for CIS"},
			{"stig_rhel9", "rocky", "9.5", true, "Rocky 9 is graded as EL 9"},
			{"stig_rhel9", "centos", "9", true, "CentOS Stream 9 is EL 9"},
			{"stig_rhel9", "ol", "9.4", true, "Oracle Linux 9 is EL 9"},

			// Unchanged behavior, so the fix did not widen anything else.
			{"stig_rhel9", "rhel", "9.6", true, "the case that already worked"},
			{"stig_rhel10", "almalinux", "9.8", false, "major version still has to match"},
			{"cis_ubuntu2404", "ubuntu", "24.04", true, "major+minor concatenation"},
			{"nist_800_53", "almalinux", "9.8", true, "OS-neutral lens is always offered"},
			{"stig_rhel9", "", "", true, "undiscovered host cannot be judged"},

			// The exclusion that keeps this honest. Fedora rolls up to the
			// rhel family in Discovery, so a rollup-based fix would have made
			// this true and graded a Fedora host against the RHEL 9 STIG.
			{"stig_rhel9", "fedora", "41", false, "Fedora is upstream of RHEL, not a rebuild, and has no EL benchmark"},
			{"cis_rhel9", "fedora", "41", false, "same for CIS"},
			{"stig_rhel9", "arch", "1", false, "unknown distro gets no OS-specific lens"},
		}
		for _, c := range cases {
			got := frameworkCompatibleWithOS(c.frameworkID, c.osFamily, c.osVersion)
			if got != c.want {
				t.Errorf("frameworkCompatibleWithOS(%q, %q, %q) = %v, want %v (%s)",
					c.frameworkID, c.osFamily, c.osVersion, got, c.want, c.why)
			}
		}
	})
}
