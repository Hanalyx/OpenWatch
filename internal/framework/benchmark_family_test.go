// @spec system-compliance-lens
//
//	AC-12  TestBenchmarkFamily_NormalizesRebuildsOnly
//	AC-13  TestBenchmarkFamily_BothResolutionPathsConsumeIt
package framework

import (
	"strings"
	"testing"
)

// @ac AC-12
// AC-12: an EL rebuild is graded against its upstream, and nothing else is.
//
// Found on a live host: an almalinux 9.8 host carried 391 rule results
// referencing stig_rhel9, and the lens asked for stig_almalinux9, which no rule
// in the corpus emits. The negative half matters as much as the positive half.
// Fedora rolls up to the rhel FAMILY in host discovery, so the obvious "just
// use the discovery rollup" fix would have swept it in and graded a Fedora host
// against the RHEL 9 STIG, inventing coverage rather than reporting none.
func TestBenchmarkFamily_NormalizesRebuildsOnly(t *testing.T) {
	t.Run("system-compliance-lens/AC-12", func(t *testing.T) {
		rebuilds := map[string]string{
			"almalinux": "rhel",
			"centos":    "rhel",
			"ol":        "rhel",
			"oracle":    "rhel",
			"rocky":     "rhel",
			// Not a rebuild, but must survive the mapping unchanged.
			"rhel":   "rhel",
			"ubuntu": "ubuntu",
			"debian": "debian",
			// Case and whitespace folded: os_family arrives from Discovery.
			"AlmaLinux": "rhel",
			"  Rocky  ": "rhel",
		}
		for in, want := range rebuilds {
			if got := BenchmarkFamily(in); got != want {
				t.Errorf("BenchmarkFamily(%q) = %q, want %q", in, got, want)
			}
		}

		// The deliberate exclusions. If either of these ever returns "rhel",
		// OpenWatch is grading a host against a benchmark it was never
		// assessed under, which is worse than offering no lens at all.
		for _, notEL := range []string{"fedora", "amzn", "amazon", "arch"} {
			if got := BenchmarkFamily(notEL); got == "rhel" {
				t.Errorf("BenchmarkFamily(%q) = %q; %q is not an EL rebuild and must not be graded as one", notEL, got, notEL)
			}
		}
		if got := BenchmarkFamily("fedora"); got != "fedora" {
			t.Errorf("BenchmarkFamily(\"fedora\") = %q, want %q unchanged", got, "fedora")
		}
		// An unknown family is returned as-is, so it resolves to a key the
		// corpus does not emit and no OS-specific lens is offered.
		if got := BenchmarkFamily("Gentoo"); got != "gentoo" {
			t.Errorf("BenchmarkFamily(\"Gentoo\") = %q, want %q", got, "gentoo")
		}
		if got := BenchmarkFamily(""); got != "" {
			t.Errorf("BenchmarkFamily(\"\") = %q, want empty", got)
		}
	})
}

// @ac AC-13
// AC-13: the SQL half and the Go half consume the same mapping.
//
// This is the actual defect class. The product already knew almalinux was RHEL
// -- the frontend's osLabel table said so -- while the query did not, so one
// page labeled a host "RHEL 9.8" and then withheld the RHEL 9 benchmarks from
// it. Two independent copies of one fact is how that shipped, so the guard is
// that both paths route through BenchmarkFamily rather than that they happen to
// agree today.
func TestBenchmarkFamily_BothResolutionPathsConsumeIt(t *testing.T) {
	t.Run("system-compliance-lens/AC-13", func(t *testing.T) {
		sql := OSResolvedMatchSQL("$1", "h.os_family", "h.os_version")

		// The SQL must normalize, not lower-case. A bare lower() is the bug.
		for _, rebuild := range []string{"almalinux", "centos", "ol", "oracle", "rocky"} {
			if !strings.Contains(sql, "WHEN '"+rebuild+"' THEN 'rhel'") {
				t.Errorf("OSResolvedMatchSQL does not map %q to rhel; an EL rebuild would resolve to a key the corpus never emits.\nSQL: %s", rebuild, sql)
			}
		}
		if strings.Contains(sql, "'fedora'") {
			t.Error("OSResolvedMatchSQL maps fedora; Fedora has no EL benchmark and must not be graded against one")
		}

		// Generated from the map rather than hand-written, so the two cannot
		// drift. Deterministic ordering keeps the query text stable.
		if a, b := benchmarkFamilySQL("x"), benchmarkFamilySQL("x"); a != b {
			t.Errorf("benchmarkFamilySQL is not deterministic:\n%s\n%s", a, b)
		}
		for fam := range benchmarkFamily {
			if !strings.Contains(sql, "WHEN '"+fam+"'") {
				t.Errorf("benchmarkFamily has %q but the generated SQL does not; the map and the SQL have drifted", fam)
			}
		}
	})
}
