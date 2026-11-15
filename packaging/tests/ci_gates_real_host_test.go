// @spec release-ci-gates

package packaging_test

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Real-host install and upgrade (release-ci-gates C-28). The behavior lives in
// scripts/release-status.py and its scope in release/gates.toml; the Python
// tests drive both. This criterion runs them, counts the cases by class so a
// deleted case is noticed, and reads the runbook for how an operator is told
// which hosts a release needs.

// @ac AC-54
// AC-54: real hosts install and upgrade every release, scoped by release type.
func TestCIGates_RealHostGatesScopeByReleaseType(t *testing.T) {
	t.Run("release-ci-gates/AC-54", func(t *testing.T) {
		haveTool(t, "python3")
		cmd := exec.Command("python3", "-S", filepath.Join("scripts", "test_release_status.py"))
		cmd.Dir = appDir(t)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("scripts/test_release_status.py: %v\n%s", err, tailOf(out, 40))
		}
		passed := map[string]int{}
		line := regexp.MustCompile(`\(__main__\.(\w+)\.\w+\) \.\.\. ok$`)
		for _, ln := range strings.Split(string(out), "\n") {
			if m := line.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
				passed[m[1]]++
			}
		}
		for class, want := range map[string]int{
			"RealHostGates":    19,
			"RealHostManifest": 4,
		} {
			if passed[class] != want {
				t.Errorf("%s: %d of %d cases passed", class, passed[class], want)
			}
		}

		book := readAppFile(t, "docs/runbooks/RELEASING.md")
		for _, want := range []struct{ frag, why string }{
			{"gates I3 and U3, `release-ci-gates` C-28", "the procedure must name the gates and the rule"},
			{"A patch release `vX.Y.Z` needs one RHEL 9 host and one Ubuntu 24.04 or\n  Debian 12 host.", "the procedure must state the patch scope"},
			{"needs a real host of\n  every tested platform", "the procedure must state the vX.Y.0 scope"},
			{"`ID=rhel` in `/etc/os-release`", "the RHEL host must be RHEL itself"},
			{"`host-clean-install` or `host-upgrade`", "the procedure must name the attestation kinds"},
			{"`upgraded_from`", "an upgrade attestation names where it started"},
			{"v0.8.6 and earlier report I3 and U3 as N/A", "the procedure must say when the rule starts"},
		} {
			if !strings.Contains(book, want.frag) {
				t.Errorf("docs/runbooks/RELEASING.md is missing %q: %s", want.frag, want.why)
			}
		}
	})
}
