// @spec release-ci-gates

package packaging_test

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Truthful local CI (release-ci-gates C-20). The behavior lives in
// scripts/ci-strict.py and its tests drive it with a fake machine; these
// criteria run those tests and count the cases by name, so a deleted case is
// noticed, and read the Makefile and guides for how it is wired.

// strictCases runs scripts/test_ci_strict.py once and returns, per test
// class, how many cases passed.
func strictCases(t *testing.T) map[string]int {
	t.Helper()
	haveTool(t, "python3")
	cmd := exec.Command("python3", "-S", filepath.Join("scripts", "test_ci_strict.py"))
	cmd.Dir = appDir(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("scripts/test_ci_strict.py: %v\n%s", err, out)
	}
	passed := map[string]int{}
	line := regexp.MustCompile(`\(__main__\.(\w+)\.\w+\) \.\.\. ok$`)
	for _, ln := range strings.Split(string(out), "\n") {
		if m := line.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
			passed[m[1]]++
		}
	}
	return passed
}

// @ac AC-37
// AC-37: the verdicts, the preflight, the local test split and the absence of
// any "safe to push" claim.
func TestCIGates_StrictLocalCIReportsWhatRan(t *testing.T) {
	t.Run("release-ci-gates/AC-37", func(t *testing.T) {
		if got := strictCases(t); got["Verdicts"] != 10 || got["Wiring"] != 3 {
			t.Errorf("Verdicts %d of 10 and Wiring %d of 3 cases passed", got["Verdicts"], got["Wiring"])
		}
	})
}

// @ac AC-38
// AC-38: one invocation at a time, isolated results, atomic writes, and a
// result check that accepts nothing but a finished matching COMPLETE run.
func TestCIGates_StrictLocalCIResultsBelongToOneInvocation(t *testing.T) {
	t.Run("release-ci-gates/AC-38", func(t *testing.T) {
		if got := strictCases(t)["ConcurrencyAndResults"]; got != 6 {
			t.Errorf("ConcurrencyAndResults: %d of 6 cases passed", got)
		}
	})
}

// @ac AC-39
// AC-39: the Makefile and the guides.
func TestCIGates_StrictLocalCIIsWiredAndDocumented(t *testing.T) {
	t.Run("release-ci-gates/AC-39", func(t *testing.T) {
		mk := readAppFile(t, "Makefile")
		if !regexp.MustCompile(`(?m)^ci-strict:\n\tpython3 -S scripts/ci-strict\.py`).MatchString(mk) {
			t.Error("ci-strict does not run python3 -S scripts/ci-strict.py")
		}
		if !regexp.MustCompile(`(?m)^ci-local: ci-strict\s*$`).MatchString(mk) {
			t.Error("ci-local is not an alias of ci-strict alone")
		}
		quick := regexp.MustCompile(`(?ms)^ci-quick:.*?\n\n`).FindString(mk)
		if !strings.Contains(quick, "this is not CI") {
			t.Error("ci-quick does not say it is not CI")
		}
		runner := readAppFile(t, "scripts/ci-strict.py")
		for _, gate := range []string{"vet", "lint", "vuln", "spec-check", "docs-style", "check-generated", "license-bundle"} {
			if !strings.Contains(runner, `"`+gate+`": ["make", "`+gate+`"]`) {
				t.Errorf("the strict runner does not run make %s", gate)
			}
		}
		agents := readAppFile(t, "AGENTS.md")
		for _, want := range []string{"python3 -S scripts/ci-strict.py", "Exit 0 is\nCOMPLETE, 1 FAILED, 3 INCOMPLETE",
			"4 REFUSED", "run the script directly"} {
			if !strings.Contains(agents, want) {
				t.Errorf("AGENTS.md does not say %q", want)
			}
		}
		safe := regexp.MustCompile(`(?i)safe to push`)
		for _, f := range []string{"Makefile", "scripts/ci-strict.py", "AGENTS.md", "CONTRIBUTING.md", "README.md"} {
			if loc := safe.FindString(readAppFile(t, f)); loc != "" {
				t.Errorf("%s says %q; the local gate makes no claim about whether to push", f, loc)
			}
		}
	})
}
