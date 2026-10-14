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

// strictCase reports whether the named case of scripts/test_ci_strict.py
// passed. Runs the suite once per call; the readiness cases need git.
func strictCase(t *testing.T, class, name string) bool {
	t.Helper()
	haveTool(t, "python3")
	haveTool(t, "git")
	cmd := exec.Command("python3", "-S", filepath.Join("scripts", "test_ci_strict.py"), class+"."+name)
	cmd.Dir = appDir(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("%s.%s: %v\n%s", class, name, err, out)
		return false
	}
	return strings.Contains(string(out), "OK")
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

// @ac AC-45
// AC-45 (bugs/OW-124): a commit-mode result tests the commit's files alone. A
// test that is ignored, untracked, or staged but not committed cannot make it
// pass; a committed one does; the checkout is left as it was; a failed export
// runs no gate.
func TestCIGates_CommitResultsComeFromTheCommit(t *testing.T) {
	t.Run("release-ci-gates/AC-45", func(t *testing.T) {
		for _, name := range []string{
			"test_an_uncommitted_test_cannot_make_a_commit_result_pass",
			"test_a_committed_test_does_pass_in_commit_mode",
			"test_commit_mode_leaves_the_checkout_as_it_was",
			"test_a_failed_export_runs_no_gate_and_is_incomplete",
		} {
			if !strictCase(t, "ReadinessFromCommit", name) {
				t.Errorf("ReadinessFromCommit.%s did not pass", name)
			}
		}
	})
}

// @ac AC-45
// AC-45, failure and interruption: a failed npm ci in the export runs no
// gate, is FAILED, and keeps npm's output; an interrupt during the clone, the
// checkout or npm ci, and a real SIGINT or SIGTERM, leave no export and
// release the lock.
func TestCIGates_CommitRunsFailClosedAndCleanUp(t *testing.T) {
	t.Run("release-ci-gates/AC-45", func(t *testing.T) {
		for _, name := range []string{
			"test_a_failed_npm_ci_runs_no_gate_and_fails",
			"test_an_interrupt_while_exporting_leaves_no_export",
			"test_a_real_signal_during_npm_ci_leaves_no_export",
			"test_main_installs_the_sigterm_cleanup_before_running",
		} {
			if !strictCase(t, "ReadinessFromCommit", name) {
				t.Errorf("ReadinessFromCommit.%s did not pass", name)
			}
		}
	})
}

// @ac AC-46
// AC-46: a stale results file naming an AC as passed, for a test the commit
// does not contain, cannot make a commit-mode result pass.
func TestCIGates_StaleResultsCannotPassACommit(t *testing.T) {
	t.Run("release-ci-gates/AC-46", func(t *testing.T) {
		if !strictCase(t, "ReadinessFromCommit", "test_a_stale_results_file_cannot_make_a_commit_result_pass") {
			t.Error("the stale-results case did not pass")
		}
	})
}

// @ac AC-47
// AC-47: a development run says what it tested and is never readiness
// evidence; a commit-mode result is readiness evidence for its commit only;
// the development identity covers untracked and ignored contents; and make
// has a target for each mode.
func TestCIGates_ResultsNameWhatTheyTested(t *testing.T) {
	t.Run("release-ci-gates/AC-47", func(t *testing.T) {
		for _, name := range []string{
			"test_a_development_run_says_what_it_tested_and_is_not_readiness",
			"test_a_commit_result_is_readiness_evidence_for_head_only",
			"test_the_development_identity_covers_untracked_and_ignored_contents",
		} {
			if !strictCase(t, "ReadinessFromCommit", name) {
				t.Errorf("ReadinessFromCommit.%s did not pass", name)
			}
		}
		mk := readAppFile(t, "Makefile")
		if !regexp.MustCompile(`(?m)^ci-strict-commit:\n\tpython3 -S scripts/ci-strict\.py --commit`).MatchString(mk) {
			t.Error("Makefile has no ci-strict-commit target running scripts/ci-strict.py --commit")
		}
	})
}

// @ac AC-47
// AC-47, the recorded tree: a commit result is accepted only when its tree is
// its commit's git tree. Another commit's tree, a made-up tree or none is
// refused, with and without --commit.
func TestCIGates_CommitResultsMustRecordTheirTree(t *testing.T) {
	t.Run("release-ci-gates/AC-47", func(t *testing.T) {
		if !strictCase(t, "ReadinessFromCommit", "test_a_commit_result_must_record_its_commits_tree") {
			t.Error("the recorded-tree case did not pass")
		}
	})
}
