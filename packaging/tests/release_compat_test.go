// @spec release-compat-runs

package packaging_test

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// Local compatibility runs (release-compat-runs). The behavior lives in
// scripts/release_compat.py and is driven by scripts/test_release_compat.py,
// one unittest class per criterion. The suite runs once; each criterion checks
// its class passed in full and names the cases a reviewer relies on.

var (
	releaseCompatOnce   sync.Once
	releaseCompatOut    []byte
	releaseCompatErr    error
	releaseCompatPassed map[string]int
	releaseCompatCases  map[string]bool
)

func requireReleaseCompat(t *testing.T, class string, want int, cases ...string) {
	t.Helper()
	haveTool(t, "python3")
	haveTool(t, "git")
	haveTool(t, "gpg")
	haveTool(t, "tar")
	dir := appDir(t)
	releaseCompatOnce.Do(func() {
		cmd := exec.Command("python3", "-S", filepath.Join("scripts", "test_release_compat.py"))
		cmd.Dir = dir
		releaseCompatOut, releaseCompatErr = cmd.CombinedOutput()
		releaseCompatPassed = map[string]int{}
		releaseCompatCases = map[string]bool{}
		line := regexp.MustCompile(`\(__main__\.(\w+)\.(\w+)\) \.\.\. ok$`)
		for _, ln := range strings.Split(string(releaseCompatOut), "\n") {
			if m := line.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
				releaseCompatPassed[m[1]]++
				releaseCompatCases[m[1]+"."+m[2]] = true
			}
		}
	})
	if releaseCompatErr != nil {
		t.Fatalf("scripts/test_release_compat.py: %v\n%s", releaseCompatErr, tailOf(releaseCompatOut, 40))
	}
	if got := releaseCompatPassed[class]; got != want {
		t.Errorf("%s: %d of %d cases passed", class, got, want)
	}
	for _, c := range cases {
		if !releaseCompatCases[class+"."+c] {
			t.Errorf("%s.%s did not pass", class, c)
		}
	}
}

// @ac AC-01
// AC-01: the candidate's own test runs in every mode against the release's packages.
func TestReleaseCompat_RunsTheCandidatesTestOnReleasePackages(t *testing.T) {
	t.Run("release-compat-runs/AC-01", func(t *testing.T) {
		requireReleaseCompat(t, "CompatRuns", 5,
			"test_every_mode_passes_on_the_candidates_source",
			"test_the_source_is_the_candidate_even_when_the_repository_moved_on")
	})
}

// @ac AC-02
// AC-02: a skipped, incomplete or failing run is never a pass.
func TestReleaseCompat_NeverPassesASkippedOrIncompleteRun(t *testing.T) {
	t.Run("release-compat-runs/AC-02", func(t *testing.T) {
		requireReleaseCompat(t, "CompatNoFalsePass", 8,
			"test_a_skipped_test_fails",
			"test_a_run_without_the_tests_pass_result_fails",
			"test_no_docker_means_no_mode_ran")
	})
}

// @ac AC-03
// AC-03: only verified packages from both releases are used, and they do not change.
func TestReleaseCompat_UsesOnlyVerifiedUnchangedInputs(t *testing.T) {
	t.Run("release-compat-runs/AC-03", func(t *testing.T) {
		requireReleaseCompat(t, "CompatInputs", 7,
			"test_a_new_release_signed_by_another_key_stops_before_any_run",
			"test_a_package_changed_during_the_runs_fails")
	})
}
