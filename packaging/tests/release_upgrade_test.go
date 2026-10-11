// @spec release-upgrade-steps

package packaging_test

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// Upgrade Steps 1 to 8 (release-upgrade-steps). The behavior lives in
// scripts/release_upgrade.py and release/prep/upgrade/, and is driven by
// scripts/test_release_upgrade.py against a simulated server,
// one unittest class per criterion. The suite runs once; each criterion checks
// its class passed in full and names the cases a reviewer relies on.

var (
	releaseUpgradeOnce   sync.Once
	releaseUpgradeOut    []byte
	releaseUpgradeErr    error
	releaseUpgradePassed map[string]int
	releaseUpgradeCases  map[string]bool
)

func requireReleaseUpgrade(t *testing.T, class string, want int, cases ...string) {
	t.Helper()
	haveTool(t, "python3")
	haveTool(t, "git")
	haveTool(t, "tar")
	dir := appDir(t)
	releaseUpgradeOnce.Do(func() {
		cmd := exec.Command("python3", "-S", filepath.Join("scripts", "test_release_upgrade.py"))
		cmd.Dir = dir
		releaseUpgradeOut, releaseUpgradeErr = cmd.CombinedOutput()
		releaseUpgradePassed = map[string]int{}
		releaseUpgradeCases = map[string]bool{}
		line := regexp.MustCompile(`\(__main__\.(\w+)\.(\w+)\) \.\.\. ok$`)
		for _, ln := range strings.Split(string(releaseUpgradeOut), "\n") {
			if m := line.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
				releaseUpgradePassed[m[1]]++
				releaseUpgradeCases[m[1]+"."+m[2]] = true
			}
		}
	})
	if releaseUpgradeErr != nil {
		t.Fatalf("scripts/test_release_upgrade.py: %v\n%s", releaseUpgradeErr, tailOf(releaseUpgradeOut, 40))
	}
	if got := releaseUpgradePassed[class]; got != want {
		t.Errorf("%s: %d of %d cases passed", class, got, want)
	}
	for _, c := range cases {
		if !releaseUpgradeCases[class+"."+c] {
			t.Errorf("%s.%s did not pass", class, c)
		}
	}
}

// @ac AC-01
// AC-01: the five phases run in order, each a verified capture.
func TestReleaseUpgrade_ReachesMatchInOrder(t *testing.T) {
	t.Run("release-upgrade-steps/AC-01", func(t *testing.T) {
		requireReleaseUpgrade(t, "UpgradePhasesInOrder", 4,
			"test_a_full_upgrade_reaches_match",
			"test_a_dry_run_changes_nothing_and_shows_the_commands")
	})
}

// @ac AC-02
// AC-02: a phase needs the previous phases verified, from the same host.
func TestReleaseUpgrade_GatesEachPhase(t *testing.T) {
	t.Run("release-upgrade-steps/AC-02", func(t *testing.T) {
		requireReleaseUpgrade(t, "UpgradeGates", 6,
			"test_each_phase_needs_the_ones_before_it",
			"test_a_capture_reporting_a_failed_step_is_refused_even_at_exit_0",
			"test_execute_needs_the_preflight_to_show_this_host")
	})
}

// @ac AC-03
// AC-03: a failed step stops the phase, and nothing starts the service by hand.
func TestReleaseUpgrade_StopsSafely(t *testing.T) {
	t.Run("release-upgrade-steps/AC-03", func(t *testing.T) {
		requireReleaseUpgrade(t, "UpgradeStopsSafely", 6,
			"test_a_package_that_does_not_match_stops_before_the_service_is_touched",
			"test_a_failed_install_leaves_the_service_stopped_and_blocks_verify",
			"test_a_stopped_service_after_install_fails_verify_without_starting_it")
	})
}

// @ac AC-04
// AC-04: Step 8 reaches MATCH only when the served rules are the installed rules.
func TestReleaseUpgrade_Step8MatchesServedAndInstalledRules(t *testing.T) {
	t.Run("release-upgrade-steps/AC-04", func(t *testing.T) {
		requireReleaseUpgrade(t, "UpgradeStep8", 7,
			"test_a_stale_served_rule_is_a_mismatch",
			"test_the_token_never_appears_in_any_evidence")
	})
}

// @ac AC-05
// AC-05: explicit timeouts, and nothing in the scripts starts, rolls back or reboots.
func TestReleaseUpgrade_StaysInsideTheProcedure(t *testing.T) {
	t.Run("release-upgrade-steps/AC-05", func(t *testing.T) {
		requireReleaseUpgrade(t, "UpgradeBoundaries", 3,
			"test_the_scripts_never_start_roll_back_or_reboot")
	})
}
