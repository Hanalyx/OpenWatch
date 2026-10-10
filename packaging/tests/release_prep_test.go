// @spec release-preparation

package packaging_test

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// Release preparation (release-preparation). The F2 workflow lives in
// scripts/release_prep.py and is driven end to end by
// scripts/test_release_prep.py against a simulated host, one unittest class per
// criterion. The suite runs once; each criterion checks its class passed in full
// and names the cases a reviewer relies on.

var (
	releasePrepOnce   sync.Once
	releasePrepOut    []byte
	releasePrepErr    error
	releasePrepPassed map[string]int
	releasePrepCases  map[string]bool
)

func releasePrepSuite(t *testing.T) {
	t.Helper()
	haveTool(t, "python3")
	haveTool(t, "tar")
	dir := appDir(t)
	releasePrepOnce.Do(func() {
		cmd := exec.Command("python3", "-S", filepath.Join("scripts", "test_release_prep.py"))
		cmd.Dir = dir
		releasePrepOut, releasePrepErr = cmd.CombinedOutput()
		releasePrepPassed = map[string]int{}
		releasePrepCases = map[string]bool{}
		line := regexp.MustCompile(`\(__main__\.(\w+)\.(\w+)\) \.\.\. ok$`)
		for _, ln := range strings.Split(string(releasePrepOut), "\n") {
			if m := line.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
				releasePrepPassed[m[1]]++
				releasePrepCases[m[1]+"."+m[2]] = true
			}
		}
	})
	if releasePrepErr != nil {
		t.Fatalf("scripts/test_release_prep.py: %v\n%s", releasePrepErr, tailOf(releasePrepOut, 40))
	}
}

func requireReleasePrep(t *testing.T, class string, want int, cases ...string) {
	t.Helper()
	releasePrepSuite(t)
	if got := releasePrepPassed[class]; got != want {
		t.Errorf("%s: %d of %d cases passed", class, got, want)
	}
	for _, c := range cases {
		if !releasePrepCases[class+"."+c] {
			t.Errorf("%s.%s did not pass", class, c)
		}
	}
}

// @ac AC-01
// AC-01: three verified captures, in order, with the next step named.
func TestReleasePrep_F2PhasesCaptureAndVerifyInOrder(t *testing.T) {
	t.Run("release-preparation/AC-01", func(t *testing.T) {
		requireReleasePrep(t, "F2PhasesInOrder", 4,
			"test_the_three_phases_capture_verify_and_prompt_in_order")
	})
}

// @ac AC-02
// AC-02: rollback is prompted only after the staged capture verifies.
func TestReleasePrep_RollbackOnlyAfterVerifiedStagedCapture(t *testing.T) {
	t.Run("release-preparation/AC-02", func(t *testing.T) {
		requireReleasePrep(t, "F2RollbackGate", 7,
			"test_staged_needs_a_verified_preflight",
			"test_a_failed_staged_snapshot_gives_no_rollback_prompt",
			"test_a_broken_transfer_gives_no_rollback_prompt",
			"test_staged_from_another_machine_is_refused",
			"test_an_altered_staged_capture_blocks_after")
		skill := readAppFile(t, ".claude/skills/release-prep/SKILL.md")
		for _, want := range []string{
			"Never tell the captain to roll back before `f2 staged` has printed its rollback prompt.",
			"Every capture has an explicit timeout.",
			"Leave every human field blank.",
		} {
			if !strings.Contains(skill, want) {
				t.Errorf("the release-prep skill no longer says %q", want)
			}
		}
	})
}

// @ac AC-03
// AC-03: the host and candidate are checked before anything is staged.
func TestReleasePrep_F2Preconditions(t *testing.T) {
	t.Run("release-preparation/AC-03", func(t *testing.T) {
		requireReleasePrep(t, "F2Preconditions", 3, "test_preflight_requires_enabled_2",
			"test_the_maintained_snapshot_is_read_only")
	})
}

// @ac AC-04
// AC-04: every capture and transfer has an explicit timeout.
func TestReleasePrep_EveryCaptureHasAnExplicitTimeout(t *testing.T) {
	t.Run("release-preparation/AC-04", func(t *testing.T) {
		requireReleasePrep(t, "F2Timeouts", 3,
			"test_every_capture_and_fetch_passes_the_declared_timeout",
			"test_a_hung_snapshot_is_stopped_by_the_phase_timeout")
	})
}

// @ac AC-05
// AC-05: the packet is derived from verified captures and records no verdict.
func TestReleasePrep_PacketRecordsNoVerdict(t *testing.T) {
	t.Run("release-preparation/AC-05", func(t *testing.T) {
		requireReleasePrep(t, "F2Packet", 2,
			"test_packet_shows_raw_digests_and_derived_changes_with_blank_confirmations")
	})
}

// @ac AC-06
// AC-06: the maintained snapshot fails when any required section fails, and a
// failed section never reaches the rollback prompt.
func TestReleasePrep_FailedSnapshotSectionsBlockRollback(t *testing.T) {
	t.Run("release-preparation/AC-06", func(t *testing.T) {
		requireReleasePrep(t, "F2MaintainedSnapshot", 10,
			"test_a_failed_auditctl_list_fails_the_snapshot_and_keeps_its_output",
			"test_a_failed_read_before_a_good_one_fails_the_snapshot",
			"test_a_failed_auditctl_list_while_staged_gives_no_rollback_prompt",
			"test_a_failed_rules_read_while_staged_gives_no_rollback_prompt",
			"test_a_reported_failure_is_refused_even_when_the_script_exits_0")
	})
}

// @ac AC-06
// AC-06: auditctl's loaded-rule output is kept byte for byte, with a digest
// computed from the same bytes, and the temporary file never outlives the run.
func TestReleasePrep_LoadedRulesStayByteExact(t *testing.T) {
	t.Run("release-preparation/AC-06", func(t *testing.T) {
		requireReleasePrep(t, "F2MaintainedSnapshot", 10,
			"test_loaded_rules_are_emitted_byte_for_byte_with_their_digest",
			"test_staged_evidence_keeps_the_exact_loaded_rule_bytes",
			"test_an_interrupted_snapshot_removes_its_temporary_file")
	})
}
