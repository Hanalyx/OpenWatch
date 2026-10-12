// @spec release-prep-pr

package packaging_test

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// Release-prep pull request content (release-prep-pr). The behavior lives in
// scripts/release_prep_pr.py and is driven by scripts/test_release_prep_pr.py
// against throwaway git repositories, one unittest class per criterion. The
// suite runs once; each criterion checks its class passed in full and names
// the cases a reviewer relies on.

var (
	releasePrepPROnce   sync.Once
	releasePrepPROut    []byte
	releasePrepPRErr    error
	releasePrepPRPassed map[string]int
	releasePrepPRCases  map[string]bool
)

func requireReleasePrepPR(t *testing.T, class string, want int, cases ...string) {
	t.Helper()
	haveTool(t, "python3")
	haveTool(t, "git")
	haveTool(t, "bash")
	dir := appDir(t)
	releasePrepPROnce.Do(func() {
		cmd := exec.Command("python3", "-S", filepath.Join("scripts", "test_release_prep_pr.py"))
		cmd.Dir = dir
		releasePrepPROut, releasePrepPRErr = cmd.CombinedOutput()
		releasePrepPRPassed = map[string]int{}
		releasePrepPRCases = map[string]bool{}
		line := regexp.MustCompile(`\(__main__\.(\w+)\.(\w+)\) \.\.\. ok$`)
		for _, ln := range strings.Split(string(releasePrepPROut), "\n") {
			if m := line.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
				releasePrepPRPassed[m[1]]++
				releasePrepPRCases[m[1]+"."+m[2]] = true
			}
		}
	})
	if releasePrepPRErr != nil {
		t.Fatalf("scripts/test_release_prep_pr.py: %v\n%s", releasePrepPRErr, tailOf(releasePrepPROut, 40))
	}
	if got := releasePrepPRPassed[class]; got != want {
		t.Errorf("%s: %d of %d cases passed", class, got, want)
	}
	for _, c := range cases {
		if !releasePrepPRCases[class+"."+c] {
			t.Errorf("%s.%s did not pass", class, c)
		}
	}
}

// @ac AC-01
// AC-01: draft makes exactly the Stage 1 edits, derived, and commits nothing.
func TestReleasePrepPR_DraftEdits(t *testing.T) {
	t.Run("release-prep-pr/AC-01", func(t *testing.T) {
		requireReleasePrepPR(t, "DraftEdits", 5,
			"test_the_four_edits_and_nothing_else",
			"test_the_changelog_section_holds_the_notes_under_a_fresh_unreleased")
	})
}

// @ac AC-02
// AC-02: draft refuses, changing nothing, rather than guess.
func TestReleasePrepPR_DraftRefuses(t *testing.T) {
	t.Run("release-prep-pr/AC-02", func(t *testing.T) {
		requireReleasePrepPR(t, "DraftRefusals", 9,
			"test_an_empty_unreleased_section_is_refused",
			"test_malformed_inputs_are_refused",
			"test_a_second_draft_is_refused")
	})
}

// @ac AC-03
// AC-03: body is written from the recorded captures, with every human field blank.
func TestReleasePrepPR_BodyFromEvidence(t *testing.T) {
	t.Run("release-prep-pr/AC-03", func(t *testing.T) {
		requireReleasePrepPR(t, "BodyFromEvidence", 4,
			"test_the_body_reports_the_recorded_findings",
			"test_every_human_field_is_blank_and_follows_the_evidence",
			"test_changes_after_the_draft_are_named")
	})
}

// @ac AC-04
// AC-04: a local CI result counts only for this commit, and its gaps are copied.
func TestReleasePrepPR_LocalCIResult(t *testing.T) {
	t.Run("release-prep-pr/AC-04", func(t *testing.T) {
		requireReleasePrepPR(t, "LocalCIResult", 9,
			"test_a_result_for_this_commit_is_copied_with_every_gap",
			"test_a_result_for_another_commit_is_not_counted")
	})
}

// @ac AC-05
// AC-05: body refuses an unverified or inconsistent state, and never overwrites.
func TestReleasePrepPR_BodyRefuses(t *testing.T) {
	t.Run("release-prep-pr/AC-05", func(t *testing.T) {
		requireReleasePrepPR(t, "BodyRefusals", 6,
			"test_an_altered_reading",
			"test_a_commit_whose_own_tag_check_refuses")
	})
}

// @ac AC-06
// AC-06: an explicit timeout, and the tool never commits, pushes or tags.
func TestReleasePrepPR_StaysOffline(t *testing.T) {
	t.Run("release-prep-pr/AC-06", func(t *testing.T) {
		requireReleasePrepPR(t, "PrepBoundaries", 3,
			"test_the_tool_never_commits_pushes_or_tags")
	})
}

// @ac AC-02
// AC-02: a refused or failed draft leaves every file as it was, and only the
// VERSION assignment changes (review of 7e0738aa: a comment quoting it was
// rewritten, then five files were left edited behind a refusal).
func TestReleasePrepPR_DraftLeavesNothingBehind(t *testing.T) {
	t.Run("release-prep-pr/AC-02", func(t *testing.T) {
		requireReleasePrepPR(t, "DraftRefusals", 9,
			"test_a_proposal_that_would_disagree_is_refused_before_anything_is_written",
			"test_a_failure_while_applying_restores_every_original_byte")
		requireReleasePrepPR(t, "DraftEdits", 5,
			"test_only_the_version_assignment_changes_not_a_comment_quoting_it")
	})
}

// @ac AC-04
// AC-04: CI evidence counts only when finished, well formed and from this
// tree (review of 7e0738aa: another tree with an empty finished field was
// reported as "verdict complete").
func TestReleasePrepPR_CIEvidenceBindsToTheTree(t *testing.T) {
	t.Run("release-prep-pr/AC-04", func(t *testing.T) {
		requireReleasePrepPR(t, "LocalCIResult", 9,
			"test_the_reviewers_result_another_tree_and_unfinished_is_refused",
			"test_a_finished_result_for_another_tree_is_not_counted",
			"test_untracked_files_since_the_run_change_the_tree",
			"test_a_malformed_result_is_refused")
	})
}
