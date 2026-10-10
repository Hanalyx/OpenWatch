// @spec release-tagging

package packaging_test

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// Release tagging (release-tagging; CP bugs/OW-118). The behavior lives in
// scripts/release_tag.py and is driven by scripts/test_release_tag.py against
// real git repositories and a throwaway GnuPG home, one unittest class per
// criterion. The suite runs once; each criterion checks its class passed in
// full and names the cases a reviewer relies on.

var (
	releaseTagOnce   sync.Once
	releaseTagOut    []byte
	releaseTagErr    error
	releaseTagPassed map[string]int
	releaseTagCases  map[string]bool
)

func requireReleaseTag(t *testing.T, class string, want int, cases ...string) {
	t.Helper()
	haveTool(t, "python3")
	haveTool(t, "git")
	haveTool(t, "gpg")
	dir := appDir(t)
	releaseTagOnce.Do(func() {
		cmd := exec.Command("python3", "-S", filepath.Join("scripts", "test_release_tag.py"))
		cmd.Dir = dir
		releaseTagOut, releaseTagErr = cmd.CombinedOutput()
		releaseTagPassed = map[string]int{}
		releaseTagCases = map[string]bool{}
		line := regexp.MustCompile(`\(__main__\.(\w+)\.(\w+)\) \.\.\. ok$`)
		for _, ln := range strings.Split(string(releaseTagOut), "\n") {
			if m := line.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
				releaseTagPassed[m[1]]++
				releaseTagCases[m[1]+"."+m[2]] = true
			}
		}
	})
	if releaseTagErr != nil {
		t.Fatalf("scripts/test_release_tag.py: %v\n%s", releaseTagErr, tailOf(releaseTagOut, 40))
	}
	if got := releaseTagPassed[class]; got != want {
		t.Errorf("%s: %d of %d cases passed", class, got, want)
	}
	for _, c := range cases {
		if !releaseTagCases[class+"."+c] {
			t.Errorf("%s.%s did not pass", class, c)
		}
	}
}

// @ac AC-01
// AC-01: the candidate is a full SHA on origin/main, never a branch.
func TestReleaseTag_TagsOnlyTheExplicitCandidate(t *testing.T) {
	t.Run("release-tagging/AC-01", func(t *testing.T) {
		requireReleaseTag(t, "TagExplicitCandidate", 5,
			"test_the_candidate_is_tagged_after_main_moves_on_with_the_same_version",
			"test_a_dry_run_checks_everything_and_creates_nothing")
	})
}

// @ac AC-02
// AC-02: the tag is derived from the candidate's own files, which must agree.
func TestReleaseTag_DerivesTheTagAtTheCandidate(t *testing.T) {
	t.Run("release-tagging/AC-02", func(t *testing.T) {
		requireReleaseTag(t, "TagVersionAgreement", 4,
			"test_the_candidates_own_check_script_is_run")
	})
}

// @ac AC-03
// AC-03: an existing tag, anywhere, refuses the candidate.
func TestReleaseTag_NeverReusesATag(t *testing.T) {
	t.Run("release-tagging/AC-03", func(t *testing.T) {
		requireReleaseTag(t, "TagNeverReused", 4, "test_a_release_or_draft_using_the_tag_is_refused")
	})
}

// @ac AC-04
// AC-04: only a primary key in security/KEYS at the candidate, with its secret.
func TestReleaseTag_SignsOnlyWithTheReleaseKey(t *testing.T) {
	t.Run("release-tagging/AC-04", func(t *testing.T) {
		requireReleaseTag(t, "TagReleaseKey", 3, "test_a_key_not_in_keys_is_refused")
	})
}

// @ac AC-05
// AC-05: sign the candidate, verify the object and signature, push only that ref.
func TestReleaseTag_SignsVerifiesAndPushesOnlyTheTag(t *testing.T) {
	t.Run("release-tagging/AC-05", func(t *testing.T) {
		requireReleaseTag(t, "TagSignAndPush", 6,
			"test_push_sends_only_the_tag_ref_and_checks_origin",
			"test_push_refuses_an_unsigned_or_foreign_or_misplaced_tag",
			"test_the_repository_signing_key_is_not_used")
	})
}
