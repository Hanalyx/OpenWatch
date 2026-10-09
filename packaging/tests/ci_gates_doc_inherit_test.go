// @spec release-ci-gates

package packaging_test

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Documentation-review inheritance (release-ci-gates C-21). The behavior lives
// in scripts/release-status.py and scripts/doc-review-skeleton.py; their
// Python tests drive it. This criterion runs those tests, counts the
// inheritance cases by class so a deleted case is noticed, and reads the
// runbook for how a reviewer is told to use it.

// @ac AC-40
// AC-40: inheriting a documentation review from the last published release.
func TestCIGates_DocumentationReviewInheritsOnlyUnchangedDocuments(t *testing.T) {
	t.Run("release-ci-gates/AC-40", func(t *testing.T) {
		haveTool(t, "python3")
		haveTool(t, "git")
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
			"DocReviewInheritance":                     18,
			"LastPublishedReleaseIsTheOnlySource":      6,
			"SkeletonCanInheritFromThePublishedReview": 1,
		} {
			if passed[class] != want {
				t.Errorf("%s: %d of %d cases passed", class, passed[class], want)
			}
		}

		book := readAppFile(t, "docs/runbooks/RELEASING.md")
		for _, want := range []struct{ frag, why string }{
			{"--inherit-from", "the procedure must run the generator's inheriting mode, not describe it"},
			{"release-ci-gates` C-21", "the procedure must name the rule that allows inheritance"},
			{"inherits.changes_reviewed", "the reviewer must be told to record the checked change range"},
			{"nothing is ever carried over from an RC", "inheritance must never come from a release candidate"},
		} {
			if !strings.Contains(book, want.frag) {
				t.Errorf("docs/runbooks/RELEASING.md is missing %q: %s", want.frag, want.why)
			}
		}
	})
}

// @ac AC-40
// AC-40, runbook half: the reviewer is told that the generated split is
// provisional, and that the prior review is re-checked by the checker from the
// prior release's own tag rather than by today's rules.
func TestCIGates_DocumentationReviewInheritanceIsProvisionalAndVerifiedAsDecided(t *testing.T) {
	t.Run("release-ci-gates/AC-40", func(t *testing.T) {
		book := readAppFile(t, "docs/runbooks/RELEASING.md")
		for _, want := range []struct{ frag, why string }{
			{"The split the generator writes is provisional",
				"a text scan of changed file names is a flag, not a dependency analysis"},
			{"checker from that release's own tag",
				"the prior review is verified as it was decided, not by today's rules"},
		} {
			if !strings.Contains(book, want.frag) {
				t.Errorf("docs/runbooks/RELEASING.md is missing %q: %s", want.frag, want.why)
			}
		}
		gen := readAppFile(t, "scripts/doc-review-skeleton.py")
		if !strings.Contains(gen, "PROVISIONAL SPLIT") {
			t.Error("the inheriting skeleton does not say its split is provisional")
		}
		checker := readAppFile(t, "scripts/release-status.py")
		for _, want := range []string{"Candidate's own policy:", "Amendment applied:", "Checker commit:"} {
			if !strings.Contains(checker, want) {
				t.Errorf("the checker's NOTE does not print %q; a decision under a later rule "+
					"must record the candidate's policy, the amendment and the checker commit", want)
			}
		}
	})
}
