// @spec release-ci-gates

package packaging_test

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Accepted documentation defects (release-ci-gates C-22). The behavior lives in
// scripts/release-status.py and the registry in release/doc-review-exceptions.toml;
// their Python tests drive both. This criterion runs those tests, counts the
// cases by class so a deleted case is noticed, and reads the runbook and the
// generator for how a reviewer is told to use the exception.

// @ac AC-41
// AC-41: a captain-accepted defect, bound to one candidate and one blob.
func TestCIGates_DocumentationReviewAcceptsOnlyRegisteredDefects(t *testing.T) {
	t.Run("release-ci-gates/AC-41", func(t *testing.T) {
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
			"DocReviewAcceptedDefects": 11,
			"AcceptedDefectRegistry":   3,
		} {
			if passed[class] != want {
				t.Errorf("%s: %d of %d cases passed", class, passed[class], want)
			}
		}

		registry := readAppFile(t, "release/doc-review-exceptions.toml")
		if got := strings.Count(registry, "[[exception]]"); got != 2 {
			t.Errorf("release/doc-review-exceptions.toml has %d records; it holds the two "+
				"v0.8.4 records and nothing else", got)
		}

		book := readAppFile(t, "docs/runbooks/RELEASING.md")
		for _, want := range []struct{ frag, why string }{
			{"release-ci-gates` C-22", "the procedure must name the rule that allows the exception"},
			{"release/doc-review-exceptions.toml", "the procedure must point at the registry"},
			{"Never write `accurate` for it.", "an accepted defect is never recorded as accurate"},
		} {
			if !strings.Contains(book, want.frag) {
				t.Errorf("docs/runbooks/RELEASING.md is missing %q: %s", want.frag, want.why)
			}
		}
		if strings.Contains(book, "there is no waiver.") {
			t.Error("docs/runbooks/RELEASING.md still says there is no waiver; C-22 is one")
		}
		gen := readAppFile(t, "scripts/doc-review-skeleton.py")
		if strings.Contains(gen, "there is no waiver mechanism") {
			t.Error("the skeleton generator still says there is no waiver mechanism")
		}
	})
}
