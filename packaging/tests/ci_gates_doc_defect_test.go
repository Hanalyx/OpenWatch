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
			"DocReviewAcceptedDefects": 15,
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
			{"C-22 lets the D1 review of v0.8.4", "the procedure must name the rule and its single candidate"},
			{"release/doc-review-exceptions.toml", "the procedure must point at the registry"},
			{"Never write `accurate` for them.", "an accepted defect is never recorded as accurate"},
			{"There is no general waiver.", "C-22 is not a general waiver"},
			{"C-22\n   covers nothing else", "the exception is scoped to the two v0.8.4 documents"},
		} {
			if !strings.Contains(book, want.frag) {
				t.Errorf("docs/runbooks/RELEASING.md is missing %q: %s", want.frag, want.why)
			}
		}
		gen := readAppFile(t, "scripts/doc-review-skeleton.py")
		if !strings.Contains(gen, "there is no general waiver") {
			t.Error("the skeleton generator does not say there is no general waiver")
		}

	})
}

// @ac AC-41
// AC-41, privacy half: the tracked registry is public, so it carries the
// technical scope only, and the captain's acceptance is recorded in the internal
// attestation, where the runbook tells the reviewer to put it.
func TestCIGates_AcceptedDefectAcceptanceStaysInternal(t *testing.T) {
	t.Run("release-ci-gates/AC-41", func(t *testing.T) {
		registry := readAppFile(t, "release/doc-review-exceptions.toml")
		for _, field := range []string{"accepted_by", "accepted_at", "acceptance ="} {
			if strings.Contains(registry, field) {
				t.Errorf("release/doc-review-exceptions.toml carries %q; the public registry holds "+
					"the technical scope only, and the acceptance is internal", field)
			}
		}
		book := readAppFile(t, "docs/runbooks/RELEASING.md")
		for _, want := range []string{"[[defect_acceptance]]", "captain's acceptance is internal"} {
			if !strings.Contains(book, want) {
				t.Errorf("docs/runbooks/RELEASING.md is missing %q: the captain's acceptance is "+
					"recorded in the internal attestation", want)
			}
		}
		checker := readAppFile(t, "scripts/release-status.py")
		if !strings.Contains(checker, "the registered scope alone is not the captain's ") {
			t.Error("the checker does not refuse a registered defect that has no internal acceptance")
		}
	})
}
