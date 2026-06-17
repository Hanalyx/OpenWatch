// @spec release-changelog
//
// Source-inspection tests for CHANGELOG.md authoring discipline. The
// changelog is the operator-facing record of what changed between releases;
// these tests gate its structure (dated version sections, Keep a Changelog
// categories), the human-readability of newly authored entries (the
// [Unreleased] section), and the repo-wide no-emoji rule. Released sections
// authored before release-changelog are grandfathered: the strict per-entry
// checks run only against [Unreleased], the surface authors actively edit.

package packaging_test

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// changelogPath returns the repo-root CHANGELOG.md (two dirs up from
// packaging/tests/), so the test behaves the same regardless of cwd.
func changelogPath(t *testing.T) string {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(here), "..", "..", "CHANGELOG.md"))
}

func readChangelog(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(changelogPath(t))
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}
	return string(b)
}

// unreleasedBlock returns the lines of the [Unreleased] section (between its
// `## [Unreleased]` heading and the next `## [` version heading).
func unreleasedBlock(t *testing.T, doc string) []string {
	t.Helper()
	lines := strings.Split(doc, "\n")
	start := -1
	for i, ln := range lines {
		if strings.HasPrefix(ln, "## [Unreleased]") {
			start = i + 1
			break
		}
	}
	if start == -1 {
		t.Fatal("CHANGELOG.md has no `## [Unreleased]` section")
	}
	var out []string
	for _, ln := range lines[start:] {
		if strings.HasPrefix(ln, "## [") {
			break
		}
		out = append(out, ln)
	}
	return out
}

// @ac AC-01
//
// Every `## [<version>]` heading other than [Unreleased] carries an ISO date;
// the [Unreleased] accumulator exists and carries no date.
func TestChangelog_VersionSectionsDated(t *testing.T) {
	t.Run("release-changelog/AC-01", func(t *testing.T) {
		doc := readChangelog(t)
		isoDate := regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)
		sawUnreleased := false
		for _, ln := range strings.Split(doc, "\n") {
			if !strings.HasPrefix(ln, "## [") {
				continue
			}
			if strings.HasPrefix(ln, "## [Unreleased]") {
				sawUnreleased = true
				if isoDate.MatchString(ln) {
					t.Errorf("[Unreleased] heading must not carry a date: %q", ln)
				}
				continue
			}
			if !isoDate.MatchString(ln) {
				t.Errorf("released version heading lacks an ISO date: %q", ln)
			}
		}
		if !sawUnreleased {
			t.Error("CHANGELOG.md has no `## [Unreleased]` section")
		}
	})
}

// @ac AC-02
//
// Category headings in the [Unreleased] section are drawn only from the Keep a
// Changelog vocabulary.
func TestChangelog_UnreleasedCategoriesAreStandard(t *testing.T) {
	t.Run("release-changelog/AC-02", func(t *testing.T) {
		allowed := map[string]bool{
			"Added": true, "Changed": true, "Deprecated": true,
			"Removed": true, "Fixed": true, "Security": true,
		}
		for _, ln := range unreleasedBlock(t, readChangelog(t)) {
			if !strings.HasPrefix(ln, "### ") {
				continue
			}
			cat := strings.TrimSpace(strings.TrimPrefix(ln, "### "))
			if !allowed[cat] {
				t.Errorf("non-standard category heading in [Unreleased]: %q (allowed: Added/Changed/Deprecated/Removed/Fixed/Security)", cat)
			}
		}
	})
}

// @ac AC-03
//
// Top-level entries in [Unreleased] read as user-facing sentences: at least 5
// words and not a raw conventional-commit subject.
func TestChangelog_UnreleasedEntriesAreHumanReadable(t *testing.T) {
	t.Run("release-changelog/AC-03", func(t *testing.T) {
		commitPrefix := regexp.MustCompile(`^(feat|fix|chore|docs|refactor|test|ci|perf|build|style)(\([^)]*\))?:`)
		// Strip markdown emphasis and inline-code ticks so word counting and
		// prefix detection see the prose, not the formatting.
		strip := strings.NewReplacer("**", "", "`", "", "*", "")
		for _, ln := range unreleasedBlock(t, readChangelog(t)) {
			// Only top-level bullets ("- "); continuation/sub-bullets are indented.
			if !strings.HasPrefix(ln, "- ") {
				continue
			}
			entry := strings.TrimSpace(strip.Replace(strings.TrimPrefix(ln, "- ")))
			if commitPrefix.MatchString(entry) {
				t.Errorf("entry reads as a raw commit subject, not a user-facing sentence: %q", entry)
			}
			if n := len(strings.Fields(entry)); n < 5 {
				t.Errorf("entry too terse to be human-readable (%d words, need >=5): %q", n, entry)
			}
		}
	})
}

// @ac AC-05
//
// An [Unreleased] entry that calls out a regression must name the version it
// regressed in, so an operator can judge exposure.
func TestChangelog_RegressionsNameAVersion(t *testing.T) {
	t.Run("release-changelog/AC-05", func(t *testing.T) {
		versionTok := regexp.MustCompile(`\d+\.\d+(\.\d+)?(-rc\.\d+)?|v\d+\.\d+`)
		for _, ln := range unreleasedBlock(t, readChangelog(t)) {
			if !strings.HasPrefix(ln, "- ") {
				continue
			}
			if !strings.Contains(strings.ToLower(ln), "regression") {
				continue
			}
			if !versionTok.MatchString(ln) {
				t.Errorf("regression entry names no version: %q", strings.TrimSpace(ln))
			}
		}
	})
}

// @ac AC-04
//
// The whole changelog is emoji-free, matching the repo-wide no-emoji rule.
// Arrows (U+2190..U+21FF) and box-drawing are intentionally NOT treated as
// emoji — the changelog uses "->" arrows in prose.
func TestChangelog_NoEmoji(t *testing.T) {
	t.Run("release-changelog/AC-04", func(t *testing.T) {
		doc := readChangelog(t)
		isEmoji := func(r rune) bool {
			switch {
			case r >= 0x1F000 && r <= 0x1FAFF: // pictographs, symbols, supplemental
				return true
			case r >= 0x2600 && r <= 0x27BF: // misc symbols + dingbats
				return true
			case r >= 0x2B00 && r <= 0x2BFF: // stars, decorative arrows
				return true
			case r == 0xFE0F: // emoji variation selector
				return true
			}
			return false
		}
		for i, ln := range strings.Split(doc, "\n") {
			for _, r := range ln {
				if isEmoji(r) {
					t.Errorf("emoji %q (U+%04X) on line %d: %q", string(r), r, i+1, ln)
					break
				}
			}
		}
	})
}
