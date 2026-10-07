// Source-inspection tests for the repository's front door: the files a new
// reader or a security reporter looks for first, and the version number they
// see when they get there.
//
// Both gates exist because the failure mode is silent. Nothing breaks when the
// README advertises a version we shipped two releases ago, or when a security
// policy is missing — the build stays green and the docs quietly stop being
// true. A reader who catches one stale fact discounts every other claim on the
// page, so these are checked by machine rather than left to review discipline.
//
// Deliberately NOT checked here: commit and branch naming, and whether a change
// earned a CHANGELOG entry. Those need a person to weigh them.

package packaging_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// hygieneRepoRoot returns the repo root (two dirs up from packaging/tests/), so
// these tests behave the same regardless of cwd.
func hygieneRepoRoot(t *testing.T) string {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
}

func readHygieneFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(hygieneRepoRoot(t), rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// versionEnvVersion returns VERSION from packaging/version.env, the single
// source of truth every other version string must agree with.
func versionEnvVersion(t *testing.T) string {
	t.Helper()
	for _, line := range strings.Split(readHygieneFile(t, "packaging/version.env"), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "VERSION=") {
			continue
		}
		return strings.Trim(strings.TrimPrefix(line, "VERSION="), `"'`)
	}
	t.Fatal("packaging/version.env declares no VERSION=")
	return ""
}

// readmeCurrentVersion pulls the version out of the README's project-status
// phrase. The phrase wraps across lines inside a blockquote, so the text is
// normalized (blockquote markers and line breaks collapsed to spaces) before
// matching.
var readmeVersionPhrase = regexp.MustCompile("current version is `([^`]+)`")

func readmeCurrentVersion(t *testing.T) string {
	t.Helper()
	doc := readHygieneFile(t, "README.md")
	flat := strings.Join(strings.Fields(strings.ReplaceAll(doc, "\n>", " ")), " ")
	m := readmeVersionPhrase.FindStringSubmatch(flat)
	if m == nil {
		t.Fatal("README.md no longer contains the phrase \"current version is `X`\"; " +
			"keep that phrasing so the version stays machine-checkable, or update " +
			"readmeVersionPhrase in this test to match the new wording")
	}
	return m[1]
}

// changelogLatestVersion returns the newest released version heading, skipping
// the [Unreleased] accumulator.
func changelogLatestVersion(t *testing.T) string {
	t.Helper()
	heading := regexp.MustCompile(`^## \[([^\]]+)\]`)
	for _, line := range strings.Split(readHygieneFile(t, "CHANGELOG.md"), "\n") {
		m := heading.FindStringSubmatch(line)
		if m == nil || m[1] == "Unreleased" {
			continue
		}
		return m[1]
	}
	t.Fatal("CHANGELOG.md has no released `## [<version>]` heading")
	return ""
}

// The version must be identical in all three places a reader can find it. The
// documented release flow bumps version.env and stamps the CHANGELOG in one
// "prepare release" pull request, and the README version is refreshed in the
// same one, so these never legitimately disagree on a merged commit.
func TestRepoHygiene_VersionAgreesAcrossSources(t *testing.T) {
	want := versionEnvVersion(t)

	if got := readmeCurrentVersion(t); got != want {
		t.Errorf("README.md advertises version %q but packaging/version.env says %q; "+
			"update the README project-status paragraph", got, want)
	}

	if got := changelogLatestVersion(t); got != want {
		t.Errorf("newest CHANGELOG.md heading is [%s] but packaging/version.env says %q; "+
			"stamp the release section (rename [Unreleased] to [%s] with an ISO date "+
			"and open a fresh empty [Unreleased])", got, want, want)
	}
}

// The files a newcomer and a security reporter expect to find, with the reason
// each one has to exist. Size floor catches a heading-only placeholder; it is
// deliberately low, since these are gates against absence, not length.
func TestRepoHygiene_FrontDoorFilesExist(t *testing.T) {
	frontDoor := []struct {
		name string
		why  string
	}{
		{"README.md", "what the project does and how to run it"},
		{"CONTRIBUTING.md", "how to build, test, and get a change reviewed"},
		{"SECURITY.md", "where vulnerability reports go instead of public issues"},
		{"CODE_OF_CONDUCT.md", "the behavior expected of participants"},
		{"LICENSE", "the terms the code is offered under"},
	}

	const minBytes = 200
	root := hygieneRepoRoot(t)
	for _, f := range frontDoor {
		info, err := os.Stat(filepath.Join(root, f.name))
		if err != nil {
			t.Errorf("%s is missing; it carries %s", f.name, f.why)
			continue
		}
		if info.Size() < minBytes {
			t.Errorf("%s is only %d bytes, too small to carry %s", f.name, info.Size(), f.why)
		}
	}
}

// A security policy is only useful if it routes reports away from public
// issues and tells a reporter what happens next. Checked by substance rather
// than by the file merely existing.
func TestRepoHygiene_SecurityPolicyIsActionable(t *testing.T) {
	doc := readHygieneFile(t, "SECURITY.md")

	if !strings.Contains(doc, "security@hanalyx.com") {
		t.Error("SECURITY.md names no reporting address; it must match the one in README.md")
	}

	lower := strings.ToLower(doc)
	for _, want := range []struct{ token, why string }{
		{"supported versions", "a reporter needs to know which releases get fixes"},
		{"do not open a public issue", "the policy must say where reports must NOT go"},
	} {
		if !strings.Contains(lower, want.token) {
			t.Errorf("SECURITY.md is missing %q: %s", want.token, want.why)
		}
	}
}

// Release attestations are internal evidence. The release checker reads them
// from release/attestations/ while a decision is open, and after publication
// they are archived outside the repository. The directory keeps only its
// .gitkeep. A tracked attestation, even one forced past .gitignore with
// `git add -f`, fails here.
func TestRepoHygiene_AttestationsAreNeverTracked(t *testing.T) {
	root := hygieneRepoRoot(t)
	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		out, err := cmd.Output()
		return string(out), err
	}

	tracked, err := git("ls-files", "-z", "--", "release/attestations")
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	var keep bool
	for _, path := range strings.Split(strings.TrimRight(tracked, "\x00"), "\x00") {
		switch path {
		case "":
		case "release/attestations/.gitkeep":
			keep = true
		default:
			t.Errorf("%s is tracked; attestations are internal evidence and are "+
				"archived outside the repository, never committed", path)
		}
	}
	if !keep {
		t.Error("release/attestations/.gitkeep is not tracked; without it the directory " +
			"does not exist in a fresh clone and `cp <file> release/attestations/` " +
			"writes a file named attestations")
	}

	// The ignore rule is what stops an ordinary `git add` from picking one up.
	// check-ignore exits 0 for an ignored path and 1 for a path it would add.
	for _, probe := range []string{
		"release/attestations/attest-H1-release-captain-v9.9.9.toml",
		"release/attestations/doc-review-v9.9.9.toml",
		"release/attestations/notes.md",
	} {
		if _, err := git("check-ignore", "-q", "--no-index", probe); err != nil {
			t.Errorf("%s is not ignored; .gitignore must ignore everything in "+
				"release/attestations/ except .gitkeep", probe)
		}
	}
	if _, err := git("check-ignore", "-q", "--no-index", "release/attestations/.gitkeep"); err == nil {
		t.Error("release/attestations/.gitkeep is ignored; the directory would vanish from a clone")
	}
}
