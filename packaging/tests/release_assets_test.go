// @spec release-asset-verification

package packaging_test

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// Release asset verification (release-asset-verification). The behavior lives
// in scripts/release_assets.py and is driven by scripts/test_release_assets.py,
// one unittest class per criterion. The suite runs once; each criterion checks
// its class passed in full and names the cases a reviewer relies on.

var (
	releaseAssetsOnce   sync.Once
	releaseAssetsOut    []byte
	releaseAssetsErr    error
	releaseAssetsPassed map[string]int
	releaseAssetsCases  map[string]bool
)

func requireReleaseAssets(t *testing.T, class string, want int, cases ...string) {
	t.Helper()
	haveTool(t, "python3")
	haveTool(t, "git")
	haveTool(t, "gpg")
	haveTool(t, "tar")
	dir := appDir(t)
	releaseAssetsOnce.Do(func() {
		cmd := exec.Command("python3", "-S", filepath.Join("scripts", "test_release_assets.py"))
		cmd.Dir = dir
		releaseAssetsOut, releaseAssetsErr = cmd.CombinedOutput()
		releaseAssetsPassed = map[string]int{}
		releaseAssetsCases = map[string]bool{}
		line := regexp.MustCompile(`\(__main__\.(\w+)\.(\w+)\) \.\.\. ok$`)
		for _, ln := range strings.Split(string(releaseAssetsOut), "\n") {
			if m := line.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
				releaseAssetsPassed[m[1]]++
				releaseAssetsCases[m[1]+"."+m[2]] = true
			}
		}
	})
	if releaseAssetsErr != nil {
		t.Fatalf("scripts/test_release_assets.py: %v\n%s", releaseAssetsErr, tailOf(releaseAssetsOut, 40))
	}
	if got := releaseAssetsPassed[class]; got != want {
		t.Errorf("%s: %d of %d cases passed", class, got, want)
	}
	for _, c := range cases {
		if !releaseAssetsCases[class+"."+c] {
			t.Errorf("%s.%s did not pass", class, c)
		}
	}
}

// @ac AC-01
// AC-01: inputs, a passing release, and raw evidence for every command.
func TestReleaseAssets_VerifiesFromRawEvidence(t *testing.T) {
	t.Run("release-asset-verification/AC-01", func(t *testing.T) {
		requireReleaseAssets(t, "AssetsRunAndEvidence", 5,
			"test_a_good_release_passes_every_check",
			"test_every_command_is_captured_with_its_declared_timeout")
	})
}

// @ac AC-02
// AC-02: the manifest, the KEYS asset and the tag bind the assets to the commit.
func TestReleaseAssets_BindsAssetsToTheCommit(t *testing.T) {
	t.Run("release-asset-verification/AC-02", func(t *testing.T) {
		requireReleaseAssets(t, "AssetsManifestAndRelease", 4, "test_a_tag_on_another_commit_fails")
	})
}

// @ac AC-03
// AC-03: SHA256SUMS and every RPM are signed by the release key.
func TestReleaseAssets_ChecksSignatures(t *testing.T) {
	t.Run("release-asset-verification/AC-03", func(t *testing.T) {
		requireReleaseAssets(t, "AssetsSignatures", 3, "test_a_signature_by_another_key_fails")
	})
}

// @ac AC-04
// AC-04: each binary is the commit's build, with go.mod's toolchain and modules.
func TestReleaseAssets_ChecksEachBinary(t *testing.T) {
	t.Run("release-asset-verification/AC-04", func(t *testing.T) {
		requireReleaseAssets(t, "AssetsBinaries", 3,
			"test_each_build_mismatch_fails_the_binary",
			"test_a_binary_from_another_commit_fails")
	})
}

// @ac AC-05
// AC-05: no called vulnerability, the commit's notices, SBOMs bound to packages.
func TestReleaseAssets_ChecksVulnsNoticesAndSboms(t *testing.T) {
	t.Run("release-asset-verification/AC-05", func(t *testing.T) {
		requireReleaseAssets(t, "AssetsVulnsNoticesSboms", 5,
			"test_a_called_vulnerability_fails_every_binary",
			"test_required_module_findings_are_reported_not_failed")
	})
}
