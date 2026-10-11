// @spec release-asset-verification

package packaging_test

import (
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
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

// @ac AC-06
// AC-06: the declared inventory, not a consistent manifest, decides completeness.
func TestReleaseAssets_RequiresTheDeclaredInventory(t *testing.T) {
	t.Run("release-asset-verification/AC-06", func(t *testing.T) {
		requireReleaseAssets(t, "AssetsInventory", 4,
			"test_no_packages_at_all_fails_even_with_a_signed_consistent_manifest",
			"test_a_missing_architecture_fails")
	})
}

// @ac AC-06
// AC-06: release/assets.toml is pinned to what the build makes and what the
// release workflow uploads, so the inventory cannot drift from the release.
func TestReleaseAssets_InventoryMatchesBuildAndUpload(t *testing.T) {
	t.Run("release-asset-verification/AC-06", func(t *testing.T) {
		inv := readAppFile(t, "release/assets.toml")
		var pkgs []string
		for _, m := range regexp.MustCompile(`(?m)^file = "([^"]+)"$`).FindAllStringSubmatch(inv, -1) {
			pkgs = append(pkgs, m[1])
		}
		sort.Strings(pkgs)

		// The Makefile's packages target names one build per package.
		m := regexp.MustCompile(`(?m)^packages:(.*)$`).FindStringSubmatch(readAppFile(t, "Makefile"))
		if m == nil {
			t.Fatal("Makefile has no packages target")
		}
		byTarget := map[string][]string{
			"rpm":         {"openwatch-{version}-1.x86_64.rpm"},
			"rpm-arm64":   {"openwatch-{version}-1.aarch64.rpm"},
			"deb":         {"openwatch_{version}_amd64.deb"},
			"deb-arm64":   {"openwatch_{version}_arm64.deb"},
			"kensa-rules": {"kensa-rules-{kensa}-1.noarch.rpm", "kensa-rules_{kensa}_all.deb"},
		}
		var want []string
		for _, target := range strings.Fields(m[1]) {
			files, ok := byTarget[target]
			if !ok {
				t.Errorf("the packages target builds %q, which release/assets.toml does not map; "+
					"declare its assets there and in this test", target)
			}
			want = append(want, files...)
		}
		sort.Strings(want)
		if strings.Join(pkgs, " ") != strings.Join(want, " ") {
			t.Errorf("release/assets.toml declares packages %v; the Makefile's packages target "+
				"builds %v", pkgs, want)
		}

		// release.yml uploads exactly what the inventory declares.
		y := readAppFile(t, ".github/workflows/release.yml")
		f := regexp.MustCompile(`(?s)\n\s+files: \|\n(.*?)\n\s*\n|(?s)\n\s+files: \|\n(.*)$`).FindStringSubmatch(y)
		if f == nil {
			t.Fatal("release.yml has no `files: |` upload list")
		}
		block := f[1] + f[2]
		var globs []string
		for _, ln := range strings.Split(block, "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || strings.Contains(ln, ":") {
				break
			}
			globs = append(globs, path.Base(ln))
		}
		match := func(name string) bool {
			for _, g := range globs {
				if ok, _ := path.Match(g, name); ok {
					return true
				}
			}
			return false
		}
		sample := strings.NewReplacer("{version}", "1.2.3", "{kensa}", "4.5.6")
		for _, p := range pkgs {
			if !match(sample.Replace(p)) {
				t.Errorf("release.yml does not upload %s (globs %v)", p, globs)
			}
			if !match(sample.Replace(p) + ".cdx.json") {
				t.Errorf("release.yml does not upload the SBOM of %s", p)
			}
		}
		for _, name := range []string{"openwatch.cdx.json", "SHA256SUMS", "SHA256SUMS.asc", "KEYS",
			"SHA256SUMS.cosign.sig"} {
			if !strings.Contains(inv, `"`+name+`"`) {
				t.Errorf("release/assets.toml does not declare %s", name)
			}
			if !match(name) {
				t.Errorf("release.yml does not upload %s (globs %v)", name, globs)
			}
		}
		for _, g := range globs {
			used := false
			for _, p := range pkgs {
				if ok, _ := path.Match(g, sample.Replace(p)); ok {
					used = true
				}
			}
			for _, name := range []string{"openwatch.cdx.json", "SHA256SUMS", "SHA256SUMS.asc",
				"KEYS", "SHA256SUMS.cosign.sig"} {
				if ok, _ := path.Match(g, name); ok {
					used = true
				}
			}
			if !used {
				t.Errorf("release.yml uploads %q, which release/assets.toml does not declare", g)
			}
		}
	})
}

// @ac AC-07
// AC-07: missing input and checks that could not run are failures, never a pass.
func TestReleaseAssets_NeverPassesWithoutEvidence(t *testing.T) {
	t.Run("release-asset-verification/AC-07", func(t *testing.T) {
		requireReleaseAssets(t, "AssetsNoSilentPass", 4,
			"test_a_missing_or_non_directory_from_is_refused",
			"test_a_failed_download_reports_every_area_as_not_run",
			"test_no_report_can_pass_without_checks_in_every_area")
	})
}

// @ac AC-08
// AC-08: govulncheck's output and exit status are validated together.
func TestReleaseAssets_ValidatesScannerOutput(t *testing.T) {
	t.Run("release-asset-verification/AC-08", func(t *testing.T) {
		requireReleaseAssets(t, "AssetsScannerOutput", 5,
			"test_an_empty_stream_fails_with_exit_0_or_3",
			"test_valid_module_only_findings_still_pass")
	})
}
