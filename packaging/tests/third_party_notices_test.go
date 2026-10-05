package packaging_test

import (
	"os/exec"
	"testing"
)

// @spec release-package-build
// @ac AC-27
func TestThirdPartyNotices_Inventory(t *testing.T) {
	t.Run("release-package-build/AC-27", func(t *testing.T) {
		cmd := exec.Command("python3", "-S", "scripts/test_third_party_notices.py", "InventoryTests")
		cmd.Dir = appDir(t)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("inventory tests: %v\n%s", err, out)
		}
	})
}

// @spec release-package-build
// @ac AC-28
func TestThirdPartyNotices_Packages(t *testing.T) {
	t.Run("release-package-build/AC-28", func(t *testing.T) {
		cmd := exec.Command("python3", "-S", "scripts/test_third_party_notices.py", "PackagingTests")
		cmd.Dir = appDir(t)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("package license tests: %v\n%s", err, out)
		}
	})
}
