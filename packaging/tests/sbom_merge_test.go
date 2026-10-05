package packaging_test

// The release SBOMs gain the frontend's npm components and, for each package,
// the shipped binary's Go modules (spec system-supply-chain C-09). The logic
// lives in scripts/sbom-merge.py, which uses the standard library only; these
// tests run its unit tests one class per criterion.

import (
	"os/exec"
	"testing"
)

func runSBOMMergeTests(t *testing.T, class string) {
	t.Helper()
	cmd := exec.Command("python3", "-S", "scripts/test_sbom_merge.py", class)
	cmd.Dir = appDir(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", class, err, out)
	}
}

// @spec system-supply-chain
// @ac AC-12
func TestSupplyChain_SBOMFrontendInventory(t *testing.T) {
	t.Run("system-supply-chain/AC-12", func(t *testing.T) {
		runSBOMMergeTests(t, "InventoryTests")
	})
}

// @spec system-supply-chain
// @ac AC-13
func TestSupplyChain_SBOMMergePreservesGraph(t *testing.T) {
	t.Run("system-supply-chain/AC-13", func(t *testing.T) {
		runSBOMMergeTests(t, "GraphTests")
	})
}

// @spec system-supply-chain
// @ac AC-14
func TestSupplyChain_SBOMCheck(t *testing.T) {
	t.Run("system-supply-chain/AC-14", func(t *testing.T) {
		runSBOMMergeTests(t, "CheckTests")
	})
}

// @spec system-supply-chain
// @ac AC-15
func TestSupplyChain_ReleaseMergesSBOMs(t *testing.T) {
	t.Run("system-supply-chain/AC-15", func(t *testing.T) {
		runSBOMMergeTests(t, "WorkflowTests")
	})
}
