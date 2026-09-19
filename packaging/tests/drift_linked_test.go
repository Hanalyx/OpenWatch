// @spec system-drift-detector
//
//	AC-22  TestDriftDetector_IsLinkedIntoTheBinary
package packaging_test

import (
	"os/exec"
	"strings"
	"testing"
)

// @ac AC-22
// AC-22: internal/drift is a dependency of cmd/openwatch. The instrument is
// the dependency graph the linker sees. The package's own tests kept the
// coverage gate at 100% for two releases while no binary called it
// (CP bugs/OW-055).
func TestDriftDetector_IsLinkedIntoTheBinary(t *testing.T) {
	t.Run("system-drift-detector/AC-22", func(t *testing.T) {
		cmd := exec.Command("go", "list", "-deps", "./cmd/openwatch")
		cmd.Dir = repoRootForLinks(t)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list -deps ./cmd/openwatch: %v", err)
		}
		const want = "github.com/Hanalyx/openwatch/internal/drift"
		for _, dep := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if dep == want {
				return
			}
		}
		t.Fatalf("%s is not linked into cmd/openwatch: no build of serve or worker can call drift.DetectForScan (system-drift-detector C-11)", want)
	})
}
