// @spec system-drift-detector
//
// AC traceability (this file):
//   AC-12  TestNoScanBaselinesReferences

package drift

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func packageDir(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(file)
}

// @ac AC-12
// AC-12: internal/drift source files contain no scan_baselines /
// ScanBaseline references. Python-era baseline table explicitly
// dropped — the prior host_rule_state aggregate IS the baseline.
func TestNoScanBaselinesReferences(t *testing.T) {
	t.Run("system-drift-detector/AC-12", func(t *testing.T) {
		dir := packageDir(t)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir: %v", err)
		}

		forbidden := []string{
			"scan_baselines",
			"ScanBaseline",
		}

		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			// This source_test.go contains the forbidden strings as
			// test literals; skip it.
			if e.Name() == "source_test.go" {
				continue
			}
			path := filepath.Join(dir, e.Name())
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			for _, bad := range forbidden {
				if strings.Contains(string(b), bad) {
					t.Errorf("%s references %q — Python-era baseline table dropped (AC-12)", path, bad)
				}
			}
		}
	})
}
