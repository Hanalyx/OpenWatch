// @spec system-scan-results-store
//
// AC traceability (this file):
//   AC-08  TestWorkerWiring_PersistBeforeMarkCompleted
//   AC-08  TestWriter_NoAuditImport

package scanresult

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

func repoRoot(t *testing.T) string {
	t.Helper()
	return filepath.Join(packageDir(t), "..", "..")
}

// @ac AC-08
// The durable write must run in the worker success path BEFORE the run is
// marked completed, so a run is never "completed" without its durable
// record. Source-inspect scan_worker.go: scanResults.Persist must appear,
// and appear before scanruns.MarkCompleted.
func TestWorkerWiring_PersistBeforeMarkCompleted(t *testing.T) {
	t.Run("system-scan-results-store/AC-08", func(t *testing.T) {
		src, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "worker", "scan_worker.go"))
		if err != nil {
			t.Fatalf("read scan_worker.go: %v", err)
		}
		body := string(src)
		persistIdx := strings.Index(body, "scanResults.Persist")
		if persistIdx < 0 {
			t.Fatal("scan_worker.go does not call scanResults.Persist")
		}
		markIdx := strings.Index(body, "scanruns.MarkCompleted")
		if markIdx < 0 {
			t.Fatal("scan_worker.go does not call scanruns.MarkCompleted")
		}
		if persistIdx > markIdx {
			t.Errorf("scanResults.Persist (at %d) must precede scanruns.MarkCompleted (at %d)", persistIdx, markIdx)
		}
	})
}

// @ac AC-08
// The scanresult writer must NOT emit audit events — the transaction log
// already emits finding.persisted; a second emission here would
// double-count. Enforce by source-inspecting the package's non-test .go
// files for any import of internal/audit.
func TestWriter_NoAuditImport(t *testing.T) {
	t.Run("system-scan-results-store/AC-08", func(t *testing.T) {
		dir := packageDir(t)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir: %v", err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatalf("read %s: %v", e.Name(), err)
			}
			if strings.Contains(string(b), "internal/audit") {
				t.Errorf("%s imports internal/audit; the scanresult writer must not emit audit events", e.Name())
			}
		}
	})
}
