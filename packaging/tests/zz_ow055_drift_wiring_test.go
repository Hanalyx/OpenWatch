package packaging_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Diagnostic for CP bugs/OW-055: is the drift detector part of the binary
// that serve and worker run? The instrument is the Go dependency graph of
// cmd/openwatch, which is what the linker sees; a grep over tests or a
// Specter coverage figure says nothing about the binary.
func TestZZOW055DriftDetectorIsLinkedIntoTheBinary(t *testing.T) {
	if os.Getenv("OW055") == "" {
		t.Skip()
	}
	cmd := exec.Command("go", "list", "-deps", "./cmd/openwatch")
	cmd.Dir = repoRootForLinks(t)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	deps := strings.Split(strings.TrimSpace(string(out)), "\n")
	has := func(p string) bool {
		for _, d := range deps {
			if d == p {
				return true
			}
		}
		return false
	}
	for _, p := range []string{
		"github.com/Hanalyx/openwatch/internal/alertrouter",
		"github.com/Hanalyx/openwatch/internal/eventbus",
		"github.com/Hanalyx/openwatch/internal/worker",
		"github.com/Hanalyx/openwatch/internal/drift",
	} {
		t.Logf("%-50s linked=%v", strings.TrimPrefix(p, "github.com/Hanalyx/openwatch/"), has(p))
	}
	if !has("github.com/Hanalyx/openwatch/internal/drift") {
		t.Errorf("internal/drift is not a dependency of cmd/openwatch: no build of serve or worker can call drift.DetectForScan, so no DriftDetected event is ever published and the alert router's drift_* kinds cannot fire (system-drift-detector context: \"runs at the end of every scan\"; daemon-orchestration scope note: \"called per-scan-completion by the worker\")")
	}
}
