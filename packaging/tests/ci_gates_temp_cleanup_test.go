// @spec release-ci-gates

package packaging_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// @ac AC-43
// AC-43: owned temporary directories are removed, and caller outputs survive.
func TestCIGates_TemporaryDirectoryOwnership(t *testing.T) {
	t.Run("release-ci-gates/AC-43", func(t *testing.T) {
		haveTool(t, "python3")
		haveTool(t, "git")
		cmd := exec.Command("python3", "-S", filepath.Join("scripts", "test_temp_cleanup.py"))
		cmd.Dir = appDir(t)
		raw, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("temporary cleanup tests: %v\n%s", err, raw)
		}
		for _, name := range []string{
			"test_tagged_checker_is_callable_after_import_directory_is_removed",
			"test_tagged_checker_failure_and_interrupt_remove_import_directory",
			"test_evaluation_cleans_on_exhaustion_failure_interrupt_and_close",
			"test_real_evaluation_keeps_workspace_until_last_row_then_cleans",
			"test_caller_workspace_and_outputs_survive_every_exit",
			"test_fixture_suites_leave_no_directories_on_success",
			"test_fixture_cleanup_is_registered_before_setup_can_fail",
		} {
			if !strings.Contains(string(raw), name+" (__main__.TemporaryOwnership."+name+") ... ok") {
				t.Errorf("cleanup case %s did not pass:\n%s", name, raw)
			}
		}
	})
}
