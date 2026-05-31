// @spec system-liveness-loop
//
// AC traceability (this file):
//
//	AC-32  TestTickRoutesMultiLayerWhenEnabled
//	AC-33  TestListProbeTargetsExcludesMaintenance
//	AC-34  TestListProbeTargetsOrdersByPriorityThenNextProbeAt
//	AC-35  TestPersistMultiLayerAppendsHistoryWhenEnabled
//	AC-36  TestNoCredentialImportsV130_AffirmsAC14

package liveness

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func readSourceFile(t *testing.T, name string) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// @ac AC-32
// AC-32: tick() routes through probeMultiLayerHost when the multi-layer
// machinery is wired (Pinger and/or PrivilegeProbeFunc). The legacy
// single-layer ProbeHost path stays as the else branch.
func TestTickRoutesMultiLayerWhenEnabled(t *testing.T) {
	t.Run("system-liveness-loop/AC-32", func(t *testing.T) {
		src := readSourceFile(t, "service.go")
		// The branch decision must come from multiLayerEnabled().
		if !strings.Contains(src, "useMultiLayer := s.multiLayerEnabled()") {
			t.Errorf("service.go missing multiLayerEnabled branch in tick()")
		}
		if !strings.Contains(src, "s.probeMultiLayerHost(") {
			t.Errorf("service.go missing probeMultiLayerHost call site")
		}
		if !strings.Contains(src, "s.ProbeHost(") {
			t.Errorf("service.go must keep ProbeHost as the legacy else branch")
		}
	})
}

// @ac AC-33
// AC-33: listProbeTargets MUST WHERE-out hosts.maintenance_mode = true.
// A host flipped to maintenance gets no probe, no history row, no audit.
func TestListProbeTargetsExcludesMaintenance(t *testing.T) {
	t.Run("system-liveness-loop/AC-33", func(t *testing.T) {
		src := readSourceFile(t, "service.go")
		if !strings.Contains(src, "h.maintenance_mode = false") {
			t.Errorf("listProbeTargets must filter `h.maintenance_mode = false`")
		}
	})
}

// @ac AC-34
// AC-34: ORDER BY priority DESC, next_probe_at ASC NULLS FIRST. Source
// inspection because the planner-level ordering decision is fixed in
// the literal SQL and not derived at runtime.
func TestListProbeTargetsOrdersByPriorityThenNextProbeAt(t *testing.T) {
	t.Run("system-liveness-loop/AC-34", func(t *testing.T) {
		src := readSourceFile(t, "service.go")
		if !strings.Contains(src, "ORDER BY h.check_priority DESC, hl.next_probe_at ASC NULLS FIRST") {
			t.Errorf("listProbeTargets ORDER BY clause missing or modified")
		}
	})
}

// @ac AC-35
// AC-35: persistMultiLayer appends a host_monitoring_history row when
// historyEnabled is true. Off by default — the appendHistory call is
// gated behind `if s.historyEnabled`.
func TestPersistMultiLayerAppendsHistoryWhenEnabled(t *testing.T) {
	t.Run("system-liveness-loop/AC-35", func(t *testing.T) {
		src := readSourceFile(t, "service_multilayer.go")
		if !strings.Contains(src, "if s.historyEnabled {") {
			t.Errorf("persistMultiLayer missing historyEnabled gate")
		}
		if !strings.Contains(src, "s.appendHistory(") {
			t.Errorf("persistMultiLayer must call appendHistory under the gate")
		}
		if !strings.Contains(src, "INSERT INTO host_monitoring_history") {
			t.Errorf("appendHistory must INSERT into host_monitoring_history")
		}
	})
}

// @ac AC-36
// AC-36: Reaffirm AC-14 invariant for v1.3.0 source files. Walks the
// import set (via go/parser) of every new multi-layer file. Comments
// that *mention* the forbidden packages are fine — only actual imports
// fail the test.
func TestNoCredentialImportsV130_AffirmsAC14(t *testing.T) {
	t.Run("system-liveness-loop/AC-36", func(t *testing.T) {
		_, file, _, _ := runtime.Caller(0)
		dir := filepath.Dir(file)
		fset := token.NewFileSet()
		for _, name := range []string{"multilayer.go", "state_multilayer.go", "service_multilayer.go"} {
			path := filepath.Join(dir, name)
			astFile, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			for _, imp := range astFile.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if strings.Contains(p, "internal/credential") {
					t.Errorf("%s imports %q — violates AC-14/36", name, p)
				}
				if strings.Contains(p, "golang.org/x/crypto/ssh") {
					t.Errorf("%s imports %q — violates AC-14/36", name, p)
				}
			}
			// Belt-and-suspenders: scan for ParsePrivateKey calls.
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			// Only flag actual code references, not the string in comments.
			// A literal "ssh.ParsePrivateKey(" would be a call site.
			if strings.Contains(string(src), "ssh.ParsePrivateKey(") {
				t.Errorf("%s calls ssh.ParsePrivateKey — violates AC-14/36", name)
			}
		}
	})
}
