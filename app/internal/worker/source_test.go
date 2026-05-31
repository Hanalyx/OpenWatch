// @spec system-worker-subcommand
//
// AC traceability (this file):
//
//	AC-09  TestSource_ExecutorRun_NoFrameworkArg
//	AC-12  TestSource_NoFrameworkID_InScanWorker
//	AC-14  TestSource_ImportsSchedulerVerify
//	AC-15  TestSource_AdvisoryLockKeyDerivation_FNV1a64

package worker

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// scanWorkerSourceFiles are the files that comprise the scan-job worker.
// AC-12 source-inspection runs against this exact set, excluding the
// existing Stage-0 worker.go (which is the diagnostics.test_job demo).
var scanWorkerSourceFiles = []string{
	"scan_worker.go",
	"advisory_lock.go",
	"backoff.go",
	"credential_bridge.go",
	"payload.go",
}

func readWorkerSource(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(".", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// stripComments removes // line comments and /* block */ comments so
// substring checks against "framework" / "framework_id" don't trigger
// on documentation that explains the v2.0.0 removal.
func stripComments(src string) string {
	// Strip block comments first (greedy, multi-line).
	block := regexp.MustCompile(`(?s)/\*.*?\*/`)
	src = block.ReplaceAllString(src, "")
	// Then strip line comments (// to end of line).
	line := regexp.MustCompile(`(?m)//.*$`)
	src = line.ReplaceAllString(src, "")
	return src
}

// AC-09: source inspection — the executor.Run call site has signature
// Run(ctx, hostID, policyVersion) — exactly 3 arguments. The call MUST
// NOT pass a framework argument.
func TestSource_ExecutorRun_NoFrameworkArg(t *testing.T) {
	t.Run("system-worker-subcommand/AC-09", func(t *testing.T) {
		src := readWorkerSource(t, "scan_worker.go")
		code := stripComments(src)

		// Find the executor.Run call. Regex tolerates whitespace and
		// the receiver name.
		callRE := regexp.MustCompile(`w\.executor\.Run\(\s*([^)]+)\s*\)`)
		matches := callRE.FindAllStringSubmatch(code, -1)
		if len(matches) == 0 {
			t.Fatalf("no w.executor.Run( call found in scan_worker.go (code-stripped)")
		}
		for _, m := range matches {
			args := strings.Split(m[1], ",")
			if len(args) != 3 {
				t.Errorf("w.executor.Run has %d args, want 3 — call: %q", len(args), m[0])
			}
			for _, a := range args {
				if strings.Contains(strings.ToLower(a), "framework") {
					t.Errorf("executor.Run argument %q contains 'framework' — v2.0.0 removed framework parameter", a)
				}
			}
		}
	})
}

// AC-12: source inspection — the scan-job worker package source files
// (excluding the existing Stage-0 diagnostics worker) do NOT contain
// the substring "framework_id" outside of comments. Documentation in
// comments that references the v1 legacy is allowed.
func TestSource_NoFrameworkID_InScanWorker(t *testing.T) {
	t.Run("system-worker-subcommand/AC-12", func(t *testing.T) {
		for _, name := range scanWorkerSourceFiles {
			src := readWorkerSource(t, name)
			stripped := stripComments(src)
			if strings.Contains(stripped, "framework_id") {
				t.Errorf("%s contains 'framework_id' outside of comments — v2.0.0 removed framework slicing from scan execution", name)
			}
		}
	})
}

// AC-14: source inspection — the scan-job worker package imports
// internal/scheduler and references its Verify function. Pins the
// HMAC-verification dependency to the canonical scheduler package
// rather than a worker-local duplicate.
func TestSource_ImportsSchedulerVerify(t *testing.T) {
	t.Run("system-worker-subcommand/AC-14", func(t *testing.T) {
		src := readWorkerSource(t, "scan_worker.go")
		if !strings.Contains(src, `"github.com/Hanalyx/openwatch/internal/scheduler"`) {
			t.Error("scan_worker.go must import internal/scheduler")
		}
		// The Verify call appears with the scheduler. qualifier (real
		// invocation) — not just in a comment.
		stripped := stripComments(src)
		if !regexp.MustCompile(`\bscheduler\.Verify\s*\(`).MatchString(stripped) {
			t.Error("scan_worker.go must call scheduler.Verify (HMAC verification dependency)")
		}
	})
}

// AC-15: source inspection — the advisory-lock helper computes its
// int64 key via FNV-1a 64-bit hash of uuid.UUID's 16 bytes. The
// pattern hash/fnv.New64a + Write(uuid[:]) + Sum64() + int64(cast)
// appears verbatim. Locks the derivation strategy so a future
// contributor doesn't silently change it.
func TestSource_AdvisoryLockKeyDerivation_FNV1a64(t *testing.T) {
	t.Run("system-worker-subcommand/AC-15", func(t *testing.T) {
		src := readWorkerSource(t, "advisory_lock.go")
		if !strings.Contains(src, `"hash/fnv"`) {
			t.Error("advisory_lock.go must import hash/fnv")
		}
		stripped := stripComments(src)
		// Each of the three signature lines of FNV-1a 64-bit derivation
		// must appear in the source.
		patterns := []string{
			`fnv.New64a`,
			`Write(hostID[:])`,
			`Sum64`,
			`int64(`,
		}
		for _, p := range patterns {
			if !strings.Contains(stripped, p) {
				t.Errorf("advisory_lock.go missing pattern %q — AC-15 pins FNV-1a 64-bit derivation", p)
			}
		}
	})
}
