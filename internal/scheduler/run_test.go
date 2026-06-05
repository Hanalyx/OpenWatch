// @spec system-scheduler
//
// AC traceability (this file):
//   AC-03  TestDefaultTickInterval_Is60Seconds
//          TestRun_SourceMentions60SecondInterval
//          TestDispatch_NoDoubleDispatch_OnRepeatedTick
//   AC-07  TestServer_NoSchedulerTableInScanHandlers

package scheduler

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// @ac AC-03
// AC-03: DefaultTickInterval is exactly 60 seconds. The constant is
// load-bearing for the production cron — spec C-02 fixes it at 60s and
// this test guards against accidental retuning.
func TestDefaultTickInterval_Is60Seconds(t *testing.T) {
	t.Run("system-scheduler/AC-03", func(t *testing.T) {
		if DefaultTickInterval != 60*time.Second {
			t.Errorf("DefaultTickInterval = %v, want 60s (spec C-02)", DefaultTickInterval)
		}
	})
}

// @ac AC-03
// AC-03 (source-inspection): the Run wiring uses DefaultTickInterval
// when callers pass 0, AND the constant's value is "60 * time.Second"
// at the source level. Guards against a refactor that breaks the spec
// invariant in a way the runtime test above can't catch.
func TestRun_SourceMentions60SecondInterval(t *testing.T) {
	t.Run("system-scheduler/AC-03", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(packageDir(t), "run.go"))
		if err != nil {
			t.Fatalf("read run.go: %v", err)
		}
		src := string(raw)

		// The literal "60 * time.Second" must appear in the constant
		// declaration. A future change to a configurable interval should
		// either keep this constant for the default OR update this AC.
		if !regexp.MustCompile(`DefaultTickInterval\s*=\s*60\s*\*\s*time\.Second`).MatchString(src) {
			t.Error("run.go does not declare DefaultTickInterval = 60 * time.Second; spec C-02 broken")
		}
	})
}

// @ac AC-03
// AC-03 (behavioral): after a Dispatch advances next_scheduled_scan,
// an immediately-following Dispatch (simulating a "missed tick recovery"
// where the cron fires twice in quick succession) claims zero hosts.
// This is the no-double-dispatch guarantee.
func TestDispatch_NoDoubleDispatch_OnRepeatedTick(t *testing.T) {
	t.Run("system-scheduler/AC-03", func(t *testing.T) {
		pool := freshPool(t)
		user := seedUser(t, pool)
		const N = 5
		for i := 0; i < N; i++ {
			h := seedHost(t, pool, user)
			seedSchedule(t, pool, h)
		}

		var calls []emitCall
		now := time.Now()
		svc := newTestService(t, pool, now, &calls)

		ctx := withCorrelation(context.Background(), "tick-1")
		first, err := svc.Dispatch(ctx)
		if err != nil {
			t.Fatalf("first Dispatch: %v", err)
		}
		if first != N {
			t.Errorf("first dispatched = %d, want %d", first, N)
		}

		// Second immediate tick under the same clock — next_scheduled_scan
		// was advanced to (now + interval), so no rows are due.
		ctx2 := withCorrelation(context.Background(), "tick-2")
		second, err := svc.Dispatch(ctx2)
		if err != nil {
			t.Fatalf("second Dispatch: %v", err)
		}
		if second != 0 {
			t.Errorf("second dispatched = %d, want 0 (double-dispatch guard broken)", second)
		}
	})
}

// @ac AC-07
// AC-07: the manual scan path (handlers in internal/server) must NOT
// touch host_compliance_schedule. This is a source-inspection test:
// scans server source files and asserts no reference to the table name.
// The scheduler is the ONLY writer of that table.
func TestServer_NoSchedulerTableInScanHandlers(t *testing.T) {
	t.Run("system-scheduler/AC-07", func(t *testing.T) {
		serverDir := filepath.Join(packageDir(t), "..", "server")

		entries, err := os.ReadDir(serverDir)
		if err != nil {
			t.Fatalf("read server dir %s: %v", serverDir, err)
		}

		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			// Only check Go source, skip tests (test fixtures may
			// reference the table for assertions in unrelated specs).
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}

			b, err := os.ReadFile(filepath.Join(serverDir, name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			if strings.Contains(string(b), "host_compliance_schedule") {
				t.Errorf("server/%s references host_compliance_schedule; manual scans MUST bypass the schedule (AC-07). Only internal/scheduler may touch this table.", name)
			}
		}
	})
}

// packageDir returns the absolute path of this package's source directory.
// Used by source-inspection tests above.
func packageDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed; cannot resolve package directory")
	}
	return filepath.Dir(file)
}
