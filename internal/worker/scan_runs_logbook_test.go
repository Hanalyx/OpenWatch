// @spec system-scan-runs
//
// Worker-side logbook integration:
//
//	AC-03  TestOutcomeCounts_TallyMatchesResult
//	AC-04  TestEveryFailPath_PairsWithMarkRunFailed
package worker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/kensa"
	"github.com/Hanalyx/openwatch/internal/scanruns"
)

// @ac AC-03
func TestOutcomeCounts_TallyMatchesResult(t *testing.T) {
	t.Run("system-scan-runs/AC-03", func(t *testing.T) {
		outcomes := []kensa.RuleOutcome{
			{RuleID: "a", Status: kensa.StatusPass},
			{RuleID: "b", Status: kensa.StatusPass},
			{RuleID: "c", Status: kensa.StatusFail},
			{RuleID: "d", Status: kensa.StatusSkipped},
			{RuleID: "e", Status: kensa.StatusError},
			{RuleID: "f", Status: kensa.StatusFail},
		}
		got := outcomeCounts(outcomes)
		want := scanruns.Counts{Pass: 2, Fail: 2, Skipped: 1, Error: 1}
		if got != want {
			t.Errorf("outcomeCounts = %+v, want %+v", got, want)
		}
		if empty := outcomeCounts(nil); empty != (scanruns.Counts{}) {
			t.Errorf("outcomeCounts(nil) = %+v, want zero", empty)
		}
	})
}

// @ac AC-04
// Source-inspection: every queue.Fail call in the scan worker's
// processJob / classifyAndHandle / recordTransientFailure paths must
// pair with a logbook failure write (markRunFailed / MarkFailed), so a
// failed job can never leave a scan_runs row stuck in queued/running.
// The single allowed exception is the wrong-job-type fast-fail, which
// is not a scan and owns no logbook row.
func TestEveryFailPath_PairsWithMarkRunFailed(t *testing.T) {
	t.Run("system-scan-runs/AC-04", func(t *testing.T) {
		wd, err := os.Getwd()
		if err != nil {
			t.Fatalf("getwd: %v", err)
		}
		raw, err := os.ReadFile(filepath.Join(wd, "scan_worker.go"))
		if err != nil {
			t.Fatalf("read scan_worker.go: %v", err)
		}
		src := string(raw)

		lines := strings.Split(src, "\n")
		for i, line := range lines {
			if !strings.Contains(line, "queue.Fail(") {
				continue
			}
			// The wrong-job-type fast-fail is exempt (not a scan).
			window := strings.Join(lines[max(0, i-6):min(len(lines), i+7)], "\n")
			if strings.Contains(window, "unsupported job_type") {
				continue
			}
			if !strings.Contains(window, "markRunFailed") && !strings.Contains(window, "MarkFailed") {
				t.Errorf("scan_worker.go:%d queue.Fail without a paired markRunFailed within +/-6 lines:\n%s",
					i+1, strings.TrimSpace(line))
			}
		}
	})
}
