// @spec ci-test-read-trace

package packaging_test

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// The test-read trace diagnostic (ci-test-read-trace). The behavior lives in
// scripts/trace-test-reads.py and .github/workflows/trace-test-reads.yml, and
// is driven by scripts/test_trace_test_reads.py, one unittest class per
// criterion. The suite runs once; each criterion checks its class passed in
// full and names the cases a reviewer relies on.

var (
	traceReadsOnce   sync.Once
	traceReadsOut    []byte
	traceReadsErr    error
	traceReadsPassed map[string]int
	traceReadsCases  map[string]bool
)

func requireTraceReads(t *testing.T, class string, want int, cases ...string) {
	t.Helper()
	haveTool(t, "python3")
	haveTool(t, "git")
	dir := appDir(t)
	traceReadsOnce.Do(func() {
		cmd := exec.Command("python3", "-S", filepath.Join("scripts", "test_trace_test_reads.py"))
		cmd.Dir = dir
		traceReadsOut, traceReadsErr = cmd.CombinedOutput()
		traceReadsPassed = map[string]int{}
		traceReadsCases = map[string]bool{}
		line := regexp.MustCompile(`\(__main__\.(\w+)\.(\w+)\) \.\.\. ok$`)
		for _, ln := range strings.Split(string(traceReadsOut), "\n") {
			if m := line.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
				traceReadsPassed[m[1]]++
				traceReadsCases[m[1]+"."+m[2]] = true
			}
		}
	})
	if traceReadsErr != nil {
		t.Fatalf("scripts/test_trace_test_reads.py: %v\n%s", traceReadsErr, tailOf(traceReadsOut, 40))
	}
	if got := traceReadsPassed[class]; got != want {
		t.Errorf("%s: %d of %d cases passed", class, got, want)
	}
	for _, c := range cases {
		if !traceReadsCases[class+"."+c] {
			t.Errorf("%s.%s did not pass", class, c)
		}
	}
}

// @ac AC-01
// AC-01: successful opens and executions are read from strace -f -y output.
func TestTraceReads_ParsesStrace(t *testing.T) {
	t.Run("ci-test-read-trace/AC-01", func(t *testing.T) {
		requireTraceReads(t, "ParsesStrace", 4,
			"test_successful_opens_are_kept_and_failures_are_not",
			"test_a_split_call_counts_its_resumed_result")
	})
}

// @ac AC-02
// AC-02: the documentation pattern is go-ci.yml's own, read at run time.
func TestTraceReads_ReadsThePattern(t *testing.T) {
	t.Run("ci-test-read-trace/AC-02", func(t *testing.T) {
		requireTraceReads(t, "ReadsThePattern", 2,
			"test_the_real_workflow_classifies_code_and_documentation")
	})
}

// @ac AC-03
// AC-03: gaps, tests not exercised, unread files and the limits are reported.
func TestTraceReads_ReportsGaps(t *testing.T) {
	t.Run("ci-test-read-trace/AC-03", func(t *testing.T) {
		requireTraceReads(t, "ReportsGaps", 8,
			"test_a_documentation_file_read_outside_the_documentation_path_is_a_gap",
			"test_a_path_outside_the_repository_is_never_taken_for_a_tracked_file",
			"test_the_report_states_its_limits_and_the_exit_follows_the_gaps")
	})
}

// @ac AC-04
// AC-04: run disables caching, traces every binary and suite, and keeps the evidence.
func TestTraceReads_RunsTraced(t *testing.T) {
	t.Run("ci-test-read-trace/AC-04", func(t *testing.T) {
		requireTraceReads(t, "RunsUntimedAndTraced", 4,
			"test_a_run_traces_go_python_and_records_vitest_as_not_run",
			"test_the_workflows_flag_form_is_accepted",
			"test_caching_and_the_wrapper_cannot_be_overridden")
	})
}

// @ac AC-05
// AC-05: the workflow runs weekly or by hand, reads only, and gates nothing.
func TestTraceReads_StaysADiagnostic(t *testing.T) {
	t.Run("ci-test-read-trace/AC-05", func(t *testing.T) {
		requireTraceReads(t, "StaysADiagnostic", 3,
			"test_it_runs_only_on_a_schedule_or_by_hand",
			"test_no_gate_or_required_check_reads_it")
	})
}
