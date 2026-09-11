// @spec release-ci-gates
//
// Static checks on the CI gate plumbing: Makefile targets, .golangci.yml
// linter set, and GitHub Actions workflow shape. The tests inspect
// configuration files rather than re-running gates against the codebase
// — those gates already run on every PR.

package packaging_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Hanalyx/openwatch/internal/specfixture"
)

// readAppFile returns the contents of a file relative to the repo root
// (appDir; the Go tree lives at the repo root since the app/ promotion).
func readAppFile(t *testing.T, relpath string) string {
	t.Helper()
	dir := appDir(t)
	raw, err := os.ReadFile(filepath.Join(dir, relpath))
	if err != nil {
		t.Fatalf("read %s: %v", relpath, err)
	}
	return string(raw)
}

// @ac AC-01
// AC-01: make vet target exists and invokes `go vet ./...`.
func TestCIGates_VetTarget(t *testing.T) {
	t.Run("release-ci-gates/AC-01", func(t *testing.T) {
		mf := readAppFile(t, "Makefile")
		// The target body must contain "go vet ./...".
		re := regexp.MustCompile(`(?ms)^\.PHONY: vet\nvet:[^\n]*\n.*?go vet \./\.\.\.`)
		if !re.MatchString(mf) {
			t.Error("Makefile missing `make vet` target running `go vet ./...`")
		}
	})
}

// @ac AC-02
// AC-02: make lint target exists and the lint config enables the required
// linter set.
func TestCIGates_LintTargetAndLinters(t *testing.T) {
	t.Run("release-ci-gates/AC-02", func(t *testing.T) {
		mf := readAppFile(t, "Makefile")
		if !strings.Contains(mf, "golangci-lint run") {
			t.Error("Makefile lint target lacks `golangci-lint run` invocation")
		}
		lc := readAppFile(t, ".golangci.yml")
		required := []string{
			"govet", "staticcheck", "gosec", "errcheck",
			"unused", "ineffassign", "revive", "forbidigo",
		}
		for _, l := range required {
			pattern := regexp.MustCompile(`(?m)^\s+-\s+` + regexp.QuoteMeta(l) + `\b`)
			if !pattern.MatchString(lc) {
				t.Errorf(".golangci.yml does not enable linter %q in the linters.enable block", l)
			}
		}
	})
}

// @ac AC-03
// AC-03: make vuln target exists and invokes govulncheck.
func TestCIGates_VulnTarget(t *testing.T) {
	t.Run("release-ci-gates/AC-03", func(t *testing.T) {
		mf := readAppFile(t, "Makefile")
		re := regexp.MustCompile(`(?ms)^\.PHONY: vuln\nvuln:[^\n]*\n.*?govulncheck`)
		if !re.MatchString(mf) {
			t.Error("Makefile missing `make vuln` target invoking govulncheck")
		}
		if !strings.Contains(mf, "go install golang.org/x/vuln/cmd/govulncheck") {
			t.Error("Makefile vuln target should auto-install govulncheck if absent")
		}
	})
}

// @ac AC-04
// AC-04: make test-race target exists and runs `go test -race ./...`.
func TestCIGates_TestRaceTarget(t *testing.T) {
	t.Run("release-ci-gates/AC-04", func(t *testing.T) {
		mf := readAppFile(t, "Makefile")
		re := regexp.MustCompile(`(?ms)^\.PHONY: test-race\ntest-race:[^\n]*\n.*?go test -race`)
		if !re.MatchString(mf) {
			t.Error("Makefile missing `make test-race` target invoking `go test -race`")
		}
	})
}

// @ac AC-05
// AC-05: make check chains vet → lint → vuln → test-race in that order
// via make prerequisites.
func TestCIGates_CheckChainsAllGates(t *testing.T) {
	t.Run("release-ci-gates/AC-05", func(t *testing.T) {
		mf := readAppFile(t, "Makefile")
		re := regexp.MustCompile(`(?m)^check:\s+vet\s+lint\s+vuln\s+test-race\b`)
		if !re.MatchString(mf) {
			t.Error("Makefile missing `check: vet lint vuln test-race` prerequisite chain (in that exact order)")
		}
	})
}

// @ac AC-06
// AC-06: make help lists every gate target.
func TestCIGates_HelpListsGates(t *testing.T) {
	t.Run("release-ci-gates/AC-06", func(t *testing.T) {
		mf := readAppFile(t, "Makefile")
		// Look in the help target for each gate name.
		for _, g := range []string{"vet", "lint", "vuln", "test-race", "check"} {
			pattern := regexp.MustCompile(`(?m)^\s+@echo\s+".*\b` + regexp.QuoteMeta(g) + `\b`)
			if !pattern.MatchString(mf) {
				t.Errorf("make help missing line for gate %q", g)
			}
		}
	})
}

// @ac AC-07
// AC-07: go-ci.yml triggers on every PR/push to main without a paths
// filter, references the Go source paths (cmd/, internal/, ...) in a
// path-detection step, and gates the heavy gate steps on that step so
// non-Go PRs short-circuit to success while still producing the
// "Quality + security gates" required check.
func TestCIGates_WorkflowExistsAndScoped(t *testing.T) {
	t.Run("release-ci-gates/AC-07", func(t *testing.T) {
		wf := readAppFile(t, ".github/workflows/go-ci.yml")

		// Triggers must NOT have a paths filter — that would make the
		// required check structurally missing on non-Go PRs and block
		// every doc/packaging/backend/frontend merge.
		triggerPathsFilter := regexp.MustCompile(`(?m)^\s+(pull_request|push):\s*\n(\s+[^p].*\n)*\s+paths:\s*$`)
		if triggerPathsFilter.MatchString(wf) {
			t.Error("go-ci.yml has a paths filter on its trigger block — the required check would be missing for non-Go PRs")
		}

		// The path-detection step references the Go source paths so the
		// heavy pipeline runs for Go-relevant changes (the tree lives at
		// the repo root since the app/ promotion).
		if !strings.Contains(wf, "^(cmd/") &&
			!strings.Contains(wf, "internal/") {
			t.Error("go-ci.yml must reference the Go source paths (cmd/, internal/, ...) in its path-detection step")
		}

		// The gates steps must be gated on the path-detection output.
		if !strings.Contains(wf, "steps.paths.outputs.go") {
			t.Error("go-ci.yml must gate heavy steps on steps.paths.outputs.go (path-detection step output)")
		}

		// Path-detect step is present.
		if !regexp.MustCompile(`(?m)id:\s*paths\b`).MatchString(wf) {
			t.Error("go-ci.yml must include a step with id: paths that detects Go-relevant changes")
		}
	})
}

// @ac AC-08
// AC-08: workflow defines a Postgres service container the tests can use.
func TestCIGates_WorkflowHasPostgresService(t *testing.T) {
	t.Run("release-ci-gates/AC-08", func(t *testing.T) {
		wf := readAppFile(t, ".github/workflows/go-ci.yml")
		// Service block must reference postgres and expose POSTGRES_USER /
		// POSTGRES_DB env so the test DSN can connect.
		if !regexp.MustCompile(`(?m)^\s*services:\s*$`).MatchString(wf) {
			t.Error("workflow lacks a services: block")
		}
		if !strings.Contains(wf, "image: postgres:") {
			t.Error("workflow services block lacks a postgres: image")
		}
		if !strings.Contains(wf, "POSTGRES_USER") || !strings.Contains(wf, "POSTGRES_DB") {
			t.Error("postgres service must set POSTGRES_USER and POSTGRES_DB")
		}
	})
}

// @ac AC-09
// AC-09: workflow runs each gate as its own step (vet, lint, vuln, the
// race+JSON test run, specter sync). Race detection and the specter-ingest
// JSON are produced by a single `go test -race -json` step (replacing the
// former separate `make test-race` + non-race json passes), so the gate is
// the presence of `-race` AND `-json` on the test run, not `make test-race`.
func TestCIGates_WorkflowRunsAllGates(t *testing.T) {
	t.Run("release-ci-gates/AC-09", func(t *testing.T) {
		wf := readAppFile(t, ".github/workflows/go-ci.yml")
		gates := []string{
			"make vet",
			"make lint",
			"make vuln",
			"specter sync",
		}
		for _, g := range gates {
			if !strings.Contains(wf, g) {
				t.Errorf("workflow missing step that runs %q", g)
			}
		}
		// The single race+coverage run must still detect data races AND
		// emit JSON for specter ingest.
		if !strings.Contains(wf, "go test -race") || !strings.Contains(wf, "-json") {
			t.Error("workflow missing the race+JSON test run (`go test -race ... -json`) — race detection must still gate")
		}
	})
}

// @ac AC-10
// AC-10: workflow runs on push to main + pull_request targeting main.
func TestCIGates_WorkflowTriggers(t *testing.T) {
	t.Run("release-ci-gates/AC-10", func(t *testing.T) {
		wf := readAppFile(t, ".github/workflows/go-ci.yml")
		if !regexp.MustCompile(`(?m)^\s*push:\s*$`).MatchString(wf) {
			t.Error("workflow lacks a push: trigger")
		}
		if !regexp.MustCompile(`(?m)^\s*pull_request:\s*$`).MatchString(wf) {
			t.Error("workflow lacks a pull_request: trigger")
		}
		if !regexp.MustCompile(`branches:\s*\[\s*main\s*\]|- main`).MatchString(wf) {
			t.Error("workflow triggers must scope to main branch")
		}
	})
}

// runGateWith runs the real gate against a fake `specter` on PATH.
//
// Static assertions cannot tell whether the gate ACTS on its fixture values,
// so the behavioral cases below drive the whole script: a stub specter prints
// the JSON summary and coverage table each scenario needs, and seeded titles
// stand in for a Vitest collection so no npm install is required.
func runGateWith(t *testing.T, dir, stage, summaryJSON, coverageOut string, exitJSON int) (int, string) {
	t.Helper()
	tmp := t.TempDir()
	stub := filepath.Join(tmp, "specter")
	script := "#!/bin/sh\n" +
		"case \"$*\" in\n" +
		"  *--version*) cat " + filepath.Join(dir, ".specter-version") + "; exit 0;;\n" +
		"  *--json*) cat <<'EOF'\n" + summaryJSON + "\nEOF\n exit " + strconv.Itoa(exitJSON) + ";;\n" +
		"  *coverage*) cat <<'EOF'\n" + coverageOut + "\nEOF\n exit 0;;\n" +
		"esac\nexit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	cmd := exec.Command("python3", "-S", filepath.Join(dir, "scripts/specter-gate.py"),
		"--only", stage)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"PATH="+tmp+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run gate: %v", err)
	}
	return code, string(out)
}

func coverageTable(pct int) string {
	failing := 0
	status := "PASS"
	if pct < 100 {
		failing = 1
		status = "FAIL"
	}
	return fmt.Sprintf(
		"Spec ID                    Tier   ACs   Covered   Coverage   Status\n"+
			"demo-spec                  T1     10    %d        %d%%      %s\n\n"+
			"121 specs: %d passing, %d failing",
		pct/10, pct, status, 121-failing, failing)
}

// @ac AC-11
// AC-11: one shared gate enforces the Specter contract and both callers
// invoke it, so `make spec-check` and CI cannot drift into different
// policies. Every fixture field drives an assertion, and the severity and
// coverage thresholds are bound behaviorally rather than by reading source.
func TestCIGates_SpecterGateIsShared(t *testing.T) {
	t.Run("release-ci-gates/AC-11", func(t *testing.T) {
		dir := appDir(t)
		all := specfixture.Load(t, filepath.Join(dir, "specs/release/ci-gates.spec.yaml"), "release-ci-gates")
		ac := specfixture.Get(t, all, "AC-11")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		pinFile := in.Str("pin_file")
		wantVersion := in.Str("pinned_version")
		gate := in.Str("shared_gate")
		wantCoverage := in.Int("structural_coverage_pct")
		forbidden := in.Str("forbidden_in_callers")

		// The pin lives in exactly one tracked file.
		if !exp.Bool("version_pin_is_read_from_one_file") {
			t.Fatal("AC-11 must require a single pin file")
		}
		if got := strings.TrimSpace(readAppFile(t, pinFile)); got != wantVersion {
			t.Errorf("%s pins %q, spec requires %q", pinFile, got, wantVersion)
		}

		src := readAppFile(t, gate)
		if exp.Bool("gate_reads_the_json_summary") {
			if !strings.Contains(src, `"--json"`) || !strings.Contains(src, `"summary"`) {
				t.Error("the gate must read specter's JSON summary")
			}
		}
		if exp.Bool("exit_status_is_checked_alongside_the_summary") {
			// The SPECIFIC guard: `code != 0` appears three times in the
			// gate for unrelated reasons, so a looser match stayed true
			// after this one was removed.
			if !strings.Contains(src, "if code != 0 and not (errors or warnings):") {
				t.Error("the gate must fail on a nonzero exit even when the summary is clean")
			}
		}
		if !strings.Contains(src, pinFile) {
			t.Errorf("the gate must read the pin from %s", pinFile)
		}

		// Callers drive both the paths inspected and the invocation required.
		// MapList, not List: each entry is itself a fixture whose fields must
		// all be consumed, so a nested key cannot be added and go unchecked.
		callers := in.MapList("callers")
		if len(callers) == 0 {
			t.Fatal("AC-11 must name the callers")
		}
		checkCallers := exp.Bool("both_callers_invoke_the_same_gate")
		requireDashS := exp.Bool("gate_runs_with_site_packages_disabled")
		for _, c := range callers {
			path := c.Str("path")
			invocation := c.Str("invocation")
			kind := c.Str("kind")
			c.AllConsumed()
			body := readAppFile(t, path)

			// Require an INVOCATION, not a mention: both files explain the
			// gate in a comment, so a whole-file substring search stayed
			// true after the recipe and the run: step were swapped out.
			found := false
			for _, ln := range strings.Split(body, "\n") {
				code := ln
				if i := strings.Index(code, "#"); i >= 0 {
					code = code[:i]
				}
				if !strings.Contains(code, invocation) {
					continue
				}
				if kind == "recipe" && strings.HasPrefix(ln, "\t") {
					found = true
				}
				if kind == "run_step" && strings.Contains(code, "run:") {
					found = true
				}
			}
			if checkCallers && !found {
				t.Errorf("%s has no %s invoking %q", path, kind, invocation)
			}
			if requireDashS && !strings.Contains(invocation, "python3 -S ") {
				t.Errorf("caller %s must invoke the gate under python3 -S", path)
			}
			// The collection seam must never appear in a caller, or the gate
			// could be handed titles instead of collecting them.
			if strings.Contains(body, forbidden) {
				t.Errorf("%s must not set %s", path, forbidden)
			}
		}

		// ONE source for the version: the workflow derives it from the pin
		// file rather than carrying its own literal.
		wf := readAppFile(t, ".github/workflows/go-ci.yml")
		if !strings.Contains(wf, pinFile) {
			t.Errorf(".github/workflows/go-ci.yml must read the version from %s", pinFile)
		}
		if strings.Contains(wf, `"`+wantVersion+`"`) || strings.Contains(wf, "'"+wantVersion+"'") {
			t.Errorf(".github/workflows/go-ci.yml still hardcodes version %q; derive it from %s",
				wantVersion, pinFile)
		}

		// ---- Behavioral: the severities and the coverage threshold.
		clean := `{"diagnostics": null, "summary": {"errors": 0, "warnings": 0, "info": 0}}`
		if code, out := runGateWith(t, dir, "coverage", clean, coverageTable(wantCoverage), 0); code != 0 {
			t.Errorf("a clean run at %d%% coverage must pass; exit %d\n%s", wantCoverage, code, out)
		}
		// Below the required percentage must fail.
		if code, _ := runGateWith(t, dir, "coverage", clean, coverageTable(wantCoverage-1), 0); code == 0 {
			t.Errorf("coverage below %d%% must fail the gate", wantCoverage)
		}
		for _, sev := range in.List("rejected_severities") {
			name := sev.(string)
			body := fmt.Sprintf(
				`{"diagnostics": [{"kind": "demo", "severity": %q, "message": "m", "spec_id": "s"}],`+
					` "summary": {"errors": %d, "warnings": %d, "info": 0}}`,
				name, boolToInt(name == "error"), boolToInt(name == "warning"))
			if code, _ := runGateWith(t, dir, "annotations", body, "", 0); code == 0 {
				t.Errorf("a %s diagnostic must fail the gate", name)
			}
		}
		for _, sev := range in.List("nonblocking_severities") {
			name := sev.(string)
			body := fmt.Sprintf(
				`{"diagnostics": [{"kind": "demo", "severity": %q, "message": "m", "spec_id": "s"}],`+
					` "summary": {"errors": 0, "warnings": 0, "info": 1}}`, name)
			if code, out := runGateWith(t, dir, "annotations", body, "", 0); code != 0 {
				t.Errorf("a %s diagnostic must NOT fail the gate; exit %d\n%s", name, code, out)
			}
		}
		if !exp.Bool("warnings_are_rejected_not_only_errors") {
			t.Error("AC-11 must require warnings to be rejected")
		}

		// The gate must PRINT what it rejected. Searching the source for the
		// word "message" proved nothing: the string survives in unrelated
		// text while the printing is deleted. Feed a distinctive message and
		// require it verbatim in the output.
		if exp.Bool("diagnostics_are_printed_not_just_counted") {
			const marker = "ZZ-distinctive-diagnostic-text-ZZ"
			body := fmt.Sprintf(
				`{"diagnostics": [{"kind": "demo", "severity": "warning", "message": %q,`+
					` "spec_id": "s"}], "summary": {"errors": 0, "warnings": 1, "info": 0}}`,
				marker)
			code, out := runGateWith(t, dir, "annotations", body, "", 0)
			if code == 0 {
				t.Error("a warning must fail the gate")
			}
			if !strings.Contains(out, marker) {
				t.Errorf("the gate reported a rejection without printing the diagnostic;\nwant %q in:\n%s",
					marker, out)
			}
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// codeLines returns the lines of a file with whole-line and trailing `#`
// comments removed. Every caller of the doc-style gate also EXPLAINS it in a
// comment, so a whole-file substring search stays true after the recipe, the
// run: step and the hook entry have all been deleted.
func codeLines(body string) []string {
	out := make([]string, 0, 64)
	for _, ln := range strings.Split(body, "\n") {
		code := ln
		if i := strings.Index(code, "#"); i >= 0 {
			code = code[:i]
		}
		if strings.TrimSpace(code) == "" {
			continue
		}
		out = append(out, code)
	}
	return out
}

// @ac AC-12
// AC-12: one shared documentation-style gate, reached by all three callers,
// checking every tracked supported file rather than the files --changed
// selects. The structural half is bound here; the behavioral half runs the
// stdlib-only suite in scripts/, which exercises the real checker against a
// throwaway repository. Delegating rather than restating keeps one source of
// truth for what the gate does.
func TestCIGates_DocStyleGateIsSharedAndCoversTheTree(t *testing.T) {
	t.Run("release-ci-gates/AC-12", func(t *testing.T) {
		dir := appDir(t)
		all := specfixture.Load(t, filepath.Join(dir, "specs/release/ci-gates.spec.yaml"), "release-ci-gates")
		ac := specfixture.Get(t, all, "AC-12")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		checker := in.Str("checker")
		gate := in.Str("shared_gate")
		pinFile := in.Str("pin_file")
		wantVersion := in.Str("pinned_version")
		target := in.Str("make_target")
		mode := in.Str("default_mode")
		dashS := in.Str("interpreter_flag")
		hookID := in.Str("precommit_hook_id")
		forbidden := in.Str("forbidden_in_callers")
		excluded := in.Str("excluded_from_gate")
		exemptPath := in.Str("reading_exempt_path")
		exemptCap := in.Str("reading_exempt_cap")

		callers := in.MapList("callers")
		if len(callers) == 0 {
			t.Fatal("AC-12 must name the callers")
		}
		requireShared := exp.Bool("every_caller_reaches_the_same_make_target")
		requireFullTree := exp.Bool("default_mode_is_the_full_tracked_tree")
		requireDashS := exp.Bool("gate_runs_with_site_packages_disabled")

		for _, c := range callers {
			path := c.Str("path")
			invocation := c.Str("invocation")
			kind := c.Str("kind")
			c.AllConsumed()
			body := readAppFile(t, path)

			found := false
			for _, code := range codeLines(body) {
				if !strings.Contains(code, invocation) {
					continue
				}
				switch kind {
				case "recipe":
					// A Makefile recipe line is tab-indented. A comment line
					// mentioning the same command is not.
					if strings.HasPrefix(code, "\t") {
						found = true
					}
				case "run_step":
					if strings.Contains(code, "run:") {
						found = true
					}
				case "hook":
					if strings.Contains(code, "entry:") {
						found = true
					}
				default:
					t.Fatalf("unknown caller kind %q in the AC-12 fixture", kind)
				}
			}
			if requireShared && !found {
				t.Errorf("%s has no %s invoking %q", path, kind, invocation)
			}

			// The vacuous mode must appear in no caller's code. It may still
			// be described in a comment, which is why this reads code only.
			for _, code := range codeLines(body) {
				if strings.Contains(code, forbidden) {
					t.Errorf("%s still uses %s: %q", path, forbidden, strings.TrimSpace(code))
				}
			}
			// Wherever a caller invokes the checker directly it must disable
			// site packages, so the stdlib-only claim is enforced.
			if requireDashS {
				for _, code := range codeLines(body) {
					if !strings.Contains(code, checker) {
						continue
					}
					if !strings.Contains(code, "python3 "+dashS+" ") {
						t.Errorf("%s invokes %s without %s: %q",
							path, checker, dashS, strings.TrimSpace(code))
					}
				}
			}
		}

		// The make target must reach the full tree. The mode now lives in the
		// gate rather than the recipe, so the recipe is checked for reaching
		// the gate and the gate is checked for the mode. Asserting it on the
		// recipe alone would pass a gate that scans nothing.
		gateSrc := readAppFile(t, gate)
		if requireFullTree {
			mk := readAppFile(t, "Makefile")
			recipe := []string{}
			lines := strings.Split(mk, "\n")
			for i, ln := range lines {
				if !strings.HasPrefix(ln, target+":") {
					continue
				}
				for _, follow := range lines[i+1:] {
					if strings.HasPrefix(follow, "\t") {
						recipe = append(recipe, follow)
					} else if strings.TrimSpace(follow) != "" {
						break
					}
				}
				break
			}
			if len(recipe) == 0 {
				t.Fatalf("no %s recipe in the Makefile", target)
			}
			joined := strings.Join(codeLines(strings.Join(recipe, "\n")), "\n")
			if !strings.Contains(joined, gate) {
				t.Errorf("`make %s` does not run %s; recipe is %q", target, gate, joined)
			}
			if strings.Contains(joined, checker) {
				t.Errorf("`make %s` calls the checker directly, skipping the version gate", target)
			}
			if !strings.Contains(gateSrc, mode) {
				t.Errorf("%s does not scan with %s", gate, mode)
			}
		}

		// ---- The version pin. One tracked file, compared before scanning.
		if exp.Bool("pin_is_read_from_one_file") {
			if got := strings.TrimSpace(readAppFile(t, pinFile)); got != wantVersion {
				t.Errorf("%s pins %q, spec requires %q", pinFile, got, wantVersion)
			}
			if !strings.Contains(gateSrc, pinFile) {
				t.Errorf("%s does not read the pin from %s", gate, pinFile)
			}
		}
		if exp.Bool("checker_version_is_compared_before_scanning") {
			// The SPECIFIC guard. A looser match stayed true with the
			// comparison deleted, because the gate names both versions in
			// its failure message and in its prose.
			if !strings.Contains(gateSrc, "if got != want:") {
				t.Error("the gate must compare the reported version against the pin")
			}
			vi := strings.Index(gateSrc, "def check_version(")
			si := strings.Index(gateSrc, "def run_scan(")
			if vi < 0 || si < 0 || vi > si {
				t.Error("the gate must define its version check before its scan")
			}
		}
		if exp.Bool("no_caller_repeats_the_version") {
			// A DECLARATION, not a mention: the pinned value is a bare digit,
			// so a substring search would match half the workflow. Comments
			// are stripped because every caller explains the pin in prose.
			decl := regexp.MustCompile(`(?i)version["'\s:=-]+["']?` + regexp.QuoteMeta(wantVersion) + `\b`)
			for _, c := range []string{"Makefile", ".github/workflows/go-ci.yml", ".pre-commit-config.yaml"} {
				for _, code := range codeLines(readAppFile(t, c)) {
					if decl.MatchString(code) {
						t.Errorf("%s declares its own checker version: %q", c, strings.TrimSpace(code))
					}
				}
			}
		}

		// ---- The reading-level exemption is a hole in the gate, so its shape
		// is part of the contract: one path, one rule.
		if exp.Bool("exemption_is_reading_level_only") {
			src := readAppFile(t, checker)
			if !strings.Contains(src, exemptPath) {
				t.Errorf("%s does not cap %s", checker, exemptPath)
			}
			if !strings.Contains(src, exemptCap) {
				t.Errorf("%s does not record the cap %s", checker, exemptCap)
			}
			// READING_EXEMPT must be consulted ONLY by the reading-level
			// check. A second reader would widen the cap to other rules.
			uses := strings.Count(src, "READING_EXEMPT.get(")
			if uses == 0 {
				t.Error("READING_EXEMPT is declared and never read")
			}
			for _, fn := range []string{"line_findings", "def check_emoji"} {
				if i := strings.Index(src, fn); i >= 0 {
					seg := src[i:]
					if j := strings.Index(seg, "\ndef "); j > 0 {
						seg = seg[:j]
					}
					if strings.Contains(seg, "READING_EXEMPT") {
						t.Errorf("%s consults READING_EXEMPT; the cap must cover the reading level only", fn)
					}
				}
			}
		}

		// ci-local must reach the gate, or the documented local mirror of CI
		// is missing the one gate this AC exists to enforce.
		mk := readAppFile(t, "Makefile")
		ciLocal := ""
		for _, code := range codeLines(mk) {
			if strings.HasPrefix(code, "ci-local:") {
				ciLocal = code
				break
			}
		}
		if ciLocal == "" {
			t.Fatal("no ci-local target in the Makefile")
		}
		if !strings.Contains(ciLocal, target) {
			t.Errorf("ci-local does not depend on %s: %q", target, ciLocal)
		}

		// The pre-commit hook must ignore any file list it is handed. Keying
		// this gate on a staged-file list reintroduces the blind spot that
		// --changed already has.
		if exp.Bool("precommit_hook_ignores_passed_filenames") {
			pc := readAppFile(t, ".pre-commit-config.yaml")
			idx := strings.Index(pc, "- id: "+hookID)
			if idx < 0 {
				t.Fatalf(".pre-commit-config.yaml has no %s hook", hookID)
			}
			block := pc[idx:]
			if end := strings.Index(block, "\n  - repo:"); end > 0 {
				block = block[:end]
			}
			if !strings.Contains(block, "pass_filenames: false") {
				t.Error("the doc-style hook must set pass_filenames: false")
			}
			if !strings.Contains(block, "always_run: true") {
				t.Error("the doc-style hook must set always_run: true")
			}
		}

		// The stated scope boundary must be true, not merely claimed: the
		// excluded tree is excluded because git ignores it.
		cmd := exec.Command("git", "check-ignore", "-q", excluded)
		cmd.Dir = dir
		if err := cmd.Run(); err != nil {
			t.Errorf("AC-12 claims %s is outside the gate, but git does not ignore it", excluded)
		}

		// ---- Behavioral: delegate to the stdlib-only suite, which runs the
		// real checker against a throwaway repository. A structural test
		// cannot show that an unchanged tracked violation is caught.
		behavioral := []struct {
			key string
		}{
			{"unchanged_tracked_violation_is_caught"},
			{"staged_violation_is_caught"},
			{"source_comment_violation_is_caught"},
			{"clean_tree_passes"},
		}
		want := false
		for _, b := range behavioral {
			if exp.Bool(b.key) {
				want = true
			}
		}
		if want {
			suite := exec.Command("python3", dashS, "scripts/test_doc_style_gate.py")
			suite.Dir = dir
			out, err := suite.CombinedOutput()
			if err != nil {
				t.Errorf("the doc-style gate suite failed: %v\n%s", err, out)
			}
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// @ac AC-13
// AC-13: the shipped score semantics and the report-verification trust
// boundary are published, tracked and reachable, and the published procedure
// is EXECUTED against a production-generated artifact rather than read. Each
// input is mutated independently and must fail for its own reason.
func TestCIGates_ScoreAndVerificationDocsAreShipped(t *testing.T) {
	t.Run("release-ci-gates/AC-13", func(t *testing.T) {
		dir := appDir(t)
		all := specfixture.Load(t, filepath.Join(dir, "specs/release/ci-gates.spec.yaml"), "release-ci-gates")
		ac := specfixture.Get(t, all, "AC-13")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		docs := map[string]string{
			"verification_guide": in.Str("verification_guide"),
			"scoring_guide":      in.Str("scoring_guide"),
			"api_guide":          in.Str("api_guide"),
		}
		index := in.Str("index")
		script := in.Str("example_script")
		fixtureDir := in.Str("fixture_dir")
		keyEndpoint := in.Str("signing_key_endpoint")
		obsolete := in.Str("obsolete_endpoint")
		domain := in.Str("signing_domain")

		// ---- Tracked and reachable. A guide nobody can navigate to is a file.
		if exp.Bool("guide_is_tracked_and_reachable_from_the_index") {
			for _, p := range []string{docs["verification_guide"], script, index} {
				cmd := exec.Command("git", "ls-files", "--error-unmatch", p)
				cmd.Dir = dir
				if err := cmd.Run(); err != nil {
					t.Errorf("%s is not tracked", p)
				}
			}
			idx := readAppFile(t, index)
			rel := strings.TrimPrefix(docs["verification_guide"], "docs/")
			if !strings.Contains(idx, rel) {
				t.Errorf("%s does not link %s", index, rel)
			}
		}

		// ---- The required statements, matched in the published files.
		for _, r := range in.MapList("required_statements") {
			docKey := r.Str("doc")
			want := r.Str("contains")
			r.AllConsumed()
			path, ok := docs[docKey]
			if !ok {
				t.Fatalf("AC-13 names an unknown doc key %q", docKey)
			}
			if !strings.Contains(readAppFile(t, path), want) {
				t.Errorf("%s does not state %q", path, want)
			}
		}

		// The three coverage statuses, exactly, in the scoring guide.
		scoring := readAppFile(t, docs["scoring_guide"])
		for _, st := range in.List("coverage_statuses") {
			if !strings.Contains(scoring, st.(string)) {
				t.Errorf("%s does not name coverage status %q", docs["scoring_guide"], st)
			}
		}

		// The verification guide must name the live endpoint and the signing
		// domain, and must not name the obsolete one anywhere.
		verification := readAppFile(t, docs["verification_guide"])
		if !strings.Contains(verification, keyEndpoint) {
			t.Errorf("%s does not name %s", docs["verification_guide"], keyEndpoint)
		}
		if !strings.Contains(verification, domain) {
			t.Errorf("%s does not name the signing domain %q", docs["verification_guide"], domain)
		}

		// ---- Forbidden claims, across every tracked guide.
		if exp.Bool("forbidden_claims_absent") {
			// The obsolete endpoint must be one of the scanned claims, not a
			// separate check: a plain containment test fires on the sentence
			// warning readers away from it.
			var claimed bool
			for _, c := range in.MapList("forbidden_claims") {
				if c.Str("pattern") == obsolete {
					claimed = true
				}
			}
			if !claimed {
				t.Errorf("AC-13 does not scan for the obsolete endpoint %s", obsolete)
			}
			var guides []string
			out, err := exec.Command("git", "-C", dir, "ls-files", "docs/*.md", "docs/guides/*.md", "docs/guides/runbooks/*.md").Output()
			if err != nil {
				t.Fatalf("git ls-files: %v", err)
			}
			guides = strings.Fields(string(out))
			if len(guides) == 0 {
				t.Fatal("no tracked guides found; the scan would pass vacuously")
			}
			// Allowlist, keyed by exact path and exact line text. A line that
			// reads as a forbidden claim fails unless it appears here. There is
			// deliberately no negation heuristic: the previous one excused any
			// line carrying "not", which a single sentence can satisfy while
			// still making the claim in its second half.
			type mention struct{ path, text string }
			allowed := map[mention]bool{}
			var allowList []mention
			for _, m := range in.MapList("allowed_mentions") {
				docKey := m.Str("doc")
				text := m.Str("text")
				m.AllConsumed()
				path, ok := docs[docKey]
				if !ok {
					t.Fatalf("AC-13 allowlists an unknown doc key %q", docKey)
				}
				mn := mention{path, text}
				allowed[mn] = true
				allowList = append(allowList, mn)
			}

			var patterns []*regexp.Regexp
			for _, c := range in.MapList("forbidden_claims") {
				id := c.Str("id")
				re, err := regexp.Compile(c.Str("pattern"))
				c.AllConsumed()
				if err != nil {
					t.Fatalf("AC-13 claim %s has an invalid pattern: %v", id, err)
				}
				patterns = append(patterns, re)
				for _, g := range guides {
					for n, ln := range strings.Split(readAppFile(t, g), "\n") {
						if !re.MatchString(ln) {
							continue
						}
						if allowed[mention{g, strings.TrimRight(ln, "\r")}] {
							continue
						}
						t.Errorf("forbidden claim %s at %s:%d: %q", id, g, n+1, strings.TrimSpace(ln))
					}
				}
			}

			// Every allowlisted mention must still EXIST and must still read as
			// a forbidden claim. Without both, an exemption outlives the
			// sentence it covered and quietly widens the hole.
			if exp.Bool("allowlisted_mentions_are_live") {
				for _, mn := range allowList {
					body := readAppFile(t, mn.path)
					found := false
					for _, ln := range strings.Split(body, "\n") {
						if strings.TrimRight(ln, "\r") == mn.text {
							found = true
						}
					}
					if !found {
						t.Errorf("stale allowlist entry: %s no longer contains %q", mn.path, mn.text)
						continue
					}
					matches := false
					for _, re := range patterns {
						if re.MatchString(mn.text) {
							matches = true
						}
					}
					if !matches {
						t.Errorf("needless allowlist entry: %q in %s matches no forbidden pattern",
							mn.text, mn.path)
					}
				}
			}
		}

		// ---- Execute the published procedure against the production artifact.
		fx := filepath.Join(dir, fixtureDir)
		run := func(report, meta, key string) int {
			cmd := exec.Command(filepath.Join(dir, script), report, meta, key)
			cmd.Dir = fx
			if err := cmd.Run(); err != nil {
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					return ee.ExitCode()
				}
				t.Fatalf("running %s: %v", script, err)
			}
			return 0
		}
		runIn := func(wd string, args ...string) int {
			cmd := exec.Command(filepath.Join(dir, script), args...)
			cmd.Dir = wd
			if err := cmd.Run(); err != nil {
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					return ee.ExitCode()
				}
				t.Fatalf("running %s: %v", script, err)
			}
			return 0
		}
		report := filepath.Join(fx, "report.json")
		meta := filepath.Join(fx, "report.meta.json")
		key := filepath.Join(fx, "signing-key.json")

		if exp.Bool("example_verifies_a_production_generated_artifact") {
			if code := run(report, meta, key); code != 0 {
				t.Fatalf("the published procedure failed on the shipped artifact: exit %d", code)
			}
		}

		tmp := t.TempDir()
		mutateJSON := func(name, src string, edit func(map[string]any)) string {
			raw, err := os.ReadFile(src)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			edit(m)
			out, _ := json.Marshal(m)
			p := filepath.Join(tmp, name)
			if err := os.WriteFile(p, out, 0o644); err != nil {
				t.Fatal(err)
			}
			return p
		}

		if exp.Bool("content_mutation_fails") {
			raw, _ := os.ReadFile(report)
			bad := filepath.Join(tmp, "content.json")
			if err := os.WriteFile(bad, append(raw, ' '), 0o644); err != nil {
				t.Fatal(err)
			}
			if code := run(bad, meta, key); code != 2 {
				t.Errorf("mutated content: exit %d, want 2 (content hash mismatch)", code)
			}
		}
		if exp.Bool("declared_hash_mutation_fails") {
			bad := mutateJSON("hash.meta.json", meta, func(m map[string]any) {
				s := m["content_sha256"].(string)
				m["content_sha256"] = "0" + s[1:]
			})
			if code := run(report, bad, key); code != 2 {
				t.Errorf("mutated declared hash: exit %d, want 2", code)
			}
		}
		if exp.Bool("signature_mutation_fails") {
			bad := mutateJSON("sig.meta.json", meta, func(m map[string]any) {
				raw, _ := base64.StdEncoding.DecodeString(m["signature"].(string))
				raw[0] ^= 0x01
				m["signature"] = base64.StdEncoding.EncodeToString(raw)
			})
			if code := run(report, bad, key); code != 3 {
				t.Errorf("mutated signature: exit %d, want 3", code)
			}
		}
		if exp.Bool("untrusted_key_fails") {
			// A different key, with its identifiers made CONSISTENT so the
			// identity check passes and the run reaches the signature. Leaving
			// the original key_id in place would fail earlier, at 7, and prove
			// something else.
			other := make([]byte, 32)
			other[0] = 0x42
			otherSum := sha256.Sum256(other)
			otherID := "ed25519-" + hex.EncodeToString(otherSum[:])[:16]
			badKey := mutateJSON("key.json", key, func(m map[string]any) {
				m["public_key"] = base64.StdEncoding.EncodeToString(other)
				m["key_id"] = otherID
			})
			badMeta := mutateJSON("othermeta.json", meta, func(m map[string]any) {
				m["signing_key_id"] = otherID
			})
			if code := run(report, badMeta, badKey); code != 3 {
				t.Errorf("a different key with consistent identifiers: exit %d, want 3", code)
			}
		}
		if exp.Bool("unsigned_artifact_is_reported_distinctly") {
			// BOTH fields cleared. Clearing only the signature leaves a
			// signing_key_id behind, which is malformed metadata rather than an
			// unsigned artifact, and is checked separately below.
			bad := mutateJSON("unsigned.meta.json", meta, func(m map[string]any) {
				m["signature"] = nil
				m["signing_key_id"] = nil
			})
			if code := run(report, bad, key); code != 4 {
				t.Errorf("unsigned artifact: exit %d, want 4 (distinct from an invalid signature)", code)
			}
		}

		// ---- The payload shape. These two are the mistakes the guide exists to
		// prevent, so they are driven rather than described: verifying over the
		// bare hash, or over the canonical JSON, must NOT succeed.
		if exp.Bool("payload_prefix_mutation_fails") {
			var metaDoc struct {
				ContentSHA256 string `json:"content_sha256"`
				Signature     string `json:"signature"`
			}
			var keyDoc struct {
				PublicKey string `json:"public_key"`
			}
			raw, _ := os.ReadFile(meta)
			if err := json.Unmarshal(raw, &metaDoc); err != nil {
				t.Fatal(err)
			}
			raw, _ = os.ReadFile(key)
			if err := json.Unmarshal(raw, &keyDoc); err != nil {
				t.Fatal(err)
			}
			pub, _ := base64.StdEncoding.DecodeString(keyDoc.PublicKey)
			sig, _ := base64.StdEncoding.DecodeString(metaDoc.Signature)
			body, _ := os.ReadFile(report)

			correct := append([]byte(domain+"\n"), []byte(metaDoc.ContentSHA256)...)
			if !ed25519.Verify(pub, correct, sig) {
				t.Fatal("the contract's domain-separated payload does not verify; the fixture or the domain is wrong")
			}
			for name, payload := range map[string][]byte{
				"bare hash with no domain tag": []byte(metaDoc.ContentSHA256),
				"the canonical JSON itself":    body,
				"wrong domain version":         append([]byte("openwatch/report-snapshot/v2\n"), []byte(metaDoc.ContentSHA256)...),
			} {
				if ed25519.Verify(pub, payload, sig) {
					t.Errorf("signature verified over %s; the signed payload is not what the contract says", name)
				}
			}
		}

		// ---- The published key document. This file is the one excluded from
		// secret scanning, so its shape is pinned here field by field: exactly
		// the declared keys, the right types, a 32-byte key, and a key_id the
		// test DERIVES rather than trusts.
		if exp.Bool("signing_key_document_shape_is_enforced") {
			wantFields := map[string]bool{}
			for _, f := range in.List("signing_key_fields") {
				wantFields[f.(string)] = true
			}
			wantAlg := in.Str("signing_key_algorithm")
			wantLen := in.Int("signing_key_bytes")
			prefix := in.Str("key_id_prefix")
			idChars := in.Int("key_id_hex_chars")
			for _, d := range []string{fx, filepath.Join(dir, in.Str("counterexample_dir"))} {
				name := filepath.Join(d, in.Str("signing_key_file"))
				raw, err := os.ReadFile(name)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				var doc map[string]any
				if err := json.Unmarshal(raw, &doc); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				for f := range wantFields {
					if _, ok := doc[f]; !ok {
						t.Errorf("%s is missing %q", name, f)
					}
				}
				for f := range doc {
					if !wantFields[f] {
						t.Errorf("%s carries an undeclared field %q", name, f)
					}
				}
				alg, _ := doc["algorithm"].(string)
				if alg != wantAlg {
					t.Errorf("%s algorithm = %q, want %q", name, alg, wantAlg)
				}
				if _, ok := doc["ephemeral"].(bool); !ok {
					t.Errorf("%s ephemeral is not a bool", name)
				}
				b64, _ := doc["public_key"].(string)
				pub, err := base64.StdEncoding.DecodeString(b64)
				if err != nil {
					t.Errorf("%s public_key is not base64: %v", name, err)
				} else if len(pub) != wantLen {
					t.Errorf("%s public_key decodes to %d bytes, want %d", name, len(pub), wantLen)
				} else {
					sum := sha256.Sum256(pub)
					want := prefix + hex.EncodeToString(sum[:])[:idChars]
					if got, _ := doc["key_id"].(string); got != want {
						t.Errorf("%s key_id = %q, derived %q", name, got, want)
					}
				}
			}
		}

		// ---- Key validation, each mutation independent of the others.
		keyMutation := func(name string, edit func(map[string]any)) string {
			return mutateJSON(name, key, edit)
		}
		if exp.Bool("algorithm_mismatch_fails") {
			bad := keyMutation("alg.json", func(m map[string]any) { m["algorithm"] = "ed448" })
			if code := run(report, meta, bad); code != 5 {
				t.Errorf("algorithm mismatch: exit %d, want 5", code)
			}
		}
		if exp.Bool("malformed_key_length_fails") {
			bad := keyMutation("len.json", func(m map[string]any) {
				m["public_key"] = base64.StdEncoding.EncodeToString([]byte("short"))
			})
			if code := run(report, meta, bad); code != 6 {
				t.Errorf("malformed key length: exit %d, want 6", code)
			}
		}
		if exp.Bool("key_id_mismatch_fails") {
			bad := keyMutation("kid.json", func(m map[string]any) {
				m["key_id"] = "ed25519-0000000000000000"
			})
			if code := run(report, meta, bad); code != 7 {
				t.Errorf("key id mismatch: exit %d, want 7", code)
			}
		}

		// ---- The anchor. Without it, success must SAY it is consistency only.
		anchorFile := filepath.Join(dir, in.Str("trusted_anchor_file"))
		anchorRaw, err := os.ReadFile(anchorFile)
		if err != nil {
			t.Fatalf("reading the trusted anchor: %v", err)
		}
		anchor := strings.TrimSpace(string(anchorRaw))

		if exp.Bool("consistency_only_says_so") {
			cmd := exec.Command(filepath.Join(dir, script), report, meta, key)
			cmd.Dir = fx
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("consistency run failed: %v\n%s", err, out)
			}
			if !strings.Contains(string(out), "AUTHENTICITY NOT ESTABLISHED") {
				t.Errorf("a run with no anchor did not say authenticity was unestablished:\n%s", out)
			}
			// And with the anchor it must NOT still say that.
			cmd = exec.Command(filepath.Join(dir, script), report, meta, key, anchor)
			cmd.Dir = fx
			out, err = cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("anchored run failed: %v\n%s", err, out)
			}
			if strings.Contains(string(out), "AUTHENTICITY NOT ESTABLISHED") {
				t.Errorf("an anchored run still reported authenticity unestablished:\n%s", out)
			}
		}
		if code := runIn(fx, report, meta, key, "0000000000000000000000000000000000000000000000000000000000000000"); code != 8 {
			t.Errorf("a wrong anchor: exit %d, want 8", code)
		}

		// ---- The counterexample: a second internally consistent bundle under
		// a different key. Consistency-only must PASS on it, which is the
		// point, and the genuine anchor must reject it.
		if exp.Bool("counterexample_passes_consistency_and_fails_the_anchor") {
			ce := filepath.Join(dir, in.Str("counterexample_dir"))
			cr := filepath.Join(ce, "report.json")
			cm := filepath.Join(ce, "report.meta.json")
			ck := filepath.Join(ce, "signing-key.json")
			if code := runIn(ce, cr, cm, ck); code != 0 {
				t.Errorf("the replacement bundle is not internally consistent: exit %d; "+
					"the counterexample only makes its point if it passes", code)
			}
			if code := runIn(ce, cr, cm, ck, anchor); code != 8 {
				t.Errorf("the replacement bundle survived the genuine anchor: exit %d, want 8", code)
			}
			// And it really is a different key.
			var a, b struct {
				KeyID     string `json:"key_id"`
				PublicKey string `json:"public_key"`
			}
			raw, _ := os.ReadFile(key)
			_ = json.Unmarshal(raw, &a)
			raw, _ = os.ReadFile(ck)
			_ = json.Unmarshal(raw, &b)
			if a.PublicKey == b.PublicKey {
				t.Error("the counterexample reuses the genuine key; it proves nothing")
			}
		}

		// ---- Key identity is DERIVED, not merely cross-checked. The published
		// key_id and signing_key_id must both equal the identifier computed
		// from the key material. Two documents can agree on an invented value.
		if exp.Bool("signed_metadata_requires_both_identifiers") {
			bad := mutateJSON("nokid.json", key, func(m map[string]any) { m["key_id"] = nil })
			if code := run(report, meta, bad); code != 7 {
				t.Errorf("key response with no key_id: exit %d, want 7", code)
			}
		}
		if exp.Bool("identifiers_are_derived_not_merely_compared") {
			const fake = "ed25519-aaaaaaaaaaaaaaaa"
			badMeta := mutateJSON("fakemeta.json", meta, func(m map[string]any) { m["signing_key_id"] = fake })
			badKey := mutateJSON("fakekey.json", key, func(m map[string]any) { m["key_id"] = fake })
			if code := run(report, badMeta, badKey); code != 7 {
				t.Errorf("mutually consistent but fabricated identifiers: exit %d, want 7. "+
					"Comparing key_id with signing_key_id is not enough; derive it from the key", code)
			}
		}

		// ---- signature and signing_key_id are an all-or-nothing pair.
		unsignedDir := filepath.Join(dir, in.Str("unsigned_dir"))
		unsignedReport := filepath.Join(unsignedDir, "report.json")
		unsignedMeta := filepath.Join(unsignedDir, "report.meta.json")
		if exp.Bool("metadata_pair_is_all_or_nothing") {
			half := mutateJSON("sig-no-kid.json", meta, func(m map[string]any) { m["signing_key_id"] = nil })
			if code := run(report, half, key); code != 9 {
				t.Errorf("signature with no signing_key_id: exit %d, want 9", code)
			}
			other := mutateJSON("kid-no-sig.json", unsignedMeta, func(m map[string]any) {
				m["signing_key_id"] = "ed25519-65b60673d6ed884b"
			})
			if code := run(unsignedReport, other, key); code != 9 {
				t.Errorf("signing_key_id with no signature: exit %d, want 9", code)
			}
		}

		// ---- An unsigned artifact must verify with two files and NO key.
		if exp.Bool("unsigned_artifact_verifies_without_a_key_file") {
			var um map[string]any
			raw, err := os.ReadFile(unsignedMeta)
			if err != nil {
				t.Fatalf("reading the unsigned fixture: %v", err)
			}
			if err := json.Unmarshal(raw, &um); err != nil {
				t.Fatal(err)
			}
			if um["signature"] != nil || um["signing_key_id"] != nil {
				t.Fatalf("the unsigned fixture is not unsigned: %v", um)
			}
			// Two arguments only. Reaching 4 means it neither demanded a key
			// file (64) nor tried to open a missing one.
			if code := runIn(unsignedDir, unsignedReport, unsignedMeta); code != 4 {
				t.Errorf("unsigned artifact with no key file: exit %d, want 4", code)
			}
			// A SIGNED artifact still requires the key.
			if code := runIn(fx, report, meta); code != 64 {
				t.Errorf("signed artifact with no key file: exit %d, want 64", code)
			}
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}

// ignored reports whether git ignores a path, read from the EXIT STATUS.
// `git check-ignore -v` also prints a line when a NEGATED pattern matches, so
// treating any output as a match reports the opposite of the truth for exactly
// the rules that re-include a file.
func ignored(t *testing.T, dir, path string) bool {
	t.Helper()
	cmd := exec.Command("git", "check-ignore", "-q", path)
	cmd.Dir = dir
	err := cmd.Run()
	if err == nil {
		return true
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 1 {
		return false
	}
	t.Fatalf("git check-ignore %s: %v", path, err)
	return false
}

// @ac AC-14
// AC-14: the tracked documentation boundary, proved against candidate paths
// rather than against the files that happen to exist, plus two planted files
// that prove the rules describe real git behavior.
func TestCIGates_TrackedDocumentationBoundary(t *testing.T) {
	t.Run("release-ci-gates/AC-14", func(t *testing.T) {
		dir := appDir(t)
		all := specfixture.Load(t, filepath.Join(dir, "specs/release/ci-gates.spec.yaml"), "release-ci-gates")
		ac := specfixture.Get(t, all, "AC-14")
		in := specfixture.InputsOf(t, ac)
		exp := specfixture.ExpectedOf(t, ac)

		gitignore := readAppFile(t, in.Str("gitignore"))

		// ---- Documentation a future slice might add must be visible.
		if exp.Bool("tracked_documentation_is_visible") {
			for _, p := range in.List("visible_paths") {
				path := p.(string)
				if _, err := os.Stat(filepath.Join(dir, path)); err == nil {
					t.Fatalf("%s exists; AC-14 must probe paths that do NOT exist, or a "+
						"tracked file could mask the ignore rules", path)
				}
				if ignored(t, dir, path) {
					var why string
					c := exec.Command("git", "check-ignore", "-v", path)
					c.Dir = dir
					if out, _ := c.Output(); len(out) > 0 {
						why = strings.TrimSpace(string(out))
					}
					t.Errorf("documentation path is hidden: %s\n  by %s", path, why)
				}
			}
		}

		// ---- The same names at the repository root stay ignored. Anchoring
		// must not have turned the rules off.
		if exp.Bool("root_only_artifacts_stay_ignored") {
			for _, p := range in.List("root_only_ignored") {
				path := p.(string)
				if !ignored(t, dir, path) {
					t.Errorf("root artifact is no longer ignored: %s", path)
				}
			}
		}

		// ---- Secrets stay ignored at every depth under tracked documentation.
		if exp.Bool("secrets_stay_ignored_at_every_depth") {
			for _, d := range in.List("secret_depths") {
				for _, n := range in.List("secret_names") {
					path := d.(string) + "/" + n.(string)
					if !ignored(t, dir, path) {
						t.Errorf("SECRET NOT IGNORED: %s", path)
					}
				}
			}
		}

		// ---- The old shapes must not come back.
		if exp.Bool("unanchored_patterns_do_not_return") {
			for _, p := range in.List("forbidden_unanchored") {
				pat := p.(string)
				for i, ln := range strings.Split(gitignore, "\n") {
					if strings.TrimSpace(ln) == pat {
						t.Errorf(".gitignore:%d has %q unanchored again; it matches by basename "+
							"at every depth and hides documentation", i+1, pat)
					}
				}
			}
		}
		if exp.Bool("directory_reincludes_under_docs_are_absent") {
			for _, p := range in.List("forbidden_negations") {
				neg := p.(string)
				for i, ln := range strings.Split(gitignore, "\n") {
					if strings.TrimSpace(ln) == neg {
						t.Errorf(".gitignore:%d re-includes %q under docs; that un-ignores the "+
							"security patterns beneath it. Anchor the colliding rule instead",
							i+1, neg)
					}
				}
			}
		}

		// ---- Plant, observe, remove. The probes above read rules; these two
		// read git's actual behavior on files that are really there.
		plantedGuide := in.Str("planted_guide")
		plantedSecret := in.Str("planted_secret")
		plantDir := filepath.Dir(filepath.Join(dir, plantedGuide))
		if err := os.MkdirAll(plantDir, 0o755); err != nil {
			t.Fatal(err)
		}
		// Guaranteed cleanup, including on a failing assertion or a panic.
		t.Cleanup(func() {
			if err := os.RemoveAll(plantDir); err != nil {
				t.Errorf("cleanup: %v", err)
			}
		})
		for _, f := range []string{plantedGuide, plantedSecret} {
			if err := os.WriteFile(filepath.Join(dir, f), []byte("probe\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command("git", "status", "--short", "--untracked-files=all")
		cmd.Dir = dir
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git status: %v", err)
		}
		status := string(out)
		if exp.Bool("planted_guide_is_seen_by_git_status") && !strings.Contains(status, plantedGuide) {
			t.Errorf("git status does not see the planted guide %s;\nstatus was:\n%s",
				plantedGuide, status)
		}
		if exp.Bool("planted_secret_is_ignored") {
			if strings.Contains(status, plantedSecret) {
				t.Errorf("git status OFFERS the planted private key %s", plantedSecret)
			}
			if !ignored(t, dir, plantedSecret) {
				t.Errorf("the planted private key %s is not ignored", plantedSecret)
			}
		}

		// ---- Tracked contributor and workflow documentation cites only paths a
		// reader can open, or says the path is unavailable.
		type mention struct{ path, text string }
		allowed := map[mention]bool{}
		var allowList []mention
		for _, m := range in.MapList("allowed_references") {
			mn := mention{m.Str("doc"), m.Str("text")}
			m.AllConsumed()
			allowed[mn] = true
			allowList = append(allowList, mn)
		}
		var prefixes, markers []string
		for _, p := range in.List("ignored_path_prefixes") {
			prefixes = append(prefixes, p.(string))
		}
		for _, m := range in.List("honesty_markers") {
			markers = append(markers, strings.ToLower(m.(string)))
		}
		lsFiles := exec.Command("git", "ls-files",
			"*.md", "docs/*.md", "docs/guides/*.md", "docs/guides/runbooks/*.md",
			"docs/runbooks/*.md", ".github/*.md", ".github/workflows/*.md", ".claude/skills/*.md")
		lsFiles.Dir = dir
		lsOut, err := lsFiles.Output()
		if err != nil {
			t.Fatalf("git ls-files: %v", err)
		}
		docs := strings.Fields(string(lsOut))
		if len(docs) == 0 {
			t.Fatal("no tracked documentation found; the scan would pass vacuously")
		}
		if exp.Bool("tracked_docs_cite_only_reachable_paths") {
			for _, d := range docs {
				for i, ln := range strings.Split(readAppFile(t, d), "\n") {
					hit := false
					for _, pre := range prefixes {
						if strings.Contains(ln, pre) {
							hit = true
						}
					}
					if !hit {
						continue
					}
					low := strings.ToLower(ln)
					marked := false
					for _, mk := range markers {
						if strings.Contains(low, mk) {
							marked = true
						}
					}
					if marked || allowed[mention{d, strings.TrimRight(ln, "\r")}] {
						continue
					}
					t.Errorf("%s:%d cites a path a reader cannot open: %q",
						d, i+1, strings.TrimSpace(ln))
				}
			}
		}
		if exp.Bool("allowed_references_are_live") {
			for _, mn := range allowList {
				body := readAppFile(t, mn.path)
				found := false
				for _, ln := range strings.Split(body, "\n") {
					if strings.TrimRight(ln, "\r") == mn.text {
						found = true
					}
				}
				if !found {
					t.Errorf("stale allowlist entry: %s no longer contains %q", mn.path, mn.text)
					continue
				}
				names := false
				for _, pre := range prefixes {
					if strings.Contains(mn.text, pre) {
						names = true
					}
				}
				if !names {
					t.Errorf("needless allowlist entry: %q in %s names no ignored path",
						mn.text, mn.path)
				}
			}
		}

		in.AllConsumed()
		exp.AllConsumed()
	})
}
