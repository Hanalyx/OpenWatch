// @spec release-ci-gates
//
// Static checks on the CI gate plumbing: Makefile targets, .golangci.yml
// linter set, and GitHub Actions workflow shape. The tests inspect
// configuration files rather than re-running gates against the codebase
// — those gates already run on every PR.

package packaging_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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
// AC-09: workflow runs each gate as its own step (vet, lint, vuln,
// test-race, specter sync).
func TestCIGates_WorkflowRunsAllGates(t *testing.T) {
	t.Run("release-ci-gates/AC-09", func(t *testing.T) {
		wf := readAppFile(t, ".github/workflows/go-ci.yml")
		gates := []string{
			"make vet",
			"make lint",
			"make vuln",
			"make test-race",
			"specter sync",
		}
		for _, g := range gates {
			if !strings.Contains(wf, g) {
				t.Errorf("workflow missing step that runs %q", g)
			}
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
