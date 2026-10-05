// @spec release-ci-gates

package packaging_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The parts of a GitHub Actions workflow this criterion reads. The YAML is
// parsed, not grepped, so a key that moves to another job is seen as moved.
type ciWorkflow struct {
	Jobs map[string]ciJob `yaml:"jobs"`
}

type ciJob struct {
	Name     string            `yaml:"name"`
	Needs    yaml.Node         `yaml:"needs"`
	If       string            `yaml:"if"`
	Outputs  map[string]string `yaml:"outputs"`
	Services map[string]any    `yaml:"services"`
	Continue any               `yaml:"continue-on-error"`
	Steps    []ciStep          `yaml:"steps"`
}

type ciStep struct {
	ID       string            `yaml:"id"`
	Name     string            `yaml:"name"`
	If       string            `yaml:"if"`
	Run      string            `yaml:"run"`
	Env      map[string]string `yaml:"env"`
	Continue any               `yaml:"continue-on-error"`
}

func (j ciJob) needs() []string {
	switch j.Needs.Kind {
	case yaml.ScalarNode:
		return []string{j.Needs.Value}
	case yaml.SequenceNode:
		var out []string
		for _, n := range j.Needs.Content {
			out = append(out, n.Value)
		}
		return out
	}
	return nil
}

func (j ciJob) script() string {
	var b strings.Builder
	for _, s := range j.Steps {
		b.WriteString(s.Run)
		b.WriteString("\n")
	}
	return b.String()
}

const requiredCheck = "Quality + security gates"

// @ac AC-25
// AC-25: internal/server's race tests run in their own job, at the same time
// as every other package's, and the required check is an aggregate that
// cannot pass while either test job failed, was canceled, or was skipped on
// a Go change.
func TestCIGates_ServerTestsRunInParallelBehindAnAggregateCheck(t *testing.T) {
	t.Run("release-ci-gates/AC-25", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(appDir(t), ".github/workflows/go-ci.yml"))
		if err != nil {
			t.Fatalf("read go-ci.yml: %v", err)
		}
		var wf ciWorkflow
		if err := yaml.Unmarshal(raw, &wf); err != nil {
			t.Fatalf("parse go-ci.yml: %v", err)
		}

		// Exactly one job carries the required check's name.
		gatesID := ""
		for id, j := range wf.Jobs {
			if j.Name == requiredCheck {
				if gatesID != "" {
					t.Fatalf("jobs %q and %q are both named %q", gatesID, id, requiredCheck)
				}
				gatesID = id
			}
		}
		if gatesID == "" {
			t.Fatalf("no job is named %q; branch protection requires that check", requiredCheck)
		}
		gates := wf.Jobs[gatesID]

		// Path detection happens once, in a job whose output the others read.
		changes, ok := wf.Jobs["changes"]
		if !ok {
			t.Fatal("no `changes` job computes the Go-relevant path verdict")
		}
		if changes.Outputs["go"] != "${{ steps.paths.outputs.go }}" {
			t.Errorf("changes job output go = %q, want it bound to the paths step", changes.Outputs["go"])
		}
		hasPaths := false
		for _, s := range changes.Steps {
			if s.ID == "paths" {
				hasPaths = true
			}
		}
		if !hasPaths {
			t.Error("changes job has no step with id: paths")
		}

		// The two test jobs: both depend on the verdict, both have their own
		// database, and together they test every package exactly once.
		goGate := "needs.changes.outputs.go == 'true'"
		serverRun := regexp.MustCompile(`go test -race -json -timeout \d+s \./internal/server/`)
		var serverJob, othersJob string
		for id, j := range wf.Jobs {
			sc := j.script()
			if serverRun.MatchString(sc) {
				if serverJob != "" {
					t.Errorf("internal/server is tested in both %q and %q", serverJob, id)
				}
				serverJob = id
			}
			if strings.Contains(sc, "grep -v '^github.com/Hanalyx/openwatch/internal/server$'") {
				if othersJob != "" {
					t.Errorf("the every-other-package run appears in both %q and %q", othersJob, id)
				}
				othersJob = id
			}
		}
		if serverJob == "" || othersJob == "" {
			t.Fatalf("test jobs not found: internal/server in %q, every other package in %q", serverJob, othersJob)
		}
		if serverJob == othersJob {
			t.Fatalf("internal/server and every other package both run in job %q; they must run in parallel jobs", serverJob)
		}
		for _, id := range []string{serverJob, othersJob} {
			j := wf.Jobs[id]
			if j.If != goGate {
				t.Errorf("job %q runs under if %q, want %q", id, j.If, goGate)
			}
			if !contains(j.needs(), "changes") {
				t.Errorf("job %q does not need changes", id)
			}
			if _, ok := j.Services["postgres"]; !ok {
				t.Errorf("job %q has no postgres service of its own", id)
			}
			if j.Continue != nil {
				t.Errorf("job %q sets continue-on-error; a failure must reach the required check", id)
			}
			for _, s := range j.Steps {
				if s.Continue != nil {
					t.Errorf("job %q step %q sets continue-on-error; a failing step would leave the job green", id, s.Name)
				}
			}
			if contains(j.needs(), serverJob) || contains(j.needs(), othersJob) {
				t.Errorf("job %q needs the other test job, so the two cannot run in parallel", id)
			}
		}
		if strings.Contains(wf.Jobs[serverJob].script(), "go list ./...") {
			t.Errorf("job %q enumerates every package; it must test internal/server only", serverJob)
		}

		// The aggregate: needs all three, always runs, never continues on error.
		for _, id := range []string{"changes", serverJob, othersJob} {
			if !contains(gates.needs(), id) {
				t.Errorf("%q does not need %q", requiredCheck, id)
			}
		}
		if !strings.Contains(gates.If, "always()") {
			t.Errorf("%q runs under if %q; without always() a failed dependency skips it, and a skipped required check passes", requiredCheck, gates.If)
		}
		if gates.Continue != nil {
			t.Errorf("%q sets continue-on-error", requiredCheck)
		}
		for _, s := range gates.Steps {
			if s.Continue != nil {
				t.Errorf("%q step %q sets continue-on-error", requiredCheck, s.Name)
			}
		}

		// The verdict step: bound to every needed result, and executed here
		// across the outcomes that matter.
		var verdict *ciStep
		for i, s := range gates.Steps {
			if s.Env["CHECKS"] != "" || s.Env["SERVER"] != "" {
				verdict = &gates.Steps[i]
			}
		}
		if verdict == nil {
			t.Fatalf("%q has no step that reads the test jobs' results", requiredCheck)
		}
		if verdict.Continue != nil {
			t.Error("the verdict step sets continue-on-error")
		}
		if verdict.If != "always()" {
			t.Errorf("the verdict step runs under if %q, want always(); an earlier failed step would otherwise skip it", verdict.If)
		}
		wantEnv := map[string]string{
			"CHANGES": "${{ needs.changes.result }}",
			"GO":      "${{ needs.changes.outputs.go }}",
			"CHECKS":  "${{ needs." + othersJob + ".result }}",
			"SERVER":  "${{ needs." + serverJob + ".result }}",
		}
		for k, v := range wantEnv {
			if verdict.Env[k] != v {
				t.Errorf("verdict env %s = %q, want %q", k, verdict.Env[k], v)
			}
		}

		cases := []struct {
			changes, gov, checks, server string
			pass                         bool
		}{
			{"success", "true", "success", "success", true},
			{"success", "false", "skipped", "skipped", true},
			{"success", "true", "failure", "success", false},
			{"success", "true", "success", "failure", false},
			{"success", "true", "cancelled", "success", false},
			{"success", "true", "success", "cancelled", false},
			{"success", "true", "skipped", "success", false},
			{"success", "true", "success", "skipped", false},
			{"success", "false", "success", "skipped", false},
			{"success", "false", "skipped", "failure", false},
			{"success", "false", "success", "success", false},
			{"success", "false", "failure", "failure", false},
			{"failure", "", "skipped", "skipped", false},
			{"failure", "false", "skipped", "skipped", false},
			{"cancelled", "true", "success", "success", false},
			{"success", "", "skipped", "skipped", false},
			{"success", "maybe", "success", "success", false},
		}
		for _, c := range cases {
			cmd := exec.Command("bash", "-c", verdict.Run)
			cmd.Env = append(os.Environ(), "CHANGES="+c.changes, "GO="+c.gov, "CHECKS="+c.checks, "SERVER="+c.server)
			out, err := cmd.CombinedOutput()
			if passed := err == nil; passed != c.pass {
				t.Errorf("changes=%s go=%q checks=%s server=%s: passed=%v, want %v\n%s",
					c.changes, c.gov, c.checks, c.server, passed, c.pass, out)
			}
		}
	})
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
