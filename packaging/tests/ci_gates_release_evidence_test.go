// @spec release-ci-gates

package packaging_test

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// Full test evidence on the exact release commit (release-ci-gates C-19,
// CP bugs/OW-086 tracks B and C).

const evidenceJobName = "Full test evidence"

// @ac AC-33
// AC-33: a pushed release tag runs go-ci.yml, and path selection sends it to
// the full pipeline even when the change is documentation-only.
func TestCIGates_ReleaseTagRunsTheFullPipeline(t *testing.T) {
	t.Run("release-ci-gates/AC-33", func(t *testing.T) {
		haveTool(t, "git")
		haveTool(t, "bash")
		raw, err := os.ReadFile(filepath.Join(appDir(t), ".github/workflows/go-ci.yml"))
		if err != nil {
			t.Fatal(err)
		}
		var trig struct {
			On struct {
				Push struct {
					Branches []string `yaml:"branches"`
					Tags     []string `yaml:"tags"`
				} `yaml:"push"`
				PullRequest struct {
					Branches []string `yaml:"branches"`
				} `yaml:"pull_request"`
			} `yaml:"on"`
		}
		if err := yaml.Unmarshal(raw, &trig); err != nil {
			t.Fatal(err)
		}
		if !contains(trig.On.Push.Branches, "main") || !contains(trig.On.PullRequest.Branches, "main") {
			t.Errorf("go-ci.yml must still run on push to main and pull requests to main: push %v, pull_request %v",
				trig.On.Push.Branches, trig.On.PullRequest.Branches)
		}
		for _, tag := range []string{"v0.8.3", "v0.8.0-rc.6"} {
			matched := false
			for _, p := range trig.On.Push.Tags {
				if ok, _ := path.Match(p, tag); ok {
					matched = true
				}
			}
			if !matched {
				t.Errorf("no push tag pattern in %v matches %s; a release tag would run no Go CI", trig.On.Push.Tags, tag)
			}
		}

		var script string
		for _, s := range readGoCI(t).Jobs["changes"].Steps {
			if s.ID == "paths" {
				script = s.Run
			}
		}
		dir := t.TempDir()
		git := func(args ...string) string {
			t.Helper()
			cmd := exec.Command("git", args...)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
				"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("git %v: %v\n%s", args, err, out)
			}
			return strings.TrimSpace(string(out))
		}
		git("init", "-q")
		if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("a\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		git("add", "-A")
		git("commit", "-q", "-m", "base")
		base := git("rev-parse", "HEAD")
		if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("b\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		git("commit", "-q", "-am", "docs only")
		head := git("rev-parse", "HEAD")

		for _, c := range []struct {
			refType, want string
		}{{"tag", "true"}, {"branch", "false"}} {
			out := filepath.Join(t.TempDir(), "github_output")
			if err := os.WriteFile(out, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-e", "-c", script)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GITHUB_OUTPUT="+out, "EVENT=push", "REF_TYPE="+c.refType,
				"REF_NAME=v9.9.9", "PUSH_BEFORE="+base, "PUSH_AFTER="+head)
			log, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("ref type %s: the step failed: %v\n%s", c.refType, err, log)
			}
			got, _ := os.ReadFile(out)
			if f := strings.Fields(string(got)); len(f) != 1 || f[0] != "go="+c.want {
				t.Errorf("documentation-only push with ref type %s: GITHUB_OUTPUT = %q, want go=%s\n%s", c.refType, got, c.want, log)
			}
		}
	})
}

// evidenceJob returns the id and definition of the "Full test evidence" job.
func evidenceJob(t *testing.T, wf ciWorkflow) (string, ciJob) {
	t.Helper()
	var id string
	for jid, j := range wf.Jobs {
		if j.Name == evidenceJobName {
			if id != "" {
				t.Fatalf("jobs %q and %q are both named %q", id, jid, evidenceJobName)
			}
			id = jid
		}
	}
	if id == "" {
		t.Fatalf("go-ci.yml has no job named %q", evidenceJobName)
	}
	return id, wf.Jobs[id]
}

// @ac AC-34
// AC-34: the evidence job succeeds only when the whole full pipeline did.
func TestCIGates_FullTestEvidenceJobRequiresTheFullPipeline(t *testing.T) {
	t.Run("release-ci-gates/AC-34", func(t *testing.T) {
		haveTool(t, "bash")
		wf := readGoCI(t)
		_, job := evidenceJob(t, wf)

		gatesID := ""
		for id, j := range wf.Jobs {
			if j.Name == requiredCheck {
				gatesID = id
			}
		}
		for _, need := range []string{"changes", "checks", "server-tests", "docs-tests", gatesID} {
			if !contains(job.needs(), need) {
				t.Errorf("%q does not need %q (needs %v)", evidenceJobName, need, job.needs())
			}
		}
		if job.If != "always() && needs.changes.outputs.go == 'true'" {
			t.Errorf("%q runs under if %q; want always() so a failed dependency fails it, gated on the full path", evidenceJobName, job.If)
		}
		if job.Continue != nil {
			t.Errorf("%q sets continue-on-error", evidenceJobName)
		}
		var verdict *ciStep
		for i, s := range job.Steps {
			if s.Continue != nil {
				t.Errorf("step %q sets continue-on-error", s.Name)
			}
			if s.Env["GATES"] != "" {
				verdict = &job.Steps[i]
			}
		}
		if verdict == nil {
			t.Fatal("the evidence job has no step that reads the needed jobs' results")
		}
		wantEnv := map[string]string{
			"CHANGES": "${{ needs.changes.result }}",
			"GO":      "${{ needs.changes.outputs.go }}",
			"CHECKS":  "${{ needs.checks.result }}",
			"SERVER":  "${{ needs.server-tests.result }}",
			"DOCS":    "${{ needs.docs-tests.result }}",
			"GATES":   "${{ needs." + gatesID + ".result }}",
		}
		for k, v := range wantEnv {
			if verdict.Env[k] != v {
				t.Errorf("verdict env %s = %q, want %q", k, verdict.Env[k], v)
			}
		}

		good := map[string]string{"CHANGES": "success", "GO": "true", "CHECKS": "success",
			"SERVER": "success", "DOCS": "skipped", "GATES": "success"}
		run := func(env map[string]string) bool {
			cmd := exec.Command("bash", "-e", "-c", verdict.Run)
			cmd.Env = append(os.Environ(), "GITHUB_SHA=0123456789abcdef")
			for k, v := range env {
				cmd.Env = append(cmd.Env, k+"="+v)
			}
			return cmd.Run() == nil
		}
		if !run(good) {
			t.Fatal("the evidence step failed for a complete, successful full pipeline")
		}
		for k := range good {
			for _, bad := range []string{"failure", "cancelled", "skipped", "success", ""} {
				if bad == good[k] {
					continue
				}
				env := map[string]string{}
				for kk, vv := range good {
					env[kk] = vv
				}
				env[k] = bad
				if k == "GO" {
					env[k] = map[string]string{"failure": "false", "cancelled": "maybe", "skipped": "",
						"success": "TRUE", "": ""}[bad]
				}
				if run(env) {
					t.Errorf("the evidence step passed with %s=%q; only the complete full pipeline is evidence", k, env[k])
				}
			}
		}
	})
}

// @ac AC-35
// AC-35: the full-suite release gates read the evidence job, and the checker
// refuses anything but a success of it.
func TestCIGates_ReleaseGatesReadFullTestEvidence(t *testing.T) {
	t.Run("release-ci-gates/AC-35", func(t *testing.T) {
		_, job := evidenceJob(t, readGoCI(t))
		var manifest struct {
			Gate []struct {
				ID       string `toml:"id"`
				Evidence string `toml:"evidence"`
				Check    string `toml:"check"`
				Workflow string `toml:"workflow"`
				Job      string `toml:"job"`
			} `toml:"gate"`
		}
		if _, err := toml.DecodeFile(filepath.Join(appDir(t), "release", "gates.toml"), &manifest); err != nil {
			t.Fatalf("parse gates.toml: %v", err)
		}
		want := map[string]bool{"Q1": true, "S1": true, "S2": true, "S3": true, "S4": true, "S5": true, "S6": true, "S7": true}
		for _, g := range manifest.Gate {
			if g.Evidence == "github-check" && g.Check == requiredCheck {
				t.Errorf("gate %s reads %q, which also passes on the documentation path", g.ID, requiredCheck)
			}
			if !want[g.ID] {
				continue
			}
			delete(want, g.ID)
			if g.Evidence != "workflow-job" || g.Workflow != ".github/workflows/go-ci.yml" || g.Job != job.Name {
				t.Errorf("gate %s: evidence=%q workflow=%q job=%q; want workflow-job, .github/workflows/go-ci.yml, %q",
					g.ID, g.Evidence, g.Workflow, g.Job, job.Name)
			}
		}
		for id := range want {
			t.Errorf("gate %s is missing from gates.toml", id)
		}

		haveTool(t, "python3")
		// The suite takes no test filter, so it runs whole; the evidence cases
		// are counted by name so a deleted case is noticed.
		cmd := exec.Command("python3", "-S", filepath.Join("scripts", "test_release_status.py"))
		cmd.Dir = appDir(t)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("test_release_status.py: %v\n%s", err, out)
		}
		passed := 0
		for _, ln := range strings.Split(string(out), "\n") {
			if strings.Contains(ln, ".FullTestEvidenceIsRequired.") && strings.HasSuffix(strings.TrimSpace(ln), "... ok") {
				passed++
			}
		}
		if passed != 16 {
			t.Errorf("FullTestEvidenceIsRequired: %d cases passed, want 16\n%s", passed, out)
		}
	})
}

// @ac AC-36
// AC-36: the runbook asks for full test evidence on the candidate's commit.
func TestCIGates_RunbookRequiresFullTestEvidence(t *testing.T) {
	t.Run("release-ci-gates/AC-36", func(t *testing.T) {
		book := readAppFile(t, "docs/runbooks/RELEASING.md")
		for _, want := range []string{
			"`Full test evidence` succeeded on the candidate's own commit",
			`A green "Quality + security gates" check is not enough`,
			"Pushing the tag runs the\n  full pipeline on the tagged commit",
			"Within one run, only the latest attempt counts.",
			"makes it FAIL, even beside a success",
			"**Historical releases keep their recorded decision.**",
			"v0.8.3's GO was recorded by",
			"An older tag cannot gain the evidence either",
		} {
			if !strings.Contains(book, want) {
				t.Errorf("RELEASING.md is missing %q", want)
			}
		}
		if strings.Contains(book, "`go-ci` green on `main` at the RC commit") {
			t.Error("RELEASING.md still accepts a green go-ci on main as release evidence")
		}
	})
}
