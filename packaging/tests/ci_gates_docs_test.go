// @spec release-ci-gates

package packaging_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The documentation path of Go CI (release-ci-gates C-18, CP bugs/OW-086):
// a change outside the Go-relevant pattern runs packaging/tests, the tests
// that read documents, instead of skipping every test.

func readGoCI(t *testing.T) ciWorkflow {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(appDir(t), ".github/workflows/go-ci.yml"))
	if err != nil {
		t.Fatalf("read go-ci.yml: %v", err)
	}
	var wf ciWorkflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse go-ci.yml: %v", err)
	}
	return wf
}

func gatesJob(t *testing.T, wf ciWorkflow) ciJob {
	t.Helper()
	for _, j := range wf.Jobs {
		if j.Name == requiredCheck {
			return j
		}
	}
	t.Fatalf("no job is named %q", requiredCheck)
	return ciJob{}
}

const docsGate = "needs.changes.outputs.go == 'false'"
const fullGate = "needs.changes.outputs.go == 'true'"

// @ac AC-28
// AC-28: path selection fails closed, and sees deletions and both sides of
// a rename. The production step's script is executed against real
// repositories, not restated.
func TestCIGates_PathSelectionFailsClosed(t *testing.T) {
	t.Run("release-ci-gates/AC-28", func(t *testing.T) {
		haveTool(t, "git")
		haveTool(t, "bash")
		wf := readGoCI(t)
		var script string
		for _, s := range wf.Jobs["changes"].Steps {
			if s.ID == "paths" {
				script = s.Run
			}
		}
		if script == "" {
			t.Fatal("the changes job has no paths step")
		}
		if regexp.MustCompile(`\|\s*grep`).MatchString(script) {
			t.Error("the paths step pipes into grep; under -o pipefail a SIGPIPE in the writer turns a match into a failure")
		}

		git := func(dir string, args ...string) string {
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
		write := func(dir, name, body string) {
			t.Helper()
			p := filepath.Join(dir, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		// repo returns a repository with a base commit, and the commit after
		// change() ran and everything was committed.
		repo := func(change func(dir string)) (dir, base, head string) {
			t.Helper()
			dir = t.TempDir()
			git(dir, "init", "-q")
			for _, f := range []string{"internal/x/x.go", "docs/guides/A.md", "README.md",
				".github/workflows/other.yml", "release/gates.toml"} {
				write(dir, f, "base "+f+"\n")
			}
			git(dir, "add", "-A")
			git(dir, "commit", "-q", "-m", "base")
			base = git(dir, "rev-parse", "HEAD")
			if change != nil {
				change(dir)
				git(dir, "add", "-A")
				git(dir, "commit", "-q", "--allow-empty", "-m", "change")
			}
			head = git(dir, "rev-parse", "HEAD")
			return dir, base, head
		}
		mv := func(from, to string) func(string) {
			return func(dir string) { git(dir, "mv", from, to) }
		}
		edit := func(names ...string) func(string) {
			return func(dir string) {
				for _, n := range names {
					write(dir, n, "changed "+n+"\n")
				}
			}
		}
		rm := func(name string) func(string) { return func(dir string) { git(dir, "rm", "-q", name) } }

		const zero = "0000000000000000000000000000000000000000"
		cases := []struct {
			name   string
			event  string
			change func(string)
			base   func(base, head string) string // overrides the base
			want   string
		}{
			{"documentation-only pull request", "pull_request", edit("README.md", "docs/guides/A.md"), nil, "false"},
			{"documentation-only push", "push", edit("CHANGELOG.md"), nil, "false"},
			{"code change", "pull_request", edit("internal/x/x.go"), nil, "true"},
			{"mixed code and documentation", "pull_request", edit("README.md", "internal/x/x.go"), nil, "true"},
			{"deleted code file", "pull_request", rm("internal/x/x.go"), nil, "true"},
			{"code file renamed into docs/", "pull_request", mv("internal/x/x.go", "docs/x.go"), nil, "true"},
			{"documentation renamed into a code path", "pull_request", mv("docs/guides/A.md", "internal/x/A.md"), nil, "true"},
			{"workflow change", "pull_request", edit(".github/workflows/other.yml"), nil, "true"},
			{".github/scripts change", "push", edit(".github/scripts/install.sh"), nil, "true"},
			{"release/gates.toml change", "pull_request", edit("release/gates.toml"), nil, "true"},
			{"pull request listing no paths", "pull_request", nil, nil, "true"},
			{"push listing no paths", "push", nil, nil, "true"},
			{"all-zero push base", "push", edit("README.md"), func(string, string) string { return zero }, "true"},
			{"base that does not exist", "pull_request", edit("README.md"),
				func(string, string) string { return "1234567890abcdef1234567890abcdef12345678" }, "true"},
			{"unknown event", "workflow_dispatch", edit("README.md"), nil, "true"},
		}
		// GitHub runs an unconfigured step with `bash -e`, and a `shell: bash`
		// step with `-eo pipefail`. The verdict must not depend on which.
		for _, shell := range [][]string{{"-e"}, {"--noprofile", "--norc", "-eo", "pipefail"}} {
			for _, c := range cases {
				dir, base, head := repo(c.change)
				if c.base != nil {
					base = c.base(base, head)
				}
				out := filepath.Join(t.TempDir(), "github_output")
				if err := os.WriteFile(out, nil, 0o644); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("bash", append(shell, "-c", script)...)
				cmd.Dir = dir
				cmd.Env = append(os.Environ(), "GITHUB_OUTPUT="+out, "EVENT="+c.event,
					"PR_BASE="+base, "PR_HEAD="+head, "PUSH_BEFORE="+base, "PUSH_AFTER="+head)
				log, err := cmd.CombinedOutput()
				if err != nil {
					t.Errorf("%s (bash %v): the step failed instead of selecting a path: %v\n%s", c.name, shell, err, log)
					continue
				}
				got, _ := os.ReadFile(out)
				lines := strings.Fields(string(got))
				if len(lines) != 1 || lines[0] != "go="+c.want {
					t.Errorf("%s (bash %v): GITHUB_OUTPUT = %q, want exactly go=%s\n%s", c.name, shell, got, c.want, log)
				}
			}
		}
	})
}

// @ac AC-29
// AC-29: the documentation job runs the whole packaging/tests package, with
// its prerequisites, without native builds or a database.
func TestCIGates_DocumentationJobRunsThePackagingPackage(t *testing.T) {
	t.Run("release-ci-gates/AC-29", func(t *testing.T) {
		wf := readGoCI(t)
		testRun := regexp.MustCompile(`(?m)^\s*go test\b.*\./packaging/tests/.*$`)
		var id string
		for jid, j := range wf.Jobs {
			if testRun.MatchString(j.script()) && j.If == docsGate {
				if id != "" {
					t.Fatalf("jobs %q and %q both run the documentation path's tests", id, jid)
				}
				id = jid
			}
		}
		if id == "" {
			t.Fatalf("no job gated on %q runs go test on ./packaging/tests/", docsGate)
		}
		j := wf.Jobs[id]
		if !contains(j.needs(), "changes") {
			t.Errorf("job %q does not need changes", id)
		}
		if len(j.Services) != 0 {
			t.Errorf("job %q has services %v; the documentation path runs without a database", id, j.Services)
		}
		if j.Continue != nil {
			t.Errorf("job %q sets continue-on-error", id)
		}
		stage, test, upload := -1, -1, -1
		for i, s := range j.Steps {
			if s.Continue != nil {
				t.Errorf("job %q step %q sets continue-on-error", id, s.Name)
			}
			if strings.Contains(s.Run, "internal/server/openapi_embed.yaml") && strings.Contains(s.Run, "internal/server/spa/index.html") {
				stage = i
			}
			if testRun.MatchString(s.Run) {
				test = i
				line := testRun.FindString(s.Run)
				for _, want := range []string{"-count=1", "-json"} {
					if !strings.Contains(line, want) {
						t.Errorf("the documentation test command lacks %s: %s", want, line)
					}
				}
				if strings.Contains(line, "-run") {
					t.Errorf("the documentation test command selects tests by name: %s", line)
				}
				if regexp.MustCompile(`\./(internal|cmd|scripts)/|\./\.\.\.`).MatchString(line) {
					t.Errorf("the documentation test command names another package: %s", line)
				}
				if !regexp.MustCompile(`unset[^\n]*\bOPENWATCH_PACKAGING_BUILD\b`).MatchString(s.Run) ||
					!regexp.MustCompile(`unset[^\n]*\bOPENWATCH_TEST_DSN\b`).MatchString(s.Run) {
					t.Error("the documentation test step does not unset OPENWATCH_PACKAGING_BUILD and OPENWATCH_TEST_DSN")
				}
			}
			if strings.HasPrefix(s.Uses, "actions/upload-artifact@") {
				upload = i
				if s.With["name"] != "go-ci-docs-results" || s.With["if-no-files-found"] != "error" {
					t.Errorf("upload step %q: name=%q if-no-files-found=%q, want go-ci-docs-results and error",
						s.Name, s.With["name"], s.With["if-no-files-found"])
				}
			}
		}
		if stage < 0 || test < 0 || stage > test {
			t.Errorf("the embedded files must be staged (step %d) before the test (step %d)", stage, test)
		}
		if upload < 0 {
			t.Error("the documentation job does not upload its stream")
		}
		if strings.Contains(j.script(), "OPENWATCH_PACKAGING_BUILD=1") {
			t.Error("the documentation job turns native builds on")
		}
	})
}

// permittedSkips loads PERMITTED from scripts/check-doc-stream.py by running
// it, rather than restating it here.
func permittedSkips(t *testing.T) []string {
	t.Helper()
	code := `import importlib.util,json,sys
spec=importlib.util.spec_from_file_location("m", sys.argv[1]); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
print(json.dumps(list(m.PERMITTED)))`
	out, err := exec.Command("python3", "-S", "-c", code, filepath.Join(appDir(t), "scripts", "check-doc-stream.py")).Output()
	if err != nil {
		t.Fatalf("load PERMITTED: %v", err)
	}
	var msgs []string
	if err := json.Unmarshal(out, &msgs); err != nil {
		t.Fatalf("PERMITTED: %v\n%s", err, out)
	}
	return msgs
}

func runPythonTests(t *testing.T, script string) {
	t.Helper()
	haveTool(t, "python3")
	cmd := exec.Command("python3", "-S", filepath.Join("scripts", script))
	cmd.Dir = appDir(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", script, err, out)
	}
}

// @ac AC-30
// AC-30: the documentation stream is checked as results, and only the
// permitted skips pass.
func TestCIGates_DocumentationStreamIsChecked(t *testing.T) {
	t.Run("release-ci-gates/AC-30", func(t *testing.T) {
		runPythonTests(t, "test_check_doc_stream.py")

		// Each permitted message is still a literal t.Skip in packaging/tests,
		// so an entry cannot outlive the skip it permits.
		var src strings.Builder
		files, _ := filepath.Glob(filepath.Join(appDir(t), "packaging", "tests", "*_test.go"))
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			src.Write(b)
		}
		msgs := permittedSkips(t)
		if len(msgs) == 0 {
			t.Fatal("check-doc-stream.py permits no skip at all; the build opt-in at least must be permitted")
		}
		for _, m := range msgs {
			if !strings.Contains(src.String(), `t.Skip("`+m+`")`) {
				t.Errorf("permitted skip %q is not a t.Skip literal in packaging/tests", m)
			}
		}

		gates := gatesJob(t, readGoCI(t))
		fetched, checked := -1, -1
		for i, s := range gates.Steps {
			if strings.HasPrefix(s.Uses, "actions/download-artifact@") && s.With["name"] == "go-ci-docs-results" {
				fetched = i
				if s.If != docsGate {
					t.Errorf("the documentation results are fetched under if %q, want %q", s.If, docsGate)
				}
			}
			if strings.Contains(s.Run, "scripts/check-doc-stream.py") {
				checked = i
				if s.If != docsGate || s.Continue != nil || strings.Contains(s.Run, "|| true") {
					t.Errorf("step %q must run on the documentation path and be able to fail the job", s.Name)
				}
			}
		}
		if fetched < 0 || checked < 0 || fetched > checked {
			t.Errorf("the gates job must fetch go-ci-docs-results by name (step %d) and then check it (step %d)", fetched, checked)
		}
	})
}

// @ac AC-31
// AC-31: Specter takes the documentation path's results as partial: a fresh
// ingest, failed criteria rejected, no threshold sync. The full path is
// unchanged.
func TestCIGates_DocumentationPathSpecterIsPartial(t *testing.T) {
	t.Run("release-ci-gates/AC-31", func(t *testing.T) {
		runPythonTests(t, "test_check_specter_partial.py")

		gates := gatesJob(t, readGoCI(t))
		var docsIngest *ciStep
		fullCheck, fullIngest, fullSync := false, false, false
		for i, s := range gates.Steps {
			if strings.Contains(s.Run, "specter sync") && s.If != fullGate {
				t.Errorf("step %q runs specter sync under if %q; only the full path may", s.Name, s.If)
			}
			switch s.If {
			case docsGate:
				if strings.Contains(s.Run, "specter ingest") {
					docsIngest = &gates.Steps[i]
				}
			case fullGate:
				fullCheck = fullCheck || strings.Contains(s.Run, "scripts/check-test-streams.py")
				fullSync = fullSync || strings.Contains(s.Run, "specter sync")
				if strings.Contains(s.Run, "specter ingest") &&
					strings.Contains(s.Run, "/tmp/go-test.json") && strings.Contains(s.Run, "/tmp/go-test-server.json") &&
					strings.Contains(s.Run, "--junit") {
					fullIngest = true
				}
			}
		}
		if !fullCheck || !fullIngest || !fullSync {
			t.Errorf("the full path lost a step: stream check %v, ingest of both streams and vitest %v, sync %v",
				fullCheck, fullIngest, fullSync)
		}
		if docsIngest == nil {
			t.Fatal("no specter ingest step runs on the documentation path")
		}
		run := docsIngest.Run
		rmAt := strings.Index(run, "rm -f .specter-results.json")
		sinceAt := strings.Index(run, "since=")
		ingestAt := strings.Index(run, "specter ingest")
		checkAt := strings.Index(run, "scripts/check-specter-partial.py")
		if rmAt < 0 || sinceAt < rmAt || ingestAt < sinceAt || checkAt < ingestAt {
			t.Errorf("the documentation ingest must remove the old results, take the start time, ingest, then check, in that order:\n%s", run)
		}
		ingestLine := regexp.MustCompile(`specter ingest[^\n]*`).FindString(run)
		if ingestLine != "specter ingest --go-test /tmp/go-test-docs.json" {
			t.Errorf("the documentation ingest must read only the documentation stream, got %q", ingestLine)
		}
		if docsIngest.Continue != nil || strings.Contains(run, "|| true") {
			t.Error("the documentation ingest step can fail without failing the job")
		}
	})
}

// @ac AC-32
// AC-32: every scripts/test_*.py runs in the aggregate job on both paths;
// none found, or any failing, fails it.
func TestCIGates_EveryPythonTestScriptRuns(t *testing.T) {
	t.Run("release-ci-gates/AC-32", func(t *testing.T) {
		haveTool(t, "bash")
		haveTool(t, "python3")
		gates := gatesJob(t, readGoCI(t))
		var step *ciStep
		for i, s := range gates.Steps {
			if strings.Contains(s.Run, "scripts/test_*.py") {
				if step != nil {
					t.Fatalf("two steps run scripts/test_*.py: %q and %q", step.Name, s.Name)
				}
				step = &gates.Steps[i]
			}
		}
		if step == nil {
			t.Fatal("the gates job has no step that runs scripts/test_*.py by glob")
		}
		if step.If != "" {
			t.Errorf("the Python test step runs under if %q; it must run on both paths", step.If)
		}
		if step.Continue != nil {
			t.Error("the Python test step sets continue-on-error")
		}

		run := func(files map[string]string) (bool, string, string) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o755); err != nil {
				t.Fatal(err)
			}
			for name, body := range files {
				if err := os.WriteFile(filepath.Join(dir, "scripts", name), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step.Run)
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			return err == nil, string(out), dir
		}
		mark := func(name string) string {
			return "import pathlib\npathlib.Path('ran-" + name + "').write_text('x')\n"
		}

		if ok, out, _ := run(nil); ok {
			t.Errorf("no scripts/test_*.py found, and the step passed:\n%s", out)
		}
		if ok, out, _ := run(map[string]string{"test_a.py": mark("a"), "test_b.py": mark("b"), "helper.py": "raise SystemExit(1)\n"}); !ok {
			t.Errorf("two passing scripts (and a non-test file), and the step failed:\n%s", out)
		}
		ok, out, dir := run(map[string]string{"test_a.py": "raise SystemExit(1)\n", "test_b.py": mark("b")})
		if ok {
			t.Errorf("a failing script, and the step passed:\n%s", out)
		}
		if _, err := os.Stat(filepath.Join(dir, "ran-b")); err != nil {
			t.Error("a script after the failing one did not run; every script must run before the step reports")
		}

		for _, name := range []string{"test_check_doc_stream.py", "test_check_specter_partial.py"} {
			if m, _ := filepath.Match("test_*.py", name); !m {
				t.Errorf("%s does not match the glob", name)
			}
			if _, err := os.Stat(filepath.Join(appDir(t), "scripts", name)); err != nil {
				t.Errorf("%s is missing: %v", name, err)
			}
		}
	})
}
