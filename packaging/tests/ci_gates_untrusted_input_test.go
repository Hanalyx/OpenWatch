// @spec release-ci-gates
//
// Untrusted text in workflows (bugs/OW-126). GitHub substitutes a ${{ }}
// expression into a run script before bash parses it, so a pull request
// title or an alert description placed there can change the script. These
// tests read the workflows as YAML, run the alert triage workflow's own step
// scripts with hostile input, and evaluate its job condition per event.

package packaging_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type ghStep struct {
	Name string            `yaml:"name"`
	If   string            `yaml:"if"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
}

type ghJob struct {
	If          string    `yaml:"if"`
	Needs       yaml.Node `yaml:"needs"`
	Permissions yaml.Node `yaml:"permissions"`
	Steps       []ghStep  `yaml:"steps"`
}

type ghWorkflow struct {
	On          map[string]yaml.Node `yaml:"on"`
	Permissions yaml.Node            `yaml:"permissions"`
	Jobs        map[string]ghJob     `yaml:"jobs"`
}

func parseWorkflow(t *testing.T, name string, raw []byte) ghWorkflow {
	t.Helper()
	var w ghWorkflow
	if err := yaml.Unmarshal(raw, &w); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return w
}

func readWorkflow(t *testing.T, file string) ghWorkflow {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(appDir(t), ".github", "workflows", file))
	if err != nil {
		t.Fatal(err)
	}
	return parseWorkflow(t, file, raw)
}

// trustedRunExpr is every expression a run script may contain: values the
// repository itself sets. Anything else goes through env (spec C-27).
var trustedRunExpr = regexp.MustCompile(`^(matrix\.[A-Za-z0-9_-]+|github\.(repository|repository_owner|sha|run_id|run_number|run_attempt|workspace)|runner\.[a-z_]+)$`)

var runExpr = regexp.MustCompile(`(?s)\$\{\{(.*?)\}\}`)

// untrustedRunExprs returns "job / step: expression" for each expression in
// a run script that is not on the allowlist.
func untrustedRunExprs(w ghWorkflow) []string {
	var out []string
	for jn, job := range w.Jobs {
		for _, st := range job.Steps {
			for _, m := range runExpr.FindAllStringSubmatch(st.Run, -1) {
				if e := strings.TrimSpace(m[1]); !trustedRunExpr.MatchString(e) {
					out = append(out, fmt.Sprintf("%s / %s: ${{ %s }}", jn, st.Name, e))
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// @ac AC-50
func TestCIGates_RunScriptsHoldNoUntrustedExpressions(t *testing.T) {
	t.Run("release-ci-gates/AC-50", func(t *testing.T) {
		// The checker finds each untrusted form, so a pass below means
		// something.
		for _, e := range []string{
			"github.event.pull_request.title",
			"github.head_ref",
			"github.event.inputs.alert_id",
			"inputs.alert_id",
			"steps.fetch.outputs.count",
			"needs.risk-assessment.outputs.description",
			"env.TITLE",
			"github.actor",
			"format('{0}', github.event.issue.title)",
		} {
			for _, form := range []string{"${{ %s }}", "${{%s}}"} {
				expr := fmt.Sprintf(form, e)
				src := "jobs:\n  j:\n    steps:\n      - name: s\n        run: |\n          echo start\n          echo \"" + expr + "\"\n"
				if got := untrustedRunExprs(parseWorkflow(t, "synthetic", []byte(src))); len(got) != 1 {
					t.Errorf("the checker did not find %s in a run script: %v", expr, got)
				}
			}
		}

		files, err := filepath.Glob(filepath.Join(appDir(t), ".github", "workflows", "*.y*ml"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no workflows found: %v", err)
		}
		for _, f := range files {
			for _, bad := range untrustedRunExprs(readWorkflow(t, filepath.Base(f))) {
				t.Errorf("%s: %s is substituted into the script before bash parses it; pass it through the step's env and quote it", filepath.Base(f), bad)
			}
		}
	})
}

// alertsStep returns the named step of the alert triage workflow.
func alertsStep(t *testing.T, w ghWorkflow, job, step string) ghStep {
	t.Helper()
	for _, st := range w.Jobs[job].Steps {
		if st.Name == step {
			// The rig moves only these paths; any other would be written
			// on the machine running the test.
			if rest := stepTmpPath.ReplaceAllString(st.Run, ""); strings.Contains(rest, "/tmp/") {
				t.Fatalf("step %q uses a /tmp path the rig does not move; add it to stepTmpPath", step)
			}
			return st
		}
	}
	t.Fatalf("claude-code-alerts.yml has no step %q in job %q", step, job)
	return ghStep{}
}

// stepRig runs workflow step scripts the way Actions does (bash -e) from the
// repository root, with the real scripts/risk_assessment.py, a recording gh
// stand-in, and /tmp redirected into a test directory.
type stepRig struct {
	dir, bin, tmp string
	ghLog         string
	root          string
	ghFail        string // "list" or "get" makes that gh call fail
}

// breakAssessor replaces the real assessor with one that classifies
// nothing, to show the workflow refuses an assessment that lost the alert.
func (r *stepRig) breakAssessor(t *testing.T) {
	t.Helper()
	py := `#!/bin/bash
for a in "$@"; do case "$a" in --output=*) out="${a#--output=}" ;; esac; done
for f in low medium high; do echo '[]' > "$out/${f}_risk_alerts.json"; done
`
	_ = os.Remove(filepath.Join(r.bin, "python"))
	if err := os.WriteFile(filepath.Join(r.bin, "python"), []byte(py), 0o755); err != nil {
		t.Fatal(err)
	}
}

func newStepRig(t *testing.T) *stepRig {
	t.Helper()
	for _, tool := range []string{"bash", "jq", "grep", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required to run workflow steps: %v", tool, err)
		}
	}
	dir := t.TempDir()
	r := &stepRig{dir: dir, bin: filepath.Join(dir, "bin"), tmp: filepath.Join(dir, "tmp"), ghLog: filepath.Join(dir, "gh.log"), root: appDir(t)}
	for _, d := range []string{r.bin, r.tmp} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// gh records each call's arguments, one per line with newlines escaped.
	// Alert reads answer from fixture files; GH_FAIL makes one fail.
	gh := `#!/bin/bash
{ echo "--- call"; for a in "$@"; do printf '%s' "$a" | sed -e ':a;N;$!ba;s/\n/\\n/g'; echo; done; } >> "$GH_LOG"
case "$*" in
  "api --paginate /repos/"*"/dependabot/alerts?"*)
    [ "$GH_FAIL" = list ] && { echo "HTTP 403: Resource not accessible by integration" >&2; exit 1; }
    cat "$GH_FIXTURES/pages.json" ;;
  "api /repos/"*"/alerts/"*)
    [ "$GH_FAIL" = get ] && { echo "HTTP 404: Not Found" >&2; exit 1; }
    cat "$GH_FIXTURES/alert.json" ;;
esac
`
	if err := os.WriteFile(filepath.Join(r.bin, "gh"), []byte(gh), 0o755); err != nil {
		t.Fatal(err)
	}
	py, _ := exec.LookPath("python3")
	if err := os.Symlink(py, filepath.Join(r.bin, "python")); err != nil {
		t.Fatal(err)
	}
	return r
}

// fixture writes a file gh answers from: pages.json or alert.json.
func (r *stepRig) fixture(t *testing.T, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(r.dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// stepTmpPath is a fixed /tmp path the workflow's steps use.
var stepTmpPath = regexp.MustCompile(`/tmp/(alerts\b|claude_task\.md|claude_output\.json)`)

// run executes script with env and returns its exit code and output. The
// steps' own /tmp paths are moved into the rig; hostile input that names a
// path under the test's directory is left alone.
func (r *stepRig) run(t *testing.T, script string, env map[string]string) (int, string) {
	t.Helper()
	script = stepTmpPath.ReplaceAllString(script, r.tmp+"/$1")
	path := filepath.Join(r.dir, "step.sh")
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-e", path)
	cmd.Dir = r.root
	cmd.Env = []string{
		"PATH=" + r.bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + r.dir,
		"GH_LOG=" + r.ghLog,
		"GH_FIXTURES=" + r.dir,
		"GITHUB_ACTIONS=true",
		"GITHUB_OUTPUT=" + filepath.Join(r.dir, "github_output"),
		"GH_FAIL=" + r.ghFail,
	}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), string(out)
		}
		t.Fatalf("run step: %v", err)
	}
	return 0, string(out)
}

func (r *stepRig) ghCalls(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(r.ghLog)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// outputs reads GITHUB_OUTPUT: every key with all the values written for it.
func (r *stepRig) outputs(t *testing.T) map[string][]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.dir, "github_output"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Errorf("GITHUB_OUTPUT line is not key=value: %q", line)
			continue
		}
		out[k] = append(out[k], v)
	}
	return out
}

// marked reports which of the hostile inputs' marker files exist.
func (r *stepRig) marked() []string {
	m, _ := filepath.Glob(filepath.Join(r.dir, "pwned-*"))
	return m
}

// stepEnv builds a step's environment from its own env block: each key the
// step declares takes the test's value, and every declared value must be an
// expression, so the test is exercising the env path the workflow uses.
func stepEnv(t *testing.T, st ghStep, values map[string]string) map[string]string {
	t.Helper()
	env := map[string]string{}
	for k, v := range st.Env {
		if !runExpr.MatchString(v) {
			t.Errorf("step %q env %s is not an expression: %q", st.Name, k, v)
		}
		env[k] = values[k]
	}
	return env
}

// depAlert is a Dependabot alert as the REST API returns it, with the fields
// the workflow and the assessor read. A patch-level fix of a low-severity
// advisory in a package the assessor does not list as critical scores LOW;
// critical severity scores MEDIUM; critical with a major-version range scores
// HIGH.
func depAlert(number int, state, pkg, severity, versionRange, summary string) string {
	b, _ := json.Marshal(map[string]any{
		"number":     number,
		"state":      state,
		"dependency": map[string]any{"package": map[string]any{"name": pkg}},
		"security_vulnerability": map[string]any{
			"severity":                 severity,
			"vulnerable_version_range": versionRange,
			"first_patched_version":    map[string]any{"identifier": "9.9.9"},
		},
		"security_advisory": map[string]any{"summary": summary},
	})
	return string(b)
}

const (
	alertTitle  = "chore(deps): bump lodash from 4.17.20 to 4.17.21 in /frontend"
	alertPR     = "42"
	alertRepo   = "o/r"
	syntheticTk = "synthetic"
)

// pipelineResult is what one alert triage run did.
type pipelineResult struct {
	fetchExit, assessExit int
	fetchOut, assessOut   string
	outputs               map[string][]string
	jobs                  []string // downstream jobs whose condition held, in order
	calls                 string   // every gh call, from every step
}

// runPipeline runs the assessment job's two shell steps, then evaluates each
// downstream job's condition with the outputs they wrote, as GitHub does, and
// runs the steps of every job that would run. A failed step ends the job, so
// nothing after it runs.
func runPipeline(t *testing.T, r *stepRig, w ghWorkflow, event map[string]string) pipelineResult {
	t.Helper()
	fetch := alertsStep(t, w, "risk-assessment", "Fetch Alert")
	assess := alertsStep(t, w, "risk-assessment", "Assess Risk")
	values := map[string]string{"GITHUB_TOKEN": syntheticTk, "REPOSITORY": alertRepo, "PR_NUMBER": alertPR}
	for k, v := range event {
		values[k] = v
	}
	var res pipelineResult
	res.fetchExit, res.fetchOut = r.run(t, fetch.Run, stepEnv(t, fetch, values))
	if res.fetchExit != 0 {
		res.calls = r.ghCalls(t)
		return res
	}
	res.assessExit, res.assessOut = r.run(t, assess.Run, stepEnv(t, assess, values))
	res.outputs = r.outputs(t)
	if res.assessExit != 0 {
		res.calls = r.ghCalls(t)
		return res
	}
	one := func(k string) string {
		if v := res.outputs[k]; len(v) == 1 {
			return v[0]
		}
		t.Fatalf("output %s was written %d times: %v", k, len(res.outputs[k]), res.outputs)
		return ""
	}
	ctx := ghContext{
		"github.event_name": event["EVENT_NAME"],
		"github.actor":      "dependabot[bot]",
	}
	for _, k := range []string{"risk_level", "alert_id", "description", "can_auto_fix"} {
		ctx["needs.risk-assessment.outputs."+k] = one(k)
	}
	downstream := map[string]string{
		"GITHUB_TOKEN": syntheticTk, "GH_REPO": alertRepo, "REPOSITORY_OWNER": "owner",
		"PR_NUMBER": alertPR, "ALERT_ID": one("alert_id"), "DESCRIPTION": one("description"),
	}
	for _, jn := range []string{"auto-fix-low-risk", "claude-code-fix", "human-review-required"} {
		job := w.Jobs[jn]
		if !evalIf(t, job.If, ctx) {
			continue
		}
		res.jobs = append(res.jobs, jn)
		for _, st := range job.Steps {
			if st.Run == "" || (st.If != "" && !evalIf(t, st.If, ctx)) {
				continue
			}
			alertsStep(t, w, jn, st.Name)
			if code, out := r.run(t, st.Run, stepEnv(t, st, downstream)); code != 0 {
				t.Logf("%s / %s exited %d:\n%s", jn, st.Name, code, out)
				break
			}
		}
	}
	res.calls = r.ghCalls(t)
	return res
}

// acted reports the gh calls that change the repository: a review, a merge
// or an issue.
func acted(calls string) []string {
	var out []string
	for _, call := range strings.Split(calls, "--- call\n")[1:] {
		args := strings.SplitN(call, "\n", 3)
		if len(args) >= 2 && (args[0] == "pr" || args[0] == "issue") {
			out = append(out, args[0]+" "+args[1])
		}
	}
	return out
}

// @ac AC-51
func TestCIGates_AlertTriageStepsTreatHostileTextAsData(t *testing.T) {
	t.Run("release-ci-gates/AC-51", func(t *testing.T) {
		w := readWorkflow(t, "claude-code-alerts.yml")
		fetch := alertsStep(t, w, "risk-assessment", "Fetch Alert")

		hostileTitles := func(dir string) map[string]string {
			return map[string]string{
				"subst":    "chore(deps): bump lodash from 1 to 2 $(touch " + dir + "/pwned-subst)",
				"backtick": "chore(deps): bump lodash from 1 to 2 `touch " + dir + "/pwned-backtick`",
				"quote":    `chore(deps): bump x from 1"; touch ` + dir + `/pwned-quote; echo "`,
				"fi":       `x"); fi; touch ` + dir + `/pwned-fi; if true; then X=$(echo "`,
				"single":   `'; touch ` + dir + `/pwned-single; echo '`,
				"pkg":      "chore(deps): bump $(touch${IFS}" + dir + "/pwned-pkg) from 1 to 2",
			}
		}

		// The rig detects injection: the fetch script with the title
		// substituted the way GitHub substitutes an expression runs the
		// title's command, even for an event whose branch never runs, as
		// for an ordinary pull request before the fix.
		{
			r := newStepRig(t)
			if !strings.Contains(fetch.Run, `"$PR_TITLE"`) {
				t.Fatal(`the fetch step no longer reads "$PR_TITLE"; update this check`)
			}
			script := strings.Replace(fetch.Run, `"$PR_TITLE"`, `"`+hostileTitles(r.dir)["fi"]+`"`, 1)
			r.run(t, script, map[string]string{"EVENT_NAME": "schedule", "REPOSITORY": alertRepo})
			if len(r.marked()) == 0 {
				t.Fatal("the rig cannot see injection: a substituted title did not run its command")
			}
		}

		for _, name := range []string{"subst", "backtick", "quote", "fi", "single", "pkg"} {
			r := newStepRig(t)
			title := hostileTitles(r.dir)[name]
			r.fixture(t, "pages.json", "[]")
			res := runPipeline(t, r, w, map[string]string{"EVENT_NAME": "pull_request", "PR_TITLE": title})
			if m := r.marked(); len(m) > 0 {
				t.Errorf("title %q ran a command (%v):\n%s", title, m, res.fetchOut)
			}
			if res.fetchExit != 0 || res.assessExit != 0 {
				t.Errorf("title %q: fetch exited %d, assess %d:\n%s%s", title, res.fetchExit, res.assessExit, res.fetchOut, res.assessOut)
			}
			if a := acted(res.calls); len(a) > 0 {
				t.Errorf("title %q led to %v", title, a)
			}
		}

		// Dispatch inputs are checked before gh is called.
		for _, in := range []struct{ id, typ string }{
			{"5; touch pwned-id", "codeql"},
			{"5", "other"},
			{"", "dependabot"},
			{"0", "dependabot"},
		} {
			r := newStepRig(t)
			res := runPipeline(t, r, w, map[string]string{"EVENT_NAME": "workflow_dispatch", "INPUT_ALERT_ID": in.id, "INPUT_ALERT_TYPE": in.typ})
			if res.fetchExit == 0 {
				t.Errorf("dispatch alert_id %q type %q was accepted:\n%s", in.id, in.typ, res.fetchOut)
			}
			if res.calls != "" {
				t.Errorf("dispatch alert_id %q type %q reached gh:\n%s", in.id, in.typ, res.calls)
			}
		}

		// An alert description cannot write a second output. The assessor
		// writes its own outputs too, under other names.
		assessorKeys := []string{"has_low_risk", "has_medium_risk", "has_high_risk", "low_risk_count", "medium_risk_count", "high_risk_count"}
		for _, c := range []struct{ severity, want, autofix string }{
			{"low", "LOW", "true"},
			{"critical", "MEDIUM", "false"},
		} {
			r := newStepRig(t)
			summary := "bad\nrisk_level=LOW\r\ncan_auto_fix=true\nalert_id=1"
			r.fixture(t, "pages.json", "["+depAlert(5, "open", "lodash", c.severity, "< 4.17.21", summary)+"]")
			res := runPipeline(t, r, w, map[string]string{"EVENT_NAME": "pull_request", "PR_TITLE": alertTitle})
			if res.assessExit != 0 {
				t.Fatalf("assess exited %d:\n%s", res.assessExit, res.assessOut)
			}
			o := res.outputs
			if len(o["risk_level"]) != 1 || o["risk_level"][0] != c.want ||
				len(o["alert_id"]) != 1 || o["alert_id"][0] != "5" ||
				len(o["can_auto_fix"]) != 1 || o["can_auto_fix"][0] != c.autofix ||
				len(o["description"]) != 1 || !strings.HasPrefix(o["description"][0], "bad risk_level=LOW") {
				t.Errorf("severity %s: outputs other than the ones assessed (want risk %s):\n%v", c.severity, c.want, o)
			}
			for k := range o {
				if !contains(append([]string{"risk_level", "alert_id", "description", "can_auto_fix"}, assessorKeys...), k) {
					t.Errorf("an unexpected output %s was written: %v", k, o)
				}
			}
		}

		// Downstream steps pass the description to gh as literal text.
		for _, c := range []struct {
			job   string
			steps []string
			want  string // a gh argument that must carry the text
		}{
			{"auto-fix-low-risk", []string{"Auto-Approve Dependabot PR"}, ""},
			{"claude-code-fix", []string{"Create Claude Task", "Fallback - Create Manual Review Issue"}, "body"},
			{"human-review-required", []string{"Create High-Priority Issue"}, "body"},
		} {
			r := newStepRig(t)
			desc := "x $(touch " + r.dir + "/pwned-d1) `touch " + r.dir + "/pwned-d2` \" ' \\\nEOF\n$(touch " + r.dir + "/pwned-d3)"
			values := map[string]string{
				"GITHUB_TOKEN": syntheticTk, "GH_REPO": alertRepo, "REPOSITORY_OWNER": "owner",
				"PR_NUMBER": alertPR, "ALERT_ID": "5", "DESCRIPTION": desc,
			}
			for _, name := range c.steps {
				st := alertsStep(t, w, c.job, name)
				if code, out := r.run(t, st.Run, stepEnv(t, st, values)); code != 0 {
					t.Errorf("%s / %s exited %d:\n%s", c.job, name, code, out)
				}
			}
			if m := r.marked(); len(m) > 0 {
				t.Errorf("%s: the description ran a command (%v)", c.job, m)
			}
			calls := r.ghCalls(t)
			if calls == "" {
				t.Errorf("%s: gh was never called", c.job)
				continue
			}
			escaped := strings.ReplaceAll(desc, "\n", `\n`)
			if c.want == "body" && !strings.Contains(calls, escaped) {
				t.Errorf("%s: gh did not receive the description as literal text:\n%s", c.job, calls)
			}
			if !strings.Contains(calls, "#5") {
				t.Errorf("%s: gh did not receive the alert id:\n%s", c.job, calls)
			}
		}
	})
}

// @ac AC-53
func TestCIGates_AlertTriageFailsClosedWithoutAnAlert(t *testing.T) {
	t.Run("release-ci-gates/AC-53", func(t *testing.T) {
		w := readWorkflow(t, "claude-code-alerts.yml")
		pr := func(title string) map[string]string {
			return map[string]string{"EVENT_NAME": "pull_request", "PR_TITLE": title}
		}
		lowAlert := depAlert(7, "open", "lodash", "low", "< 4.17.21", "prototype pollution")
		other := depAlert(8, "open", "left-pad", "low", "< 1.3.0", "other package")

		type want struct {
			failed bool     // the assessment job fails
			risk   string   // otherwise, the risk level it records
			acts   []string // repository-changing gh calls
		}
		cases := []struct {
			name   string
			event  map[string]string
			pages  string // the Dependabot listing gh returns; "" for none
			alert  string // the single alert gh returns
			ghFail string
			want   want
		}{
			{"listing fails", pr(alertTitle), "", "", "list", want{failed: true}},
			{"listing is an error object", pr(alertTitle), `{"message": "Bad credentials"}`, "", "", want{failed: true}},
			{"listing is not JSON", pr(alertTitle), "<html>", "", "", want{failed: true}},
			{"listing is empty output", pr(alertTitle), "\n", "", "", want{failed: true}},
			{"listing is an object of alerts", pr(alertTitle), `{"a": ` + lowAlert + `}`, "", "", want{failed: true}},
			{"no alert matches", pr(alertTitle), "[" + other + "]", "", "", want{risk: "NONE"}},
			{"listing is empty", pr(alertTitle), "[]", "", "", want{risk: "NONE"}},
			{"the matching alert is fixed", pr(alertTitle), "[" + depAlert(7, "fixed", "lodash", "low", "< 4.17.21", "x") + "]", "", "", want{risk: "NONE"}},
			{"a grouped update", pr("chore(deps): bump the npm-production group across 1 directory with 11 updates"), "[" + lowAlert + "]", "", "", want{risk: "NONE"}},
			{"two alerts match", pr(alertTitle), "[" + lowAlert + "," + depAlert(9, "open", "lodash", "low", "< 4.17.21", "y") + "]", "", "", want{failed: true}},
			{"no severity", pr(alertTitle), `[{"number": 7, "state": "open", "dependency": {"package": {"name": "lodash"}}}]`, "", "", want{failed: true}},
			{"unknown severity", pr(alertTitle), "[" + depAlert(7, "open", "lodash", "negligible", "< 4.17.21", "x") + "]", "", "", want{failed: true}},
			{"number 0", pr(alertTitle), "[" + depAlert(0, "open", "lodash", "low", "< 4.17.21", "x") + "]", "", "", want{failed: true}},
			{"number is a string", pr(alertTitle), `[{"number": "7", "state": "open", "dependency": {"package": {"name": "lodash"}}, "security_vulnerability": {"severity": "low"}}]`, "", "", want{failed: true}},
			{"dispatch fetch fails", map[string]string{"EVENT_NAME": "workflow_dispatch", "INPUT_ALERT_ID": "7", "INPUT_ALERT_TYPE": "dependabot"}, "", "", "get", want{failed: true}},
			{"dispatch code scanning fetch fails", map[string]string{"EVENT_NAME": "workflow_dispatch", "INPUT_ALERT_ID": "3", "INPUT_ALERT_TYPE": "codeql"}, "", "", "get", want{failed: true}},
			{"dispatch returns a dismissed alert", map[string]string{"EVENT_NAME": "workflow_dispatch", "INPUT_ALERT_ID": "7", "INPUT_ALERT_TYPE": "dependabot"}, "", depAlert(7, "dismissed", "lodash", "low", "< 4.17.21", "x"), "", want{failed: true}},
			{"dispatch returns another alert", map[string]string{"EVENT_NAME": "workflow_dispatch", "INPUT_ALERT_ID": "7", "INPUT_ALERT_TYPE": "dependabot"}, "", depAlert(8, "open", "lodash", "low", "< 4.17.21", "x"), "", want{failed: true}},
			{"dispatch code scanning alert without severity", map[string]string{"EVENT_NAME": "workflow_dispatch", "INPUT_ALERT_ID": "3", "INPUT_ALERT_TYPE": "codeql"}, "", `{"number": 3, "state": "open", "rule": {"id": "js/unused-variable"}}`, "", want{failed: true}},

			// Controls: complete alerts reach the action their risk calls
			// for, so the refusals above are refusals and not a broken rig.
			{"low alert on the second page", pr(alertTitle), "[" + other + "]\n[" + lowAlert + "]", "", "", want{risk: "LOW", acts: []string{"pr review", "pr merge"}}},
			{"critical alert", pr(alertTitle), "[" + depAlert(7, "open", "lodash", "critical", "< 4.17.21", "x") + "]", "", "", want{risk: "MEDIUM", acts: []string{"issue create"}}},
			{"dispatch code scanning error", map[string]string{"EVENT_NAME": "workflow_dispatch", "INPUT_ALERT_ID": "3", "INPUT_ALERT_TYPE": "codeql"}, "", `{"number": 3, "state": "open", "rule": {"id": "js/code-injection", "severity": "error", "description": "code injection"}}`, "", want{risk: "HIGH", acts: []string{"issue create"}}},
		}
		for _, c := range cases {
			r := newStepRig(t)
			if c.pages != "" {
				r.fixture(t, "pages.json", c.pages)
			}
			if c.alert != "" {
				r.fixture(t, "alert.json", c.alert)
			}
			// GH_FAIL configures the stand-in, not a step, so it goes
			// through the rig rather than a step's env block.
			r.ghFail = c.ghFail
			res := runPipeline(t, r, w, c.event)
			failed := res.fetchExit != 0 || res.assessExit != 0
			got := acted(res.calls)
			if failed != c.want.failed {
				t.Errorf("%s: assessment failed = %v, want %v\nfetch:\n%s\nassess:\n%s", c.name, failed, c.want.failed, res.fetchOut, res.assessOut)
			}
			if !failed && (len(res.outputs["risk_level"]) != 1 || res.outputs["risk_level"][0] != c.want.risk) {
				t.Errorf("%s: risk_level = %v, want %s\n%s", c.name, res.outputs["risk_level"], c.want.risk, res.assessOut)
			}
			if strings.Join(got, ",") != strings.Join(c.want.acts, ",") {
				t.Errorf("%s: gh changed the repository with %v, want %v (jobs %v)\n%s", c.name, got, c.want.acts, res.jobs, res.calls)
			}
		}

		// An assessment that classifies no alert is refused, not read as HIGH
		// or LOW.
		{
			r := newStepRig(t)
			r.breakAssessor(t)
			r.fixture(t, "pages.json", "["+lowAlert+"]")
			res := runPipeline(t, r, w, pr(alertTitle))
			if res.assessExit == 0 || len(acted(res.calls)) > 0 {
				t.Errorf("an assessment that classified nothing was accepted (exit %d, %v):\n%s", res.assessExit, acted(res.calls), res.assessOut)
			}
		}

		// The auto-fix job needs both a LOW level and can_auto_fix, and its
		// approval step refuses an alert id that is not an assessed alert's.
		job := w.Jobs["auto-fix-low-risk"]
		for _, c := range []struct {
			risk, fix string
			want      bool
		}{{"LOW", "true", true}, {"LOW", "false", false}, {"NONE", "false", false}, {"", "", false}} {
			ctx := ghContext{"needs.risk-assessment.outputs.risk_level": c.risk, "needs.risk-assessment.outputs.can_auto_fix": c.fix}
			if got := evalIf(t, job.If, ctx); got != c.want {
				t.Errorf("auto-fix runs = %v for risk %q can_auto_fix %q, want %v", got, c.risk, c.fix, c.want)
			}
		}
		approve := alertsStep(t, w, "auto-fix-low-risk", "Auto-Approve Dependabot PR")
		for _, id := range []string{"unknown", "0", "", "7 "} {
			r := newStepRig(t)
			code, out := r.run(t, approve.Run, stepEnv(t, approve, map[string]string{
				"GITHUB_TOKEN": syntheticTk, "GH_REPO": alertRepo, "PR_NUMBER": alertPR, "ALERT_ID": id,
			}))
			if code == 0 || r.ghCalls(t) != "" {
				t.Errorf("the approval step ran for alert id %q (exit %d):\n%s\n%s", id, code, out, r.ghCalls(t))
			}
		}
	})
}

// evalIf evaluates a job condition with the expression interpreter the
// concurrency test uses (ci_gates_concurrency_test.go).
func evalIf(t *testing.T, src string, ctx ghContext) bool {
	t.Helper()
	p := &exprParser{toks: tokenize(t, src), ctx: ctx, t: t}
	v := p.or()
	if p.pos != len(p.toks) {
		t.Fatalf("unparsed tokens in %q", src)
	}
	return truthy(v)
}

// permissionMap decodes a job's permissions; a scalar (read-all, write-all)
// or anything but a flat mapping is reported.
func permissionMap(t *testing.T, where string, n yaml.Node) map[string]string {
	t.Helper()
	if n.Kind == 0 {
		return nil
	}
	if n.Kind != yaml.MappingNode {
		t.Errorf("%s: permissions must be a mapping of scopes, got %q", where, n.Value)
		return nil
	}
	var m map[string]string
	if err := n.Decode(&m); err != nil {
		t.Errorf("%s: permissions: %v", where, err)
	}
	return m
}

func needsList(n yaml.Node) []string {
	switch n.Kind {
	case yaml.ScalarNode:
		return []string{n.Value}
	case yaml.SequenceNode:
		var out []string
		for _, c := range n.Content {
			out = append(out, c.Value)
		}
		return out
	}
	return nil
}

// @ac AC-52
func TestCIGates_AlertTriageRunsOnlyForItsEvents(t *testing.T) {
	t.Run("release-ci-gates/AC-52", func(t *testing.T) {
		w := readWorkflow(t, "claude-code-alerts.yml")

		var triggers []string
		for k := range w.On {
			triggers = append(triggers, k)
		}
		sort.Strings(triggers)
		if strings.Join(triggers, ",") != "pull_request,workflow_dispatch" {
			t.Errorf("claude-code-alerts.yml triggers on %v; want pull_request and workflow_dispatch only", triggers)
		}

		if w.Permissions.Kind != yaml.MappingNode || len(w.Permissions.Content) != 0 {
			t.Errorf("claude-code-alerts.yml must set `permissions: {}` at the workflow level; a job left without its own block would inherit the rest")
		}
		mayWrite := map[string][]string{
			"contents":      {"auto-fix-low-risk"},
			"pull-requests": {"auto-fix-low-risk"},
			"issues":        {"claude-code-fix", "human-review-required"},
		}
		for jn, job := range w.Jobs {
			perms := permissionMap(t, jn, job.Permissions)
			if job.Permissions.Kind == 0 {
				t.Errorf("job %s has no permissions block", jn)
			}
			for scope, level := range perms {
				if level == "write" && !contains(mayWrite[scope], jn) {
					t.Errorf("job %s may write %s; only %v may", jn, scope, mayWrite[scope])
				}
			}
		}
		assess, ok := w.Jobs["risk-assessment"]
		if !ok {
			t.Fatal("claude-code-alerts.yml has no risk-assessment job")
		}
		got := permissionMap(t, "risk-assessment", assess.Permissions)
		if len(got) != 2 || got["contents"] != "read" || got["security-events"] != "read" {
			t.Errorf("risk-assessment permissions = %v, want exactly contents: read and security-events: read", got)
		}

		dependabot := "dependabot[bot]"
		for _, c := range []struct {
			name             string
			event, actor, by string
			want             bool
		}{
			{"manual dispatch", "workflow_dispatch", "maintainer", "", true},
			{"Dependabot pull request", "pull_request", dependabot, dependabot, true},
			{"ordinary pull request", "pull_request", "contributor", "contributor", false},
			{"Dependabot pull request someone else updated", "pull_request", "contributor", dependabot, false},
			{"pull request Dependabot updated", "pull_request", dependabot, "contributor", false},
			{"schedule", "schedule", "maintainer", "", false},
		} {
			ctx := ghContext{"github.event_name": c.event, "github.actor": c.actor}
			if c.by != "" {
				ctx["github.event.pull_request.user.login"] = c.by
			}
			if strings.TrimSpace(assess.If) == "" {
				t.Fatal("risk-assessment has no if; it runs for every event")
			}
			if got := evalIf(t, assess.If, ctx); got != c.want {
				t.Errorf("%s: risk-assessment runs = %v, want %v (if: %s)", c.name, got, c.want, assess.If)
			}
		}

		status := regexp.MustCompile(`\b(always|failure|cancelled|success)\s*\(`)
		for jn, job := range w.Jobs {
			if jn == "risk-assessment" {
				continue
			}
			if !contains(needsList(job.Needs), "risk-assessment") {
				t.Errorf("job %s does not need risk-assessment, so it is not skipped with it", jn)
			}
			if status.MatchString(job.If) {
				t.Errorf("job %s uses a status function in its if (%s), which can run it after a skipped assessment", jn, job.If)
			}
		}
	})
}
