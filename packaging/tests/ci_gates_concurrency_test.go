// @spec release-ci-gates

package packaging_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Superseded pull-request runs are canceled; nothing else is (C-23). The
// concurrency settings are read from the workflow files and evaluated with a
// small interpreter for the subset of GitHub expressions they use (contexts,
// string literals, ==, &&, || and format), so the test checks what each event
// gets, not only how the text is spelled.

var concurrencyWorkflows = []string{"go-ci.yml", "codeql.yml", "package-smoke.yml"}

type ghContext map[string]string

func (c ghContext) lookup(path string) (any, bool) {
	v, ok := c[path]
	if !ok {
		return nil, false
	}
	if n, err := strconv.Atoi(v); err == nil && path != "github.event_name" {
		return n, true
	}
	return v, true
}

type exprParser struct {
	toks []string
	pos  int
	ctx  ghContext
	t    *testing.T
}

var exprToken = regexp.MustCompile(`\s*('[^']*'|==|&&|\|\||[(),]|[A-Za-z_][A-Za-z0-9_.\-]*)`)

func tokenize(t *testing.T, s string) []string {
	t.Helper()
	var out []string
	for rest := strings.TrimSpace(s); rest != ""; rest = strings.TrimSpace(rest) {
		m := exprToken.FindStringSubmatchIndex(rest)
		if m == nil || m[0] != 0 {
			t.Fatalf("cannot tokenize expression at %q", rest)
		}
		out = append(out, rest[m[2]:m[3]])
		rest = rest[m[1]:]
	}
	return out
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case int:
		return x != 0
	case bool:
		return x
	}
	return true
}

func (p *exprParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *exprParser) next() string { tok := p.peek(); p.pos++; return tok }

// Precedence, lowest first: ||, &&, ==. Like GitHub, && and || return an
// operand, not a boolean, which is what makes `c && a || b` a conditional.
func (p *exprParser) or() any {
	v := p.and()
	for p.peek() == "||" {
		p.next()
		r := p.and()
		if !truthy(v) {
			v = r
		}
	}
	return v
}

func (p *exprParser) and() any {
	v := p.eq()
	for p.peek() == "&&" {
		p.next()
		r := p.eq()
		if truthy(v) {
			v = r
		}
	}
	return v
}

func (p *exprParser) eq() any {
	v := p.primary()
	for p.peek() == "==" {
		p.next()
		r := p.primary()
		// GitHub compares strings case-insensitively.
		v = strings.EqualFold(fmt.Sprint(v), fmt.Sprint(r))
	}
	return v
}

func (p *exprParser) primary() any {
	tok := p.next()
	switch {
	case strings.HasPrefix(tok, "'"):
		return strings.Trim(tok, "'")
	case tok == "format":
		if p.next() != "(" {
			p.t.Fatalf("format without (")
		}
		var args []any
		for p.peek() != ")" {
			args = append(args, p.or())
			if p.peek() == "," {
				p.next()
			}
		}
		p.next()
		s := fmt.Sprint(args[0])
		for i, a := range args[1:] {
			s = strings.ReplaceAll(s, "{"+strconv.Itoa(i)+"}", fmt.Sprint(a))
		}
		return s
	case tok == "(":
		v := p.or()
		p.next()
		return v
	default:
		v, _ := p.ctx.lookup(tok) // a missing context is null, as in GitHub
		return v
	}
}

var exprBlock = regexp.MustCompile(`\$\{\{(.*?)\}\}`)

// render substitutes every ${{ }} in s, as GitHub does for a string field.
func render(t *testing.T, s string, ctx ghContext) string {
	t.Helper()
	return exprBlock.ReplaceAllStringFunc(s, func(m string) string {
		inner := exprBlock.FindStringSubmatch(m)[1]
		p := &exprParser{toks: tokenize(t, inner), ctx: ctx, t: t}
		v := p.or()
		if p.pos != len(p.toks) {
			t.Fatalf("unparsed tokens in %q", inner)
		}
		if v == nil {
			return ""
		}
		return fmt.Sprint(v)
	})
}

type concurrencySetting struct {
	Group  string `yaml:"group"`
	Cancel string `yaml:"cancel-in-progress"`
}

func readConcurrency(t *testing.T, name string) (string, concurrencySetting) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(appDir(t), ".github", "workflows", name))
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Name        string             `yaml:"name"`
		Concurrency concurrencySetting `yaml:"concurrency"`
	}
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if wf.Concurrency.Group == "" || wf.Concurrency.Cancel == "" {
		t.Fatalf("%s has no workflow-level concurrency group and cancel-in-progress", name)
	}
	return wf.Name, wf.Concurrency
}

type event struct {
	label string
	ctx   ghContext
}

func events(workflow string) []event {
	pr := func(n, run, sha string) ghContext {
		return ghContext{"github.workflow": workflow, "github.event_name": "pull_request",
			"github.event.pull_request.number": n, "github.run_id": run, "github.sha": sha}
	}
	other := func(name, ref, run string) ghContext {
		return ghContext{"github.workflow": workflow, "github.event_name": name, "github.ref": ref,
			"github.run_id": run}
	}
	return []event{
		{"PR 12, first head", pr("12", "1001", "aaaa")},
		{"PR 12, second head", pr("12", "1002", "bbbb")},
		{"PR 13", pr("13", "1003", "cccc")},
		{"push to main", other("push", "refs/heads/main", "2001")},
		{"next push to main", other("push", "refs/heads/main", "2002")},
		{"tag v0.9.0", other("push", "refs/tags/v0.9.0", "3001")},
		{"tag v0.9.0, rerun of the same run", other("push", "refs/tags/v0.9.0", "3001")},
		{"tag v0.9.1", other("push", "refs/tags/v0.9.1", "3002")},
		{"schedule", other("schedule", "refs/heads/main", "4001")},
		{"manual run", other("workflow_dispatch", "refs/heads/main", "5001")},
	}
}

// @ac AC-42
// AC-42: a newer head of the same pull request cancels the older run; every
// other run, including each push to main and each tag, has a group of its own
// and is never canceled.
func TestCIGates_SupersededPRRunsAreCanceledAndNothingElse(t *testing.T) {
	t.Run("release-ci-gates/AC-42", func(t *testing.T) {
		groups := map[string]string{} // group -> "workflow: event"
		for _, file := range concurrencyWorkflows {
			name, c := readConcurrency(t, file)
			got := map[string]string{}
			for _, e := range events(name) {
				group := render(t, c.Group, e.ctx)
				cancel := render(t, c.Cancel, e.ctx)
				got[e.label] = group
				isPR := e.ctx["github.event_name"] == "pull_request"
				if want := strconv.FormatBool(isPR); cancel != want {
					t.Errorf("%s, %s: cancel-in-progress is %q, want %s", file, e.label, cancel, want)
				}
				if !strings.HasPrefix(group, name+"-") || strings.HasSuffix(group, "-") {
					t.Errorf("%s, %s: group %q is not this workflow's", file, e.label, group)
				}
				// A shared group would let one workflow's runs cancel another's.
				if prev, ok := groups[group]; ok && !strings.HasPrefix(prev, file+":") {
					t.Errorf("%s, %s: group %q is shared with %s", file, e.label, group, prev)
				}
				groups[group] = file + ": " + e.label
			}
			if got["PR 12, first head"] != got["PR 12, second head"] {
				t.Errorf("%s: two heads of one PR are in different groups (%q, %q), so the "+
					"older run is never canceled", file, got["PR 12, first head"], got["PR 12, second head"])
			}
			if got["PR 12, first head"] == got["PR 13"] {
				t.Errorf("%s: two PRs share group %q", file, got["PR 13"])
			}
			// Even with cancel-in-progress false, a shared group replaces a
			// pending run, so no two non-PR runs may share one.
			seen := map[string]string{}
			for _, e := range events(name) {
				if e.ctx["github.event_name"] == "pull_request" || e.label == "tag v0.9.0, rerun of the same run" {
					continue
				}
				if prev, ok := seen[got[e.label]]; ok {
					t.Errorf("%s: %s and %s share group %q, so one can replace the other",
						file, prev, e.label, got[e.label])
				}
				seen[got[e.label]] = e.label
			}
			if got["tag v0.9.0"] != got["tag v0.9.0, rerun of the same run"] {
				t.Errorf("%s: a rerun is in a different group from its own run", file)
			}
		}
	})
}

// @ac AC-42
// AC-42: the three workflows carry one identical setting, so they cannot drift.
func TestCIGates_ConcurrencyIsIdenticalAcrossWorkflows(t *testing.T) {
	t.Run("release-ci-gates/AC-42", func(t *testing.T) {
		_, first := readConcurrency(t, concurrencyWorkflows[0])
		for _, file := range concurrencyWorkflows[1:] {
			if _, c := readConcurrency(t, file); c != first {
				t.Errorf("%s concurrency %+v differs from %s %+v", file, c, concurrencyWorkflows[0], first)
			}
		}
		// The interpreter itself: the conditional idiom and a missing context.
		ctx := ghContext{"github.event_name": "push", "github.run_id": "7"}
		if got := render(t, "${{ github.event_name == 'pull_request' && 'a' || format('r-{0}', github.run_id) }}", ctx); got != "r-7" {
			t.Errorf("conditional idiom evaluated to %q", got)
		}
		if got := render(t, "x${{ github.missing }}y", ctx); got != "xy" {
			t.Errorf("a missing context rendered %q", got)
		}
	})
}
