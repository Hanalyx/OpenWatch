package packaging_test

// codeql.yml scans pull requests, runs daily and on demand, and no longer scans
// every push to main. Release gate Q2 reads a passing CodeQL check run on the
// tagged commit, which used to come from that push scan, so the workflow must
// scan release tags instead and still produce the check-run name Q2 reads.

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

type codeqlWorkflow struct {
	On struct {
		PullRequest *struct {
			Branches []string `yaml:"branches"`
		} `yaml:"pull_request"`
		Push *struct {
			Branches []string `yaml:"branches"`
			Tags     []string `yaml:"tags"`
		} `yaml:"push"`
		Schedule []struct {
			Cron string `yaml:"cron"`
		} `yaml:"schedule"`
		Dispatch *yaml.Node `yaml:"workflow_dispatch"`
	} `yaml:"on"`
	Jobs map[string]struct {
		Name     string `yaml:"name"`
		Strategy struct {
			Matrix struct {
				Language []string `yaml:"language"`
			} `yaml:"matrix"`
		} `yaml:"strategy"`
	} `yaml:"jobs"`
}

func readCodeQLWorkflow(t *testing.T) (codeqlWorkflow, bool) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(appDir(t), ".github", "workflows", "codeql.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var w codeqlWorkflow
	if err := yaml.Unmarshal(raw, &w); err != nil {
		t.Fatalf("codeql.yml: %v", err)
	}
	// An empty `workflow_dispatch:` key decodes to a null node, so presence is
	// read from the raw mapping rather than from the field.
	var top struct {
		On map[string]yaml.Node `yaml:"on"`
	}
	if err := yaml.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	_, dispatch := top.On["workflow_dispatch"]
	return w, dispatch
}

// dailyCron reports whether a five-field cron expression fires every day.
func dailyCron(expr string) bool {
	f := strings.Fields(expr)
	return len(f) == 5 && f[2] == "*" && f[3] == "*" && f[4] == "*"
}

// @spec release-ci-gates
// @ac AC-27
func TestCodeQL_TriggersKeepReleaseGateEvidence(t *testing.T) {
	t.Run("release-ci-gates/AC-27", func(t *testing.T) {
		w, dispatch := readCodeQLWorkflow(t)

		if w.On.PullRequest == nil || !contains(w.On.PullRequest.Branches, "main") {
			t.Error("codeql.yml must scan pull requests to main")
		}
		daily := false
		for _, s := range w.On.Schedule {
			daily = daily || dailyCron(s.Cron)
		}
		if !daily {
			t.Error("codeql.yml must have a schedule that runs every day")
		}
		if !dispatch {
			t.Error("codeql.yml must keep workflow_dispatch for manual scans")
		}

		if w.On.Push == nil {
			t.Fatal("codeql.yml has no push trigger, so a release tag is never scanned and gate Q2 finds no check run")
		}
		if len(w.On.Push.Branches) != 0 {
			t.Errorf("codeql.yml still scans pushes to branches %v; main is scanned on a schedule", w.On.Push.Branches)
		}
		for _, tag := range []string{"v0.8.3", "v0.8.0-rc.6"} {
			matched := false
			for _, pat := range w.On.Push.Tags {
				if ok, err := path.Match(pat, tag); err == nil && ok {
					matched = true
				}
			}
			if !matched {
				t.Errorf("no push tag pattern in %v matches %s, so its commit gets no CodeQL check run", w.On.Push.Tags, tag)
			}
		}

		var gates struct {
			Gate []struct {
				ID       string `toml:"id"`
				Evidence string `toml:"evidence"`
				Check    string `toml:"check"`
			} `toml:"gate"`
		}
		if _, err := toml.DecodeFile(filepath.Join(appDir(t), "release", "gates.toml"), &gates); err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, g := range gates.Gate {
			if g.Evidence != "github-check" || !strings.HasPrefix(g.Check, "Analyze Code (") {
				continue
			}
			found++
			lang := strings.TrimSuffix(strings.TrimPrefix(g.Check, "Analyze Code ("), ")")
			produced := false
			for _, j := range w.Jobs {
				if j.Name == "Analyze Code" && contains(j.Strategy.Matrix.Language, lang) {
					produced = true
				}
			}
			if !produced {
				t.Errorf("gate %s reads check %q, which no codeql.yml job produces", g.ID, g.Check)
			}
		}
		if found == 0 {
			t.Error("release/gates.toml has no CodeQL github-check gate; this test no longer guards anything")
		}
	})
}
