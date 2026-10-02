// Source-inspection guard for shell harnesses that run under pipefail.
//
// A pipe into a consumer that can exit before reading all of its input (head,
// grep -q, sed '1p;q', awk 'NR==1{print;exit}') closes the pipe early. If the
// producer is still writing, it dies of SIGPIPE and exits 141, and pipefail
// makes that the status of the whole pipeline. Under set -e the script stops.
// Whether it happens depends on scheduling, so the job fails only sometimes.
// The upgrade-from-GA check failed exactly this way on
// `openwatch --version | head -1` (bugs/OW-102, job 111006579937).
//
// The safe form captures the output first and cuts it in the shell:
//
//	v="$(openwatch --version)"; echo "${v%%$'\n'*}"
//
// Deliberately not flagged: consumers that read all of their input (tail,
// sed -n 's/.../p', sed -n '1,20p', awk without exit), and `||`, which is not
// a pipe.

package packaging_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// earlyExitPipe matches a single `|` (not `||`) into a consumer that may stop
// reading before the producer finishes writing.
var earlyExitPipe = regexp.MustCompile(
	`(?:^|[^|])\|\s*(head\b|grep\s+(?:-[a-zA-Z]*[qm][a-zA-Z0-9]*|--quiet\b|--silent\b|--max-count\b)|sed\s+-n\s+'?1p;\s*q|awk\s+'NR==1\s*\{[^}]*exit)`)

// pipefailScripts returns every *.sh under the given repo-relative roots that
// turns on pipefail.
func pipefailScripts(t *testing.T, roots ...string) []string {
	t.Helper()
	root := hygieneRepoRoot(t)
	var out []string
	for _, r := range roots {
		err := filepath.WalkDir(filepath.Join(root, r), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "node_modules" || d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".sh") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if strings.Contains(string(b), "pipefail") {
				rel, _ := filepath.Rel(root, p)
				out = append(out, rel)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", r, err)
		}
	}
	return out
}

// earlyExitPipeSites returns "file:line: text" for each early-exit pipe in
// src. A command continued across lines (a trailing `\` or `|`) is joined
// first, so a pipe split over two lines is still seen. Comment lines are
// skipped.
func earlyExitPipeSites(name, src string) []string {
	var sites []string
	lines := strings.Split(src, "\n")
	for i := 0; i < len(lines); i++ {
		start := i + 1
		cmd := lines[i]
		for {
			trimmed := strings.TrimRight(cmd, " \t")
			cont := strings.HasSuffix(trimmed, "\\") ||
				(strings.HasSuffix(trimmed, "|") && !strings.HasSuffix(trimmed, "||"))
			if !cont || i+1 >= len(lines) {
				break
			}
			cmd = strings.TrimSuffix(trimmed, "\\") + " " + strings.TrimSpace(lines[i+1])
			i++
		}
		if strings.HasPrefix(strings.TrimSpace(cmd), "#") {
			continue
		}
		if earlyExitPipe.MatchString(cmd) {
			sites = append(sites, name+":"+strconv.Itoa(start)+": "+strings.TrimSpace(cmd))
		}
	}
	return sites
}

// TestHarnessPipes_NoEarlyExitConsumerUnderPipefail fails on any pipe into an
// early-exit consumer in a pipefail shell script under packaging/ or scripts/.
// bugs/OW-102.
func TestHarnessPipes_NoEarlyExitConsumerUnderPipefail(t *testing.T) {
	files := pipefailScripts(t, "packaging", "scripts")
	if len(files) < 5 {
		t.Fatalf("found only %d pipefail scripts; the walk is not seeing the harnesses", len(files))
	}
	var sites []string
	for _, f := range files {
		sites = append(sites, earlyExitPipeSites(f, readHygieneFile(t, f))...)
	}
	for _, s := range sites {
		t.Errorf("early-exit pipe under pipefail (SIGPIPE can fail the run; capture, then cut): %s", s)
	}
}

// TestHarnessPipes_DetectorSeesTheForms keeps the detector honest: it must
// flag each early-exit form, including one split across lines, and must not
// flag consumers that read all of their input or a logical `||`.
func TestHarnessPipes_DetectorSeesTheForms(t *testing.T) {
	flagged := []string{
		"openwatch --version | head -1",
		"x=\"$(find . -type f | head -n1)\"",
		"curl -s http://x |grep -q ok && break",
		"curl -s http://x \\\n    | grep -q ok || fail",
		"curl -s http://x |\n    head -1",
		"cmd | grep -m1 x",
		"cmd | sed -n '1p;q'",
		"cmd | awk 'NR==1{print;exit}'",
	}
	for _, src := range flagged {
		if len(earlyExitPipeSites("t.sh", src)) == 0 {
			t.Errorf("not flagged: %q", src)
		}
	}
	clean := []string{
		"journalctl -n 30 | tail -30",
		"curl -s x | sed -n 's/.*\"a\":\"\\([^\"]*\\)\".*/\\1/p'",
		"printf '%s\\n' \"$st\" | sed -n '1,20p'",
		"a || grep -q x file",
		"# a comment that says | head -1",
		"v=\"$(openwatch --version)\"; echo \"${v%%$'\\n'*}\"",
	}
	for _, src := range clean {
		if got := earlyExitPipeSites("t.sh", src); len(got) != 0 {
			t.Errorf("wrongly flagged: %q -> %v", src, got)
		}
	}
}
