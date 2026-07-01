// Doc link hygiene. Markdown docs are the primary onboarding surface for humans
// and AI assistants; a link that points at a moved or deleted file is a false
// breadcrumb that costs a reader real time and erodes trust in every other link.
// This test walks the tracked Markdown and fails on a broken *relative doc link*
// — the exact rot class that let dead context/*.md and PRD/*.md references linger
// in guidance for months.
//
// Scope is deliberately narrow to stay signal-rich:
//   - Only relative links (external http(s)/mailto and pure #anchors are ignored).
//   - Image links (.png/.jpg/.svg/...) are ignored — missing screenshots are a
//     content gap tracked elsewhere, not doc rot.
//   - Template placeholders (containing < or >) are ignored.
//   - Historical/vendored trees are skipped (docs/_history, node_modules, ...).
package packaging_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// repoRootForLinks returns the repo root (two dirs up from packaging/tests/).
func repoRootForLinks(t *testing.T) string {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
}

// markdownLink matches the target of a Markdown link: ](target).
var markdownLink = regexp.MustCompile(`\]\(([^)]+)\)`)

// skipDirs are trees whose internal links we don't gate (vendored, generated, or
// deliberately-frozen historical docs that may reference archived paths).
var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	"_history":     true, // docs/_history: archived Python-era docs, links not gated
}

func isImageLink(s string) bool {
	switch strings.ToLower(filepath.Ext(s)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".pdf":
		return true
	}
	return false
}

func TestDocs_NoBrokenRelativeLinks(t *testing.T) {
	root := repoRootForLinks(t)

	// Work entirely from the TRACKED file set (git ls-files), so the check is
	// identical in CI and locally. This matters because much of docs/ is
	// gitignored-by-design (engineering/architecture docs are local-only): a
	// tracked doc that links to a local-only file is genuinely broken for anyone
	// who clones, and must be caught even though the target exists on the
	// author's disk. On-disk os.Stat would hide exactly that class.
	cmd := exec.Command("git", "ls-files", "-z")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("git ls-files unavailable (%v); skipping doc-link check", err)
	}

	// tracked holds every tracked path plus all ancestor directories, so a link
	// to a directory (e.g. docs/guides/) resolves too.
	tracked := map[string]bool{".": true}
	var mdFiles []string
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel == "" {
			continue
		}
		tracked[rel] = true
		for d := filepath.Dir(rel); d != "." && d != "/"; d = filepath.Dir(d) {
			tracked[d] = true
		}
		if !strings.EqualFold(filepath.Ext(rel), ".md") {
			continue
		}
		skip := false
		for seg := range skipDirs {
			if strings.Contains("/"+rel+"/", "/"+seg+"/") {
				skip = true
				break
			}
		}
		if !skip {
			mdFiles = append(mdFiles, rel)
		}
	}

	var broken []string
	for _, rel := range mdFiles {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		dir := filepath.Dir(rel)
		for _, m := range markdownLink.FindAllStringSubmatch(string(raw), -1) {
			link := strings.TrimSpace(m[1])
			// Drop an anchor / query fragment; a link may be just "#section".
			if i := strings.IndexAny(link, "#?"); i >= 0 {
				link = link[:i]
			}
			if link == "" {
				continue // pure anchor
			}
			// External, mail, protocol-relative, absolute, or home-relative.
			if strings.Contains(link, "://") || strings.HasPrefix(link, "mailto:") ||
				strings.HasPrefix(link, "/") || strings.HasPrefix(link, "~") {
				continue
			}
			// Template placeholders (e.g. <guide>/<step>) and images.
			if strings.ContainsAny(link, "<>") || isImageLink(link) {
				continue
			}
			// Resolve relative to the file's dir, then require the target to be a
			// tracked path (file or directory). A link to a local-only/gitignored
			// file is broken for anyone who clones, so it counts.
			target := filepath.Clean(filepath.Join(dir, link))
			if !tracked[target] {
				broken = append(broken, rel+"  ->  "+m[1])
			}
		}
	}

	if len(broken) > 0 {
		sort.Strings(broken)
		t.Errorf("%d broken relative doc link(s) — fix the link or the target:\n  %s",
			len(broken), strings.Join(broken, "\n  "))
	}
}
