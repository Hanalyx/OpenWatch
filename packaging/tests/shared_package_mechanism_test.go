package packaging_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// These tests exercise the shared-build mechanism with a fake build, so they
// run without OPENWATCH_PACKAGING_BUILD and without rpmbuild or dpkg-deb. They
// prove the properties the read-only package tests rely on: one build, the
// reported artifact and nothing else, a private read-only copy outside the
// checkout, and a refusal whenever the tree, the settings or the copy moved.

// fakeShared returns a sharedPackage whose build writes name into appDir/dist
// and reports it, counting calls. fp is the fingerprint it reports.
func fakeShared(t *testing.T, appDir, name string, fp *string, builds *int) *sharedPackage {
	t.Helper()
	return &sharedPackage{
		target: "fake",
		tool:   "true",
		name:   regexp.MustCompile(`^openwatch-[^/]+\.rpm$`),
		build: func(dir string) (string, error) {
			*builds++
			if err := os.MkdirAll(filepath.Join(dir, "dist"), 0o755); err != nil {
				return "", err
			}
			if err := os.WriteFile(filepath.Join(dir, "dist", name), []byte("built "+name), 0o644); err != nil {
				return "", err
			}
			return ">> building\n>> wrote " + name + " to " + filepath.Join(dir, "dist") + "/\n", nil
		},
		fingerprint: func(string) (string, error) { return *fp, nil },
	}
}

func TestSharedPackage_BuildsOnceAndHandsOutAPrivateReadOnlyCopy(t *testing.T) {
	appDir := t.TempDir()
	fp, builds := "tree-1", 0
	p := fakeShared(t, appDir, "openwatch-1.0.0-1.x86_64.rpm", &fp, &builds)

	first := p.get(t, appDir)
	second := p.get(t, appDir)
	if builds != 1 {
		t.Fatalf("built %d times for two hand-outs, want 1", builds)
	}
	if first != second {
		t.Errorf("two hand-outs returned %q and %q, want the same copy", first, second)
	}
	if rel, err := filepath.Rel(appDir, first); err == nil && !strings.HasPrefix(rel, "..") {
		t.Errorf("shared copy %q is inside the checkout %q; it must live outside it (C-13)", first, appDir)
	}
	info, err := os.Stat(first)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Errorf("shared copy mode %v is writable, want read-only", info.Mode().Perm())
	}
	if b, _ := os.ReadFile(first); string(b) != "built openwatch-1.0.0-1.x86_64.rpm" {
		t.Errorf("shared copy holds %q, want the built artifact", b)
	}
}

func TestSharedPackage_UsesTheReportedArtifactNotTheNewestMatch(t *testing.T) {
	appDir := t.TempDir()
	dist := filepath.Join(appDir, "dist")
	if err := os.MkdirAll(dist, 0o755); err != nil {
		t.Fatal(err)
	}
	fp, builds := "tree-1", 0
	p := fakeShared(t, appDir, "openwatch-2.0.0-1.x86_64.rpm", &fp, &builds)
	inner := p.build
	// A leftover that also matches the glob and is written AFTER the build,
	// so a newest-match lookup would pick it. The build also reports a
	// second artifact of another package, as `make kensa-rules` does, which
	// the name filter must leave out.
	p.build = func(dir string) (string, error) {
		out, err := inner(dir)
		if err != nil {
			return out, err
		}
		other := "kensa-rules-0.10.0-1.noarch.rpm"
		if err := os.WriteFile(filepath.Join(dist, other), []byte("other package"), 0o644); err != nil {
			return out, err
		}
		out += ">> wrote " + other + " to dist/\n"
		stale := filepath.Join(dist, "openwatch-9.9.9-1.x86_64.rpm")
		if err := os.WriteFile(stale, []byte("stale"), 0o644); err != nil {
			return out, err
		}
		future := time.Now().Add(time.Hour)
		return out, os.Chtimes(stale, future, future)
	}

	got := p.get(t, appDir)
	if filepath.Base(got) != "openwatch-2.0.0-1.x86_64.rpm" {
		t.Errorf("shared copy is %q, want the artifact the build reported", filepath.Base(got))
	}
}

func TestSharedPackage_RefusesWhatTheBuildDidNotWrite(t *testing.T) {
	cases := map[string]func(dir string) (string, error){
		"no artifact reported": func(string) (string, error) {
			return ">> building\n", nil
		},
		// Both files exist and are fresh, so only the count can refuse.
		"two artifacts reported": func(dir string) (string, error) {
			for _, n := range []string{"openwatch-1-1.x86_64.rpm", "openwatch-2-1.x86_64.rpm"} {
				if err := os.MkdirAll(filepath.Join(dir, "dist"), 0o755); err != nil {
					return "", err
				}
				if err := os.WriteFile(filepath.Join(dir, "dist", n), []byte(n), 0o644); err != nil {
					return "", err
				}
			}
			return ">> wrote openwatch-1-1.x86_64.rpm to dist/\n>> wrote openwatch-2-1.x86_64.rpm to dist/\n", nil
		},
		"reported file predates the build": func(dir string) (string, error) {
			old := filepath.Join(dir, "dist", "openwatch-1.0.0-1.x86_64.rpm")
			if err := os.MkdirAll(filepath.Dir(old), 0o755); err != nil {
				return "", err
			}
			if err := os.WriteFile(old, []byte("left over"), 0o644); err != nil {
				return "", err
			}
			past := time.Now().Add(-time.Hour)
			if err := os.Chtimes(old, past, past); err != nil {
				return "", err
			}
			return ">> wrote openwatch-1.0.0-1.x86_64.rpm to dist/\n", nil
		},
		"build failed": func(string) (string, error) {
			return "", errors.New("exit status 2")
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			appDir := t.TempDir()
			fp, builds := "tree-1", 0
			p := fakeShared(t, appDir, "unused", &fp, &builds)
			p.build = build
			if _, err := p.handout(appDir); err == nil {
				t.Errorf("a hand-out succeeded for a build where %s", name)
			}
		})
	}
}

func TestSharedPackage_RefusesAStaleOrModifiedArtifact(t *testing.T) {
	t.Run("tree or settings changed after the build", func(t *testing.T) {
		appDir := t.TempDir()
		fp, builds := "tree-1", 0
		p := fakeShared(t, appDir, "openwatch-1.0.0-1.x86_64.rpm", &fp, &builds)
		p.get(t, appDir)
		fp = "tree-2"
		if _, err := p.handout(appDir); err == nil {
			t.Error("a hand-out succeeded after the fingerprint changed")
		}
	})
	// The tree moved while make ran and was put back before the hand-out,
	// so only the check taken right after the build can see it.
	t.Run("tree changed during the build", func(t *testing.T) {
		appDir := t.TempDir()
		fp, builds := "unused", 0
		p := fakeShared(t, appDir, "openwatch-1.0.0-1.x86_64.rpm", &fp, &builds)
		seq, calls := []string{"tree-1", "tree-2"}, 0
		p.fingerprint = func(string) (string, error) {
			calls++
			if calls <= len(seq) {
				return seq[calls-1], nil
			}
			return "tree-1", nil
		}
		if _, err := p.handout(appDir); err == nil {
			t.Error("a hand-out succeeded for a build during which the fingerprint changed")
		}
	})
	t.Run("copy modified after the build", func(t *testing.T) {
		appDir := t.TempDir()
		fp, builds := "tree-1", 0
		p := fakeShared(t, appDir, "openwatch-1.0.0-1.x86_64.rpm", &fp, &builds)
		path := p.get(t, appDir)
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("tampered"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := p.handout(appDir); err == nil {
			t.Error("a hand-out succeeded after the copy was modified")
		}
	})
}

// The fingerprint must move for each input the build reads, and must not move
// for a file the repository ignores, such as dist/ output.
func TestSharedPackage_FingerprintTracksSourceAndSettings(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	repo := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(repo, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repo, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("init", "-q")
	write(".gitignore", "/dist/\n")
	write("main.go", "package main\n")
	run("add", ".")
	run("commit", "-q", "-m", "base")
	for _, k := range buildSettingEnv {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}

	fp := func() string {
		t.Helper()
		s, err := sourceFingerprint(repo)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	base := fp()
	if again := fp(); again != base {
		t.Fatalf("fingerprint is not stable: %s then %s", base, again)
	}

	write("dist/openwatch-1.0.0-1.x86_64.rpm", "build output")
	if got := fp(); got != base {
		t.Error("an ignored dist/ file moved the fingerprint; build output must not invalidate its own artifact")
	}

	steps := []struct {
		name   string
		change func()
	}{
		{"tracked file edited", func() { write("main.go", "package main\n\nfunc main() {}\n") }},
		{"untracked file added", func() { write("extra.go", "package main\n") }},
		{"untracked file edited", func() { write("extra.go", "package main // changed\n") }},
		{"build setting set", func() { t.Setenv("VERSION", "9.9.9") }},
		{"build setting set to empty", func() { t.Setenv("RPM_RELEASE", "") }},
		{"commit moved", func() { run("add", "."); run("commit", "-q", "-m", "next") }},
	}
	prev := base
	for _, s := range steps {
		s.change()
		got := fp()
		if got == prev {
			t.Errorf("%s: fingerprint did not change", s.name)
		}
		prev = got
	}
}
