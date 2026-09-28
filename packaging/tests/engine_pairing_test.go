// @spec release-upgrade
//
// AC traceability (this file):
//
//	AC-09  TestUpgrade_PackageManagerEnforcesEngineCorpusPairing
//	AC-10  TestUpgrade_CorpusPreinstRefusesBeforeUnpack
//
// The pairing is enforced by the package managers' own resolvers, so this
// asks them, with no root, no container and no network: `rpm --test` against
// a temporary rpmdb, and `apt-get -s` against a fixture dpkg status file.
// The packages under test are the real ones this tree builds. The older
// openwatch is a fixture package that provides no engine, which is what every
// release before C-06 is. The same scenarios also run in real containers in
// package-smoke (kensa-rules-compat), which is where fresh installs run their
// scriptlets.

package packaging_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// pairingOldOW is the fixture openwatch that provides no engine: v0.7.1, the
// previous GA. It must sort below the tree's own build, which carries
// packaging/version.env's version (an rc of the next release), or the
// resolver sees the same version already installed and tests nothing.
const pairingOldOW = "1:0.7.1"

// run executes a command and returns its combined output and whether it
// exited zero. The exit status is read directly, never through a pipe.
func run(t *testing.T, name string, args ...string) (string, bool) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatalf("%s: %v", name, err)
		}
		return string(out), false
	}
	return string(out), true
}

// ---- RPM -------------------------------------------------------------------

type rpmFixture struct {
	name, epoch, version string
	provides, files      []string
}

// buildFixtureRPM builds a payload-free package for the given arch.
func buildFixtureRPM(t *testing.T, dir, arch string, f rpmFixture) string {
	t.Helper()
	top := filepath.Join(dir, "rpmtop-"+f.name)
	var spec strings.Builder
	fmt.Fprintf(&spec, "Name: %s\n", f.name)
	if f.epoch != "" {
		fmt.Fprintf(&spec, "Epoch: %s\n", f.epoch)
	}
	fmt.Fprintf(&spec, "Version: %s\nRelease: 1\nSummary: fixture\nLicense: none\n", f.version)
	fmt.Fprintf(&spec, "AutoReqProv: no\n")
	for _, p := range f.provides {
		fmt.Fprintf(&spec, "Provides: %s\n", p)
	}
	spec.WriteString("%description\nfixture\n%install\n")
	for _, file := range f.files {
		fmt.Fprintf(&spec, "mkdir -p %%{buildroot}%s && touch %%{buildroot}%s\n", filepath.Dir(file), file)
	}
	spec.WriteString("%files\n")
	for _, file := range f.files {
		spec.WriteString(file + "\n")
	}
	specPath := filepath.Join(dir, f.name+".spec")
	if err := os.WriteFile(specPath, []byte(spec.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, ok := run(t, "rpmbuild", "--define", "_topdir "+top, "--target", arch, "-bb", specPath); !ok {
		t.Fatalf("rpmbuild %s:\n%s", f.name, out)
	}
	matches, _ := filepath.Glob(filepath.Join(top, "RPMS", "*", f.name+"-*.rpm"))
	if len(matches) != 1 {
		t.Fatalf("fixture %s: built %d packages", f.name, len(matches))
	}
	return matches[0]
}

// rpmBaseFixture provides every requirement of pkgs that neither of the two
// packages under test supplies: the host's base system, as far as the
// resolver needs to know.
func rpmBaseFixture(t *testing.T, pkgs ...string) rpmFixture {
	t.Helper()
	base := rpmFixture{name: "ow-fixture-base", version: "1"}
	seen := map[string]bool{}
	for _, p := range pkgs {
		reqs := rpmQuery(t, p, "[%{REQUIRENAME}|%{REQUIREFLAGS:depflags}|%{REQUIREVERSION}\n]")
		for _, line := range strings.Split(strings.TrimSpace(reqs), "\n") {
			parts := strings.SplitN(line, "|", 3)
			if len(parts) != 3 || seen[parts[0]] {
				continue
			}
			name, ver := parts[0], strings.TrimSpace(parts[2])
			seen[name] = true
			switch {
			case strings.HasPrefix(name, "rpmlib("), name == "openwatch", name == "kensa-rules",
				name == "openwatch-kensa-engine", strings.HasPrefix(name, "config(openwatch)"):
				continue
			case strings.HasPrefix(name, "/"):
				base.files = append(base.files, name)
			case ver != "":
				base.provides = append(base.provides, name+" = "+ver)
			default:
				base.provides = append(base.provides, name)
			}
		}
	}
	return base
}

// rpmDB is a scratch rpm database holding the given packages as installed.
func rpmDB(t *testing.T, dir, label string, installed ...string) string {
	t.Helper()
	db := filepath.Join(dir, "rpmdb-"+label)
	if out, ok := run(t, "rpm", "--dbpath", db, "--initdb"); !ok {
		t.Fatalf("rpm --initdb:\n%s", out)
	}
	args := append([]string{"--dbpath", db, "-i", "--justdb", "--nodeps", "--noscripts", "--notriggers", "--ignoresize"}, installed...)
	if out, ok := run(t, "rpm", args...); !ok {
		t.Fatalf("seed %s:\n%s", label, out)
	}
	return db
}

func rpmTest(t *testing.T, db string, args ...string) (string, bool) {
	t.Helper()
	return run(t, "rpm", append([]string{"--dbpath", db, "--test", "--ignoresize"}, args...)...)
}

// ---- DEB -------------------------------------------------------------------

type statusEntry struct{ pkg, version, arch, provides, depends string }

func (e statusEntry) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Package: %s\nStatus: install ok installed\nPriority: optional\nSection: admin\n", e.pkg)
	fmt.Fprintf(&b, "Maintainer: fixture\nArchitecture: %s\nVersion: %s\n", e.arch, e.version)
	if e.provides != "" {
		fmt.Fprintf(&b, "Provides: %s\n", e.provides)
	}
	if e.depends != "" {
		fmt.Fprintf(&b, "Depends: %s\n", e.depends)
	}
	b.WriteString("Description: fixture\n\n")
	return b.String()
}

// debBase lists every Depends entry of debs that the packages under test do
// not supply, installed at the version the constraint names.
func debBase(t *testing.T, arch string, debs ...string) []statusEntry {
	t.Helper()
	var out []statusEntry
	seen := map[string]bool{}
	for _, d := range debs {
		for _, dep := range strings.Split(debField(t, d, "Depends"), ",") {
			alt := strings.TrimSpace(strings.Split(dep, "|")[0])
			if alt == "" {
				continue
			}
			name, ver := alt, "1"
			if i := strings.Index(alt, "("); i > 0 {
				name = strings.TrimSpace(alt[:i])
				f := strings.Fields(strings.Trim(alt[i:], "()"))
				if len(f) == 2 {
					ver = f[1]
				}
			}
			if seen[name] || name == "kensa-rules" || name == "openwatch" || name == "openwatch-kensa-engine" {
				continue
			}
			seen[name] = true
			out = append(out, statusEntry{pkg: name, version: ver, arch: arch})
		}
	}
	return out
}

// aptSimulate runs `apt-get -s install` against a private apt tree whose dpkg
// status holds exactly the given entries.
func aptSimulate(t *testing.T, dir, label, arch string, installed []statusEntry, debs ...string) (string, bool) {
	t.Helper()
	root := filepath.Join(dir, "apt-"+label)
	for _, d := range []string{"state/lists/partial", "cache/archives/partial", "etc/apt.conf.d", "etc/preferences.d", "etc/sources.list.d"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var status strings.Builder
	for _, e := range installed {
		status.WriteString(e.String())
	}
	if err := os.WriteFile(filepath.Join(root, "state", "status"), []byte(status.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "sources.list"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{
		"-o", "Dir::State=" + filepath.Join(root, "state"),
		"-o", "Dir::State::status=" + filepath.Join(root, "state", "status"),
		"-o", "Dir::Cache=" + filepath.Join(root, "cache"),
		"-o", "Dir::Etc=" + filepath.Join(root, "etc"),
		"-o", "Dir::Etc::sourcelist=" + filepath.Join(root, "etc", "sources.list"),
		"-o", "Dir::Etc::sourceparts=" + filepath.Join(root, "etc", "sources.list.d"),
		"-o", "Dir::Etc::parts=" + filepath.Join(root, "etc", "apt.conf.d"),
		"-o", "Dir::Etc::preferencesparts=" + filepath.Join(root, "etc", "preferences.d"),
		"-o", "Debug::NoLocking=1",
		"-o", "APT::Architecture=" + arch,
		"-s", "install", "--allow-downgrades",
	}
	for _, d := range debs {
		abs, err := filepath.Abs(d)
		if err != nil {
			t.Fatal(err)
		}
		args = append(args, abs)
	}
	return run(t, "apt-get", args...)
}

// buildFixtureDeb builds a payload-free openwatch that provides no engine.
func buildFixtureDeb(t *testing.T, dir, arch, version string) string {
	t.Helper()
	root := filepath.Join(dir, "deb-openwatch-old")
	if err := os.MkdirAll(filepath.Join(root, "DEBIAN"), 0o755); err != nil {
		t.Fatal(err)
	}
	control := fmt.Sprintf("Package: openwatch\nVersion: %s\nArchitecture: %s\nMaintainer: fixture\nDescription: fixture\n", version, arch)
	if err := os.WriteFile(filepath.Join(root, "DEBIAN", "control"), []byte(control), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "openwatch-old-fixture.deb")
	if o, ok := run(t, "dpkg-deb", "--root-owner-group", "--build", root, out); !ok {
		t.Fatalf("dpkg-deb:\n%s", o)
	}
	return out
}

// @ac AC-09
// AC-09: the package managers refuse a corpus beside an older engine and
// accept every pairing that works, in both formats.
func TestUpgrade_PackageManagerEnforcesEngineCorpusPairing(t *testing.T) {
	t.Run("release-upgrade/AC-09", func(t *testing.T) {
		haveTool(t, "rpm")
		haveTool(t, "apt-get")
		v := linkedKensaVersion(t)
		dir := t.TempDir()

		t.Run("rpm", func(t *testing.T) {
			newOW, newKR := rpmPath(t), kensaRulesRPMPath(t)
			arch := rpmQuery(t, newOW, "%{ARCH}")
			oldOW := buildFixtureRPM(t, dir, arch, rpmFixture{name: "openwatch", epoch: "1", version: "0.7.1"})
			oldKR := buildFixtureRPM(t, dir, "noarch", rpmFixture{name: "kensa-rules", version: "0.9.0"})
			base := buildFixtureRPM(t, dir, arch, rpmBaseFixture(t, newOW, newKR))

			older := rpmDB(t, dir, "older", base, oldOW, oldKR)
			if out, ok := rpmTest(t, older, "-U", newKR); ok || !strings.Contains(out, "openwatch-kensa-engine >= "+v) {
				t.Errorf("rules-only upgrade beside openwatch %s: accepted=%v, want refused naming the engine:\n%s", pairingOldOW, ok, out)
			}
			if out, ok := rpmTest(t, older, "-U", newOW); !ok {
				t.Errorf("openwatch-only upgrade refused:\n%s", out)
			}
			if out, ok := rpmTest(t, older, "-U", newOW, newKR); !ok {
				t.Errorf("coordinated upgrade refused:\n%s", out)
			}
			if out, ok := rpmTest(t, rpmDB(t, dir, "fresh", base), "-i", newOW, newKR); !ok {
				t.Errorf("fresh install refused:\n%s", out)
			}
			if out, ok := rpmTest(t, rpmDB(t, dir, "current", base, newOW, newKR), "-U", "--oldpackage", oldOW); ok {
				t.Errorf("openwatch downgraded to %s beside kensa-rules %s:\n%s", pairingOldOW, v, out)
			}
			for _, p := range [][2]string{{"1:0.8.0~rc.5", "1:0.8.0~rc.6"}, {"1:0.8.0~rc.6", "1:0.8.0~rc.10"}, {"1:0.8.0~rc.10", "1:0.8.0"}, {"0.9.0", "0.10.0"}} {
				out, _ := run(t, "rpm", "--eval", fmt.Sprintf("%%{lua: print(rpm.vercmp('%s', '%s'))}", p[0], p[1]))
				if strings.TrimSpace(out) != "-1" {
					t.Errorf("rpm orders %s against %s as %q, want -1", p[0], p[1], strings.TrimSpace(out))
				}
			}
		})

		t.Run("deb", func(t *testing.T) {
			newOW, newKR := debPath(t), kensaRulesDebPath(t)
			arch := debField(t, newOW, "Architecture")
			base := debBase(t, arch, newOW, newKR)
			oldOW := statusEntry{pkg: "openwatch", version: pairingOldOW, arch: arch}
			oldKR := statusEntry{pkg: "kensa-rules", version: "0.9.0", arch: "all"}
			older := append(append([]statusEntry(nil), base...), oldOW, oldKR)

			if out, ok := aptSimulate(t, dir, "rules-only", arch, older, newKR); ok || !strings.Contains(out, "openwatch-kensa-engine") {
				t.Errorf("rules-only upgrade beside openwatch %s: accepted=%v, want refused naming the engine:\n%s", pairingOldOW, ok, out)
			}
			if out, ok := aptSimulate(t, dir, "ow-only", arch, older, newOW); !ok {
				t.Errorf("openwatch-only upgrade refused:\n%s", out)
			}
			if out, ok := aptSimulate(t, dir, "coordinated", arch, older, newOW, newKR); !ok {
				t.Errorf("coordinated upgrade refused:\n%s", out)
			}
			if out, ok := aptSimulate(t, dir, "fresh", arch, base, newOW, newKR); !ok {
				t.Errorf("fresh install refused:\n%s", out)
			}
			current := append(append([]statusEntry(nil), base...),
				statusEntry{pkg: "openwatch", version: debField(t, newOW, "Version"), arch: arch, provides: debField(t, newOW, "Provides")},
				statusEntry{pkg: "kensa-rules", version: v, arch: "all", depends: debField(t, newKR, "Depends")})
			if out, ok := aptSimulate(t, dir, "downgrade", arch, current, buildFixtureDeb(t, dir, arch, pairingOldOW)); ok && !strings.Contains(out, "Remv kensa-rules") {
				t.Errorf("openwatch downgraded to %s beside kensa-rules %s:\n%s", pairingOldOW, v, out)
			}
			for _, p := range [][2]string{{"1:0.8.0~rc.5", "1:0.8.0~rc.6"}, {"1:0.8.0~rc.6", "1:0.8.0~rc.10"}, {"1:0.8.0~rc.10", "1:0.8.0"}, {"0.9.0", "0.10.0"}} {
				if _, ok := run(t, "dpkg", "--compare-versions", p[0], "lt", p[1]); !ok {
					t.Errorf("dpkg does not order %s before %s", p[0], p[1])
				}
			}
		})
	})
}

// @ac AC-10
// AC-10: the kensa-rules DEB carries a preinst that refuses to unpack beside
// an installed openwatch whose engine is older than the corpus. Depends alone
// lets a bare `dpkg -i` replace the corpus before failing (measured
// 2026-09-26: the 0.10.0 files on disk, the package left unconfigured). The
// script is taken from the built package and run against a stub dpkg-query,
// so every installed-state case is exercised without root.
func TestUpgrade_CorpusPreinstRefusesBeforeUnpack(t *testing.T) {
	t.Run("release-upgrade/AC-10", func(t *testing.T) {
		haveTool(t, "dpkg")
		v := linkedKensaVersion(t)
		deb := kensaRulesDebPath(t)
		dir := t.TempDir()
		if out, ok := run(t, "dpkg-deb", "--control", deb, filepath.Join(dir, "ctl")); !ok {
			t.Fatalf("extract control:\n%s", out)
		}
		preinst := filepath.Join(dir, "ctl", "preinst")
		if _, err := os.Stat(preinst); err != nil {
			t.Fatalf("the kensa-rules DEB has no preinst: %v", err)
		}

		// A dpkg-query stub answering for openwatch from two env vars.
		stubDir := filepath.Join(dir, "bin")
		if err := os.MkdirAll(stubDir, 0o755); err != nil {
			t.Fatal(err)
		}
		stub := `#!/bin/sh
case "$*" in
  *Status-Status*) [ -n "$OW_STATUS" ] || exit 1; printf '%s' "$OW_STATUS" ;;
  *Provides*) printf '%s' "$OW_PROVIDES" ;;
esac
`
		if err := os.WriteFile(filepath.Join(stubDir, "dpkg-query"), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}
		exec1 := func(action, status, provides string) (string, bool) {
			t.Helper()
			cmd := exec.Command("sh", preinst, action)
			cmd.Env = append(os.Environ(),
				"PATH="+stubDir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"OW_STATUS="+status, "OW_PROVIDES="+provides)
			out, err := cmd.CombinedOutput()
			return string(out), err == nil
		}
		engine := func(ver string) string { return "openwatch-kensa-engine (= " + ver + ")" }
		older := "0.0.1"

		for _, tc := range []struct {
			name, action, status, provides string
			allow                          bool
		}{
			{"no openwatch", "install", "", "", true},
			{"openwatch removed, config left", "upgrade", "config-files", "", true},
			{"openwatch without an engine provide", "upgrade", "installed", "", false},
			{"engine older than the corpus", "upgrade", "installed", engine(older), false},
			{"engine equal to the corpus", "upgrade", "installed", engine(v), true},
			{"engine newer than the corpus", "upgrade", "installed", "foo, " + engine(v+".1") + ", bar", true},
			{"half-installed openwatch without an engine", "install", "half-configured", "", false},
			{"not an install action", "abort-upgrade", "installed", "", true},
		} {
			out, ok := exec1(tc.action, tc.status, tc.provides)
			if ok != tc.allow {
				t.Errorf("%s: allowed=%v, want %v\n%s", tc.name, ok, tc.allow, out)
			}
			if !tc.allow && (!strings.Contains(out, "Nothing was changed") || !strings.Contains(out, "list openwatch first")) {
				t.Errorf("%s: the refusal does not say nothing changed and how to proceed:\n%s", tc.name, out)
			}
		}
		if out, _ := exec1("upgrade", "installed", ""); !strings.Contains(out, "kensa-rules "+v+" needs") {
			t.Errorf("the refusal does not name this corpus version %s:\n%s", v, out)
		}
	})
}
