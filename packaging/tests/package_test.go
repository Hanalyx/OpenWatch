// @spec release-package-build
//
// Native packaging tests. Build the .rpm and .deb on demand (via the
// Makefile targets) then inspect the artifacts with rpm/dpkg-deb. Skips
// when the tools or build pipeline aren't available.

package packaging_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// appDir is the project root (one directory up from packaging/tests/).
// All make / shell invocations are anchored here so the tests behave
// the same whether run via `go test ./...` from app/ or anywhere else.
func appDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("native packaging tests run on linux only")
	}
	// runtime.Caller(0) → this file (packaging/tests/). parent twice = repo root.
	_, here, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
}

func haveTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not available: %v", name, err)
	}
}

func runMake(t *testing.T, dir, target string) {
	t.Helper()
	cmd := exec.Command("make", target)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("make %s: %v\nstdout: %s\nstderr: %s", target, err, stdout.String(), stderr.String())
	}
}

func findArtifact(t *testing.T, dir, glob string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, glob))
	if err != nil {
		t.Fatalf("glob %s: %v", glob, err)
	}
	if len(matches) == 0 {
		t.Fatalf("no artifact matching %s under %s", glob, dir)
	}
	// Prefer the newest match (later runs of the same glob).
	newest := matches[0]
	newestInfo, _ := os.Stat(newest)
	for _, m := range matches[1:] {
		mi, err := os.Stat(m)
		if err != nil {
			continue
		}
		if mi.ModTime().After(newestInfo.ModTime()) {
			newest = m
			newestInfo = mi
		}
	}
	return newest
}

func rpmQuery(t *testing.T, rpmPath, format string) string {
	t.Helper()
	cmd := exec.Command("rpm", "-qp", "--queryformat", format, rpmPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("rpm query %q: %v\nstderr: %s", format, err, stderr.String())
	}
	return stdout.String()
}

func debInfo(t *testing.T, debPath string) string {
	t.Helper()
	cmd := exec.Command("dpkg-deb", "--info", debPath)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatalf("dpkg-deb --info: %v", err)
	}
	return stdout.String()
}

func debContents(t *testing.T, debPath string) string {
	t.Helper()
	cmd := exec.Command("dpkg-deb", "-c", debPath)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatalf("dpkg-deb -c: %v", err)
	}
	return stdout.String()
}

// rpmPath returns the RPM under dist/, building it if necessary.
func rpmPath(t *testing.T) string {
	t.Helper()
	dir := appDir(t)
	haveTool(t, "rpmbuild")
	runMake(t, dir, "rpm")
	return findArtifact(t, filepath.Join(dir, "dist"), "openwatch-*.rpm")
}

// debPath returns the DEB under dist/, building it if necessary.
func debPath(t *testing.T) string {
	t.Helper()
	dir := appDir(t)
	haveTool(t, "dpkg-deb")
	runMake(t, dir, "deb")
	return findArtifact(t, filepath.Join(dir, "dist"), "openwatch_*.deb")
}

// @ac AC-01
// AC-01: scripts/build-rpm.sh (via `make rpm`) produces a single .rpm
// under app/dist/.
func TestBuild_ProducesRPM(t *testing.T) {
	t.Run("release-package-build/AC-01", func(t *testing.T) {
		rpm := rpmPath(t)
		if info, err := os.Stat(rpm); err != nil || info.Size() < 1024 {
			t.Fatalf("rpm at %s missing or too small: %v size=%d", rpm, err, sizeOr(info))
		}
	})
}

// @ac AC-02
// AC-02: scripts/build-deb.sh (via `make deb`) produces a single .deb
// under app/dist/.
func TestBuild_ProducesDEB(t *testing.T) {
	t.Run("release-package-build/AC-02", func(t *testing.T) {
		deb := debPath(t)
		if info, err := os.Stat(deb); err != nil || info.Size() < 1024 {
			t.Fatalf("deb at %s missing or too small: %v size=%d", deb, err, sizeOr(info))
		}
	})
}

// @ac AC-03
// AC-03: the RPM spec file parses cleanly under `rpm -q --specfile`.
func TestSpec_RPMParses(t *testing.T) {
	t.Run("release-package-build/AC-03", func(t *testing.T) {
		haveTool(t, "rpm")
		dir := appDir(t)
		specPath := filepath.Join(dir, "packaging", "rpm", "openwatch.spec")
		cmd := exec.Command("rpm", "-q", "--specfile", specPath)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		// rpm -q --specfile requires source macros; supply them via --define.
		cmd.Args = append(cmd.Args[:0], "rpm", "-q", "--specfile",
			"--define", "ow_version 0.1.0",
			"--define", "ow_release 1",
			specPath)
		if err := cmd.Run(); err != nil {
			t.Fatalf("rpm -q --specfile failed: %v\nstdout: %s\nstderr: %s",
				err, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "openwatch") {
			t.Errorf("spec query did not name openwatch: %s", stdout.String())
		}
	})
}

// @ac AC-04
// AC-04: the RPM payload contains the binary, config, systemd unit,
// and demo cert.
func TestRPM_PayloadContents(t *testing.T) {
	t.Run("release-package-build/AC-04", func(t *testing.T) {
		rpm := rpmPath(t)
		out := rpmQuery(t, rpm, "[%{FILENAMES}\n]")
		mustHave := []string{
			"/usr/bin/openwatch",
			"/etc/openwatch/openwatch.toml",
			"/etc/systemd/system/openwatch.service",
			"/etc/openwatch/tls/cert.pem",
		}
		for _, f := range mustHave {
			if !strings.Contains(out, f) {
				t.Errorf("RPM payload missing %s\nfull list:\n%s", f, out)
			}
		}
	})
}

// @ac AC-05
// AC-05: DEB control file names the package, depends, and maintainer.
func TestDEB_ControlShape(t *testing.T) {
	t.Run("release-package-build/AC-05", func(t *testing.T) {
		deb := debPath(t)
		info := debInfo(t, deb)
		mustHave := []string{
			"Package: openwatch",
			"Depends:",
			"Maintainer: OpenWatch Build",
		}
		for _, line := range mustHave {
			if !strings.Contains(info, line) {
				t.Errorf("control missing %q\ninfo:\n%s", line, info)
			}
		}
	})
}

// @ac AC-06
// AC-06: DEB payload contains the same critical files as the RPM.
func TestDEB_PayloadContents(t *testing.T) {
	t.Run("release-package-build/AC-06", func(t *testing.T) {
		deb := debPath(t)
		out := debContents(t, deb)
		mustHave := []string{
			"./usr/bin/openwatch",
			"./etc/openwatch/openwatch.toml",
			"./etc/systemd/system/openwatch.service",
			"./etc/openwatch/tls/cert.pem",
		}
		for _, f := range mustHave {
			if !strings.Contains(out, f) {
				t.Errorf("DEB payload missing %s\nfull list:\n%s", f, out)
			}
		}
	})
}

// @ac AC-07
// AC-07: RPM post-install runs systemctl daemon-reload.
func TestRPM_PostScriptReloadsSystemd(t *testing.T) {
	t.Run("release-package-build/AC-07", func(t *testing.T) {
		rpm := rpmPath(t)
		// %{POSTIN} pulls the post-install scriptlet body.
		out := rpmQuery(t, rpm, "%{POSTIN}")
		if !strings.Contains(out, "systemctl daemon-reload") {
			t.Errorf("post script lacks systemctl daemon-reload: %s", out)
		}
	})
}

// @ac AC-08
// AC-08: DEB postinst runs systemctl daemon-reload.
func TestDEB_PostinstReloadsSystemd(t *testing.T) {
	t.Run("release-package-build/AC-08", func(t *testing.T) {
		deb := debPath(t)
		body := readDebControlScript(t, deb, "postinst")
		if !strings.Contains(body, "systemctl daemon-reload") {
			t.Errorf("postinst lacks systemctl daemon-reload: %s", body)
		}
	})
}

// @ac AC-09
// AC-09: RPM pre-uninstall stops and disables the service.
func TestRPM_PreUninstallStopsService(t *testing.T) {
	t.Run("release-package-build/AC-09", func(t *testing.T) {
		rpm := rpmPath(t)
		out := rpmQuery(t, rpm, "%{PREUN}")
		if !strings.Contains(out, "systemctl stop openwatch") {
			t.Errorf("preun lacks systemctl stop: %s", out)
		}
		if !strings.Contains(out, "systemctl disable openwatch") {
			t.Errorf("preun lacks systemctl disable: %s", out)
		}
	})
}

// @ac AC-10
// AC-10: DEB prerm stops and disables the service.
func TestDEB_PrermStopsService(t *testing.T) {
	t.Run("release-package-build/AC-10", func(t *testing.T) {
		deb := debPath(t)
		body := readDebControlScript(t, deb, "prerm")
		if !strings.Contains(body, "systemctl stop openwatch") {
			t.Errorf("prerm lacks systemctl stop: %s", body)
		}
		if !strings.Contains(body, "systemctl disable openwatch") {
			t.Errorf("prerm lacks systemctl disable: %s", body)
		}
	})
}

// @ac AC-11
// AC-11: both packages create the openwatch user + group at pre-install.
func TestBoth_CreateSystemUser(t *testing.T) {
	t.Run("release-package-build/AC-11", func(t *testing.T) {
		rpm := rpmPath(t)
		rpmPreIn := rpmQuery(t, rpm, "%{PREIN}")
		if !strings.Contains(rpmPreIn, "useradd") && !strings.Contains(rpmPreIn, "adduser") {
			t.Errorf("RPM pre script lacks user creation: %s", rpmPreIn)
		}
		if !strings.Contains(rpmPreIn, "groupadd") && !strings.Contains(rpmPreIn, "addgroup") {
			t.Errorf("RPM pre script lacks group creation: %s", rpmPreIn)
		}

		deb := debPath(t)
		body := readDebControlScript(t, deb, "preinst")
		if !strings.Contains(body, "adduser") && !strings.Contains(body, "useradd") {
			t.Errorf("DEB preinst lacks user creation: %s", body)
		}
		if !strings.Contains(body, "addgroup") && !strings.Contains(body, "groupadd") {
			t.Errorf("DEB preinst lacks group creation: %s", body)
		}
	})
}

// @ac AC-12
// AC-12: the binary embedded in each package reports the package's
// VERSION via --version.
func TestBoth_BinaryVersionMatchesPackage(t *testing.T) {
	t.Run("release-package-build/AC-12", func(t *testing.T) {
		dir := appDir(t)
		// Both packages embed the same binary built in the same `make
		// build` step; the binary itself is what we assert on.
		runMake(t, dir, "build")
		binPath := filepath.Join(dir, "dist", "openwatch")
		cmd := exec.Command(binPath, "--version")
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			t.Fatalf("--version: %v output=%s", err, out.String())
		}
		// Version source: prefer the Go rebuild's packaging/version.env
		// (VERSION="..." shell-fragment form), fall back to the
		// repo-root VERSION, then to the hardcoded dev floor. Matches
		// the Makefile's resolution order.
		expectedVersion := "0.1.0-dev"
		if envBytes, err := os.ReadFile(filepath.Join(dir, "packaging", "version.env")); err == nil {
			for _, line := range strings.Split(string(envBytes), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "VERSION=") {
					v := strings.TrimPrefix(line, "VERSION=")
					v = strings.Trim(v, `"'`)
					if v != "" {
						expectedVersion = v
					}
					break
				}
			}
		} else if rootBytes, err := os.ReadFile(filepath.Join(dir, "..", "VERSION")); err == nil {
			if v := strings.TrimSpace(string(rootBytes)); v != "" {
				expectedVersion = v
			}
		}
		if !strings.Contains(out.String(), expectedVersion) {
			t.Errorf("binary --version = %q, want substring %q", out.String(), expectedVersion)
		}
	})
}

// @ac AC-13
// AC-13: make rpm and make deb exit 0.
func TestMake_RPMAndDEBTargetsExit0(t *testing.T) {
	t.Run("release-package-build/AC-13", func(t *testing.T) {
		dir := appDir(t)
		haveTool(t, "rpmbuild")
		haveTool(t, "dpkg-deb")
		runMake(t, dir, "rpm")
		runMake(t, dir, "deb")
	})
}

// @ac AC-14
// AC-14: both build scripts cross-compile for arm64. Source-inspection (an
// actual aarch64 build needs the target rpm/dpkg arch which is not portable in
// CI) — assert the scripts map ARCH=arm64 to the right GOARCH/package arch and
// build with CGO disabled.
func TestBuild_MultiArchSupport(t *testing.T) {
	t.Run("release-package-build/AC-14", func(t *testing.T) {
		dir := appDir(t)
		read := func(p string) string {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read %s: %v", p, err)
			}
			return string(b)
		}
		rpm := read(filepath.Join(dir, "packaging", "rpm", "build-rpm.sh"))
		deb := read(filepath.Join(dir, "packaging", "deb", "build-deb.sh"))

		for name, src := range map[string]string{"build-rpm.sh": rpm, "build-deb.sh": deb} {
			if !strings.Contains(src, "ARCH") || !strings.Contains(src, "arm64") {
				t.Errorf("%s does not parameterize ARCH for arm64", name)
			}
			if !regexp.MustCompile(`GOARCH=.*CGO_ENABLED=0|CGO_ENABLED=0.*GOARCH=`).MatchString(src) {
				t.Errorf("%s does not cross-compile with GOARCH + CGO_ENABLED=0", name)
			}
		}
		// RPM maps arm64 -> aarch64 and passes it to rpmbuild --target.
		if !strings.Contains(rpm, "aarch64") || !regexp.MustCompile(`--target`).MatchString(rpm) {
			t.Error("build-rpm.sh must map arm64 -> aarch64 and pass --target to rpmbuild")
		}
		// DEB renders the target arch into the control file.
		if !regexp.MustCompile(`Architecture:.*ARCH|ARCH.*Architecture`).MatchString(deb) {
			t.Error("build-deb.sh must render the target arch into the DEB control Architecture field")
		}
	})
}

// readDebControlScript extracts a named maintainer script from a DEB
// using `dpkg-deb --ctrl-tarfile` piped to `tar`. Returns the script body
// as a string.
func readDebControlScript(t *testing.T, debPath, scriptName string) string {
	t.Helper()
	// Pipe through tar to extract the named file.
	cmd := exec.Command("sh", "-c",
		"dpkg-deb --ctrl-tarfile "+shellQuote(debPath)+" | tar -xOf - ./"+scriptName)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("extract %s from %s: %v", scriptName, debPath, err)
	}
	body := out.String()
	if body == "" {
		t.Fatalf("maintainer script %s is empty in %s", scriptName, debPath)
	}
	return body
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func sizeOr(info os.FileInfo) int64 {
	if info == nil {
		return 0
	}
	return info.Size()
}

// Verify there's no spurious error import.
var _ = errors.New
