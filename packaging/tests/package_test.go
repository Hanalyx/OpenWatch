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

// requirePackagingBuild gates the tests that shell out to `make rpm`/`make deb`
// behind an explicit opt-in. A full native package build takes minutes and
// writes into dist/, so a plain `go test ./...` on a dev machine (which may
// have dpkg-deb/rpmbuild installed) should not silently trigger one. CI sets
// OPENWATCH_PACKAGING_BUILD=1 in the ingest step so coverage is unchanged
// there; locally the tests skip unless the developer opts in.
func requirePackagingBuild(t *testing.T) {
	t.Helper()
	if os.Getenv("OPENWATCH_PACKAGING_BUILD") == "" {
		t.Skip("set OPENWATCH_PACKAGING_BUILD=1 to run native package build tests (full make rpm/deb)")
	}
}

func runMake(t *testing.T, dir, target string) {
	t.Helper()
	requirePackagingBuild(t)
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
// AC-04: the RPM payload contains the binary, config, and systemd unit.
// The demo TLS cert is provisioned at install time, NOT shipped (AC-22).
func TestRPM_PayloadContents(t *testing.T) {
	t.Run("release-package-build/AC-04", func(t *testing.T) {
		rpm := rpmPath(t)
		out := rpmQuery(t, rpm, "[%{FILENAMES}\n]")
		mustHave := []string{
			"/usr/bin/openwatch",
			"/etc/openwatch/openwatch.toml",
			"/etc/systemd/system/openwatch.service",
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
// AC-06: DEB payload contains the same critical files as the RPM. The demo
// TLS cert is provisioned at install time, NOT shipped (AC-22).
func TestDEB_PayloadContents(t *testing.T) {
	t.Run("release-package-build/AC-06", func(t *testing.T) {
		deb := debPath(t)
		out := debContents(t, deb)
		mustHave := []string{
			"./usr/bin/openwatch",
			"./etc/openwatch/openwatch.toml",
			"./etc/systemd/system/openwatch.service",
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

// kensaRulesRPMPath returns the kensa-rules noarch RPM under dist/,
// building it via `make kensa-rules` if necessary.
func kensaRulesRPMPath(t *testing.T) string {
	t.Helper()
	dir := appDir(t)
	haveTool(t, "rpmbuild")
	runMake(t, dir, "kensa-rules")
	return findArtifact(t, filepath.Join(dir, "dist"), "kensa-rules-*.rpm")
}

// kensaRulesDebPath returns the kensa-rules all DEB under dist/, building
// it via `make kensa-rules` if necessary.
func kensaRulesDebPath(t *testing.T) string {
	t.Helper()
	dir := appDir(t)
	haveTool(t, "dpkg-deb")
	runMake(t, dir, "kensa-rules")
	return findArtifact(t, filepath.Join(dir, "dist"), "kensa-rules_*.deb")
}

// @ac AC-15
// AC-15: the kensa-rules RPM (noarch) and DEB (all) each carry the full
// corpus under /usr/share/kensa/rules.
func TestKensaRules_CorpusPayload(t *testing.T) {
	t.Run("release-package-build/AC-15", func(t *testing.T) {
		const wantRules = 500
		ruleLine := regexp.MustCompile(`/usr/share/kensa/rules/.*\.yml`)

		rpm := kensaRulesRPMPath(t)
		// noarch: the corpus is arch-independent.
		if arch := strings.TrimSpace(rpmQuery(t, rpm, "%{ARCH}")); arch != "noarch" {
			t.Errorf("kensa-rules RPM arch = %q, want noarch", arch)
		}
		rpmFiles := rpmQuery(t, rpm, "[%{FILENAMES}\n]")
		if n := len(ruleLine.FindAllString(rpmFiles, -1)); n < wantRules {
			t.Errorf("kensa-rules RPM has %d rule files under /usr/share/kensa/rules, want >=%d", n, wantRules)
		}

		deb := kensaRulesDebPath(t)
		debFiles := debContents(t, deb)
		if n := len(ruleLine.FindAllString(debFiles, -1)); n < wantRules {
			t.Errorf("kensa-rules DEB has %d rule files under /usr/share/kensa/rules, want >=%d", n, wantRules)
		}
		// Architecture: all in the DEB control.
		if info := debInfo(t, deb); !strings.Contains(info, "Architecture: all") {
			t.Errorf("kensa-rules DEB control lacks Architecture: all\ninfo:\n%s", info)
		}
	})
}

// @ac AC-16
// AC-16: the openwatch packages declare a hard dependency on kensa-rules
// so a corpus-less install fails fast.
func TestOpenwatch_DependsOnKensaRules(t *testing.T) {
	t.Run("release-package-build/AC-16", func(t *testing.T) {
		dir := appDir(t)
		read := func(p string) string {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read %s: %v", p, err)
			}
			return string(b)
		}
		spec := read(filepath.Join(dir, "packaging", "rpm", "openwatch.spec"))
		if !regexp.MustCompile(`(?m)^Requires:\s+kensa-rules\b`).MatchString(spec) {
			t.Error("openwatch.spec must declare `Requires: kensa-rules`")
		}
		control := read(filepath.Join(dir, "packaging", "deb", "control"))
		depends := ""
		for _, line := range strings.Split(control, "\n") {
			if strings.HasPrefix(line, "Depends:") {
				depends = line
				break
			}
		}
		if !strings.Contains(depends, "kensa-rules") {
			t.Errorf("deb/control Depends must list kensa-rules, got %q", depends)
		}
	})
}

// @ac AC-17
// AC-17: make packages builds the kensa-rules corpus package too.
func TestMake_PackagesBuildsKensaRules(t *testing.T) {
	t.Run("release-package-build/AC-17", func(t *testing.T) {
		dir := appDir(t)
		b, err := os.ReadFile(filepath.Join(dir, "Makefile"))
		if err != nil {
			t.Fatalf("read Makefile: %v", err)
		}
		if !regexp.MustCompile(`(?m)^packages:.*\bkensa-rules\b`).MatchString(string(b)) {
			t.Error("Makefile `packages` target must depend on kensa-rules")
		}
	})
}

// @ac AC-18
// AC-18: the RPM %post and DEB postinst invoke the provisioning helper, and
// the helper generates both identity keys, generate-if-absent, with the
// required formats/modes/owners.
func TestKeys_PostInstallProvisions(t *testing.T) {
	t.Run("release-package-build/AC-18", func(t *testing.T) {
		dir := appDir(t)
		const helperPath = "/usr/lib/openwatch/provision-identity-keys.sh"

		// Scriptlets call the helper.
		rpm := rpmPath(t)
		if post := rpmQuery(t, rpm, "%{POSTIN}"); !strings.Contains(post, helperPath) {
			t.Errorf("RPM %%post does not invoke %s:\n%s", helperPath, post)
		}
		deb := debPath(t)
		if body := readDebControlScript(t, deb, "postinst"); !strings.Contains(body, helperPath) {
			t.Errorf("DEB postinst does not invoke %s:\n%s", helperPath, body)
		}

		// The helper does the right thing.
		helper, err := os.ReadFile(filepath.Join(dir, "packaging", "common", "provision-identity-keys.sh"))
		if err != nil {
			t.Fatalf("read helper: %v", err)
		}
		h := string(helper)
		wants := []struct{ what, substr string }{
			{"generate-if-absent guard", "[ ! -f"},
			{"RSA JWT key via openssl genrsa", "openssl genrsa"},
			{"2048 bits", "2048"},
			{"DEK via openssl rand", "openssl rand"},
			{"32 bytes", "32"},
			{"JWT mode 0640", "chmod 0640"},
			{"DEK mode 0600", "chmod 0600"},
			{"JWT owner root:openwatch", "root:$OWNER_GROUP"},
		}
		for _, w := range wants {
			if !strings.Contains(h, w.substr) {
				t.Errorf("helper missing %s (%q)", w.what, w.substr)
			}
		}
	})
}

// @ac AC-19
// AC-19: both openwatch packages declare openssl (the provisioning helper
// needs it).
func TestKeys_OpensslDependency(t *testing.T) {
	t.Run("release-package-build/AC-19", func(t *testing.T) {
		dir := appDir(t)
		read := func(p string) string {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read %s: %v", p, err)
			}
			return string(b)
		}
		spec := read(filepath.Join(dir, "packaging", "rpm", "openwatch.spec"))
		if !regexp.MustCompile(`(?m)^Requires:\s+openssl\b`).MatchString(spec) {
			t.Error("openwatch.spec must declare `Requires: openssl`")
		}
		control := read(filepath.Join(dir, "packaging", "deb", "control"))
		depends := ""
		for _, line := range strings.Split(control, "\n") {
			if strings.HasPrefix(line, "Depends:") {
				depends = line
				break
			}
		}
		if !strings.Contains(depends, "openssl") {
			t.Errorf("deb/control Depends must list openssl, got %q", depends)
		}
	})
}

// @ac AC-20
// AC-20: the packages ship the helper + an empty keys dir, but NEVER the key
// files themselves (they are generated unique per install).
func TestKeys_NotInPayload(t *testing.T) {
	t.Run("release-package-build/AC-20", func(t *testing.T) {
		const (
			helper = "/usr/lib/openwatch/provision-identity-keys.sh"
			keyDir = "/etc/openwatch/keys"
			jwt    = "jwt_private.pem"
			dek    = "credential.key"
		)
		rpm := rpmPath(t)
		rpmFiles := rpmQuery(t, rpm, "[%{FILENAMES}\n]")
		if !strings.Contains(rpmFiles, helper) {
			t.Errorf("RPM payload missing the provisioning helper %s", helper)
		}
		if !strings.Contains(rpmFiles, keyDir) {
			t.Errorf("RPM payload missing the %s directory", keyDir)
		}
		if strings.Contains(rpmFiles, jwt) || strings.Contains(rpmFiles, dek) {
			t.Errorf("RPM payload MUST NOT contain key files; got:\n%s", rpmFiles)
		}

		deb := debPath(t)
		debFiles := debContents(t, deb)
		if !strings.Contains(debFiles, helper) {
			t.Errorf("DEB payload missing the provisioning helper %s", helper)
		}
		if !strings.Contains(debFiles, "/etc/openwatch/keys") {
			t.Errorf("DEB payload missing the keys directory")
		}
		if strings.Contains(debFiles, jwt) || strings.Contains(debFiles, dek) {
			t.Errorf("DEB payload MUST NOT contain key files; got:\n%s", debFiles)
		}
	})
}

// @ac AC-22
// AC-22: the demo TLS cert is provisioned at install time (generate-if-absent)
// and NEVER shipped in the payload, so a package upgrade cannot revert an
// operator's replacement certificate. Mirrors the identity-key model
// (AC-18/AC-20). This is the regression guard for the pre-release finding that
// a non-%config demo cert at the prod path was silently overwriting operator
// certs on every upgrade.
func TestTLS_PostInstallProvisions(t *testing.T) {
	t.Run("release-package-build/AC-22", func(t *testing.T) {
		dir := appDir(t)
		const helperPath = "/usr/lib/openwatch/provision-tls-cert.sh"

		// Scriptlets call the TLS helper.
		rpm := rpmPath(t)
		if post := rpmQuery(t, rpm, "%{POSTIN}"); !strings.Contains(post, helperPath) {
			t.Errorf("RPM %%post does not invoke %s:\n%s", helperPath, post)
		}
		deb := debPath(t)
		if body := readDebControlScript(t, deb, "postinst"); !strings.Contains(body, helperPath) {
			t.Errorf("DEB postinst does not invoke %s:\n%s", helperPath, body)
		}

		// The helper is generate-if-absent and mints a self-signed cert with
		// the right key strength, modes, and owners.
		helper, err := os.ReadFile(filepath.Join(dir, "packaging", "common", "provision-tls-cert.sh"))
		if err != nil {
			t.Fatalf("read helper: %v", err)
		}
		h := string(helper)
		wants := []struct{ what, substr string }{
			{"generate-if-absent guard", "[ ! -e"},
			{"self-signed cert via openssl req -x509", "openssl req -x509"},
			{"2048-bit RSA key", "rsa:2048"},
			{"cert mode 0644", "chmod 0644"},
			{"key mode 0600", "chmod 0600"},
			{"key owner openwatch:openwatch", "$OWNER_GROUP:$OWNER_GROUP"},
		}
		for _, w := range wants {
			if !strings.Contains(h, w.substr) {
				t.Errorf("TLS helper missing %s (%q)", w.what, w.substr)
			}
		}

		// Payload ships the empty tls dir + the helper, and carries NO real
		// cert/key content. On RPM the cert/key paths are declared %ghost so
		// rpm tracks them (flag 'g') without laying down content — this stops a
		// package upgrade FROM a cert-shipping release (<= rc.9) from reclaiming
		// the operator's file as an orphan, while still never shipping a cert.
		const tlsDir = "/etc/openwatch/tls"
		if !strings.Contains(rpmQuery(t, rpm, "[%{FILENAMES}\n]"), helperPath) {
			t.Errorf("RPM payload missing the TLS helper %s", helperPath)
		}
		rpmGhost := rpmQuery(t, rpm, "[%{FILENAMES} %{FILEFLAGS:fflags}\n]")
		if !strings.Contains(rpmGhost, tlsDir) {
			t.Errorf("RPM payload missing the %s directory", tlsDir)
		}
		for _, p := range []string{"cert.pem", "key.pem"} {
			re := regexp.MustCompile(`/etc/openwatch/tls/` + regexp.QuoteMeta(p) + `\s+\S*g\S*`)
			if !re.MatchString(rpmGhost) {
				t.Errorf("RPM tls/%s MUST be declared %%ghost (flag 'g', no payload content); file list:\n%s", p, rpmGhost)
			}
		}

		// DEB has no %ghost: the cert/key are not in the payload, and preinst
		// stashes an operator's cert before dpkg removes the orphan on upgrade,
		// while postinst restores it. So the cert/key are NEVER real payload
		// files in either format.
		debFiles := debContents(t, deb)
		if !strings.Contains(debFiles, helperPath) {
			t.Errorf("DEB payload missing the TLS helper %s", helperPath)
		}
		if !strings.Contains(debFiles, tlsDir) {
			t.Errorf("DEB payload missing the %s directory", tlsDir)
		}
		if strings.Contains(debFiles, "tls/cert.pem") || strings.Contains(debFiles, "tls/key.pem") {
			t.Errorf("DEB payload MUST NOT ship the TLS cert/key; got:\n%s", debFiles)
		}

		// DEB preinst backs up an operator cert on upgrade; postinst restores it.
		preinst := readPackagingFile(t, dir, "deb", "preinst")
		if !strings.Contains(preinst, ".dpkg-bak") || !strings.Contains(preinst, `"$1" = "upgrade"`) {
			t.Errorf("deb/preinst must back up the TLS cert/key (.dpkg-bak) on upgrade")
		}
		postinst := readPackagingFile(t, dir, "deb", "postinst")
		if !strings.Contains(postinst, ".dpkg-bak") || !strings.Contains(postinst, "mv -f") {
			t.Errorf("deb/postinst must restore the preserved TLS cert/key (.dpkg-bak)")
		}

		// The build scripts no longer stage a demo cert into the payload.
		for _, bs := range []string{"rpm/build-rpm.sh", "deb/build-deb.sh"} {
			b, err := os.ReadFile(filepath.Join(dir, "packaging", bs))
			if err != nil {
				t.Fatalf("read %s: %v", bs, err)
			}
			if regexp.MustCompile(`(?m)^\s*bash\b.*gen-demo-cert\.sh`).MatchString(string(b)) {
				t.Errorf("%s still stages a demo cert into the payload via gen-demo-cert.sh", bs)
			}
		}
	})
}

// readPackagingFile reads packaging/<sub>/<name> as a string.
func readPackagingFile(t *testing.T, appDir, sub, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(appDir, "packaging", sub, name))
	if err != nil {
		t.Fatalf("read packaging/%s/%s: %v", sub, name, err)
	}
	return string(b)
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

// @ac AC-21
// AC-21: pre-release versions are tilde-encoded with Epoch 1 across both
// packages, and the binary keeps the true semver. Source-inspection backstop
// for the rc.3..rc.8 regression where the suffix was stripped, collapsing
// every RC to the same NVR (openwatch-0.2.0-1) so dnf saw the next RC as
// already installed.
func TestPackaging_PreReleaseVersioning(t *testing.T) {
	t.Run("release-package-build/AC-21", func(t *testing.T) {
		dir := appDir(t)
		read := func(rel string) string {
			b, err := os.ReadFile(filepath.Join(dir, rel))
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			return string(b)
		}
		rpmBuild := read("packaging/rpm/build-rpm.sh")
		spec := read("packaging/rpm/openwatch.spec")
		debBuild := read("packaging/deb/build-deb.sh")

		// The stripping bug must be gone, replaced by a tilde conversion.
		if strings.Contains(rpmBuild, "${VERSION%%-*}") {
			t.Error("build-rpm.sh still strips the pre-release suffix (${VERSION%%-*}); use a tilde instead")
		}
		if !strings.Contains(rpmBuild, `${VERSION/-/\~}`) {
			t.Error("build-rpm.sh must tilde-encode the version (${VERSION/-/\\~})")
		}
		// RPM spec carries Epoch.
		if !regexp.MustCompile(`(?m)^Epoch:\s*1\b`).MatchString(spec) {
			t.Error("openwatch.spec must declare 'Epoch: 1'")
		}
		// DEB: tilde upstream + epoch prefix in the control version.
		if !strings.Contains(debBuild, `${VERSION/-/\~}`) {
			t.Error("build-deb.sh must tilde-encode the upstream version")
		}
		if !strings.Contains(debBuild, "DEB_EPOCH") || !strings.Contains(debBuild, `${DEB_EPOCH}:${DEB_UPSTREAM}`) {
			t.Error("build-deb.sh must prefix the control version with the epoch (1:upstream)")
		}
		// Both scripts build the binary with the FULL semver, not the
		// tilde/stripped package version.
		if !strings.Contains(rpmBuild, `make build VERSION="$VERSION"`) {
			t.Error("build-rpm.sh must build the binary with the full $VERSION (true semver)")
		}
		if !strings.Contains(debBuild, `make build VERSION="$VERSION"`) {
			t.Error("build-deb.sh must build the binary with the full $VERSION (true semver)")
		}
	})
}
