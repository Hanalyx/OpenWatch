// @spec release-package-build

package packaging_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Release signing (release-package-build C-18, C-19). release.yml signs with
// three scripts: packaging/release-signing-key.sh pins the one key, then
// packaging/sign-rpms.sh signs the RPM headers and packaging/sign-detached.sh
// writes the DEB and SHA256SUMS signatures. These tests run the scripts for
// real with throwaway keys in throwaway GnuPG homes, and read release.yml for
// where and how they run. The real release key is never used here.

// gpgHome makes a throwaway GnuPG home under /tmp (gpg-agent's socket path
// must stay short) and stops its daemons at cleanup. The agent caches no
// passphrase, so a wrong one is never covered by an earlier right one.
func gpgHome(t *testing.T) string {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "relsig-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--homedir", home, "--kill", "all").Run()
		_ = os.RemoveAll(home)
	})
	for name, body := range map[string]string{
		"gpg-agent.conf": "allow-loopback-pinentry\ndefault-cache-ttl 0\nmax-cache-ttl 0\n",
		"gpg.conf":       "pinentry-mode loopback\n",
	} {
		if err := os.WriteFile(filepath.Join(home, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func gpgIn(t *testing.T, home string, args ...string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command("gpg", append([]string{"--homedir", home, "--batch"}, args...)...)
	return cmd.CombinedOutput()
}

var fprRe = regexp.MustCompile(`(?m)^fpr:+([0-9A-F]{40}):`)

// fingerprints lists the fpr records of a --with-colons listing in order.
func fingerprints(out []byte) []string {
	var fprs []string
	for _, m := range fprRe.FindAllSubmatch(out, -1) {
		fprs = append(fprs, string(m[1]))
	}
	return fprs
}

// testKey is a throwaway key made in its own home.
type testKey struct {
	home    string // holds the full secret key
	primary string
	signer  string // the subkey that signs, or the primary for a one-key key
}

// genKey makes a throwaway key. With releaseShape the primary can only
// certify and a separate subkey signs, as the real release key does;
// otherwise one primary does both. With signing false there is no key that
// can sign at all.
func genKey(t *testing.T, uid, pass string, releaseShape, signing bool) testKey {
	t.Helper()
	home := gpgHome(t)
	usage := "sign"
	if releaseShape || !signing {
		usage = "cert"
	}
	if out, err := gpgIn(t, home, "--passphrase", pass, "--quick-gen-key", uid, "ed25519",
		usage, "1d"); err != nil {
		t.Fatalf("gpg --quick-gen-key: %v\n%s", err, out)
	}
	out, err := gpgIn(t, home, "--with-colons", "--list-secret-keys")
	if err != nil {
		t.Fatalf("gpg --list-secret-keys: %v\n%s", err, out)
	}
	k := testKey{home: home, primary: fingerprints(out)[0]}
	k.signer = k.primary
	if releaseShape && signing {
		if out, err := gpgIn(t, home, "--passphrase", pass, "--quick-add-key", k.primary,
			"ed25519", "sign", "1d"); err != nil {
			t.Fatalf("gpg --quick-add-key: %v\n%s", err, out)
		}
		out, _ := gpgIn(t, home, "--with-colons", "--list-secret-keys")
		k.signer = fingerprints(out)[1]
	}
	return k
}

// exportPublic is the key's public half, as KEYS carries it.
func (k testKey) exportPublic(t *testing.T) []byte {
	t.Helper()
	out, err := exec.Command("gpg", "--homedir", k.home, "--batch", "--armor", "--export",
		k.primary).Output()
	if err != nil {
		t.Fatalf("gpg --export: %v", err)
	}
	return out
}

// importInto imports the key's secret into home: the subkeys only, with the
// primary stubbed, when subkeysOnly is set (how GPG_PRIVATE_KEY is exported).
func (k testKey) importInto(t *testing.T, home, pass string, subkeysOnly bool) {
	t.Helper()
	verb := "--export-secret-keys"
	if subkeysOnly {
		verb = "--export-secret-subkeys"
	}
	sec, err := exec.Command("gpg", "--homedir", k.home, "--batch", "--pinentry-mode",
		"loopback", "--passphrase", pass, "--armor", verb, k.primary).Output()
	if err != nil {
		t.Fatalf("gpg %s: %v", verb, err)
	}
	f := filepath.Join(home, "secret.asc")
	if err := os.WriteFile(f, sec, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := gpgIn(t, home, "--import", f); err != nil {
		t.Fatalf("gpg --import: %v\n%s", err, out)
	}
	_ = os.Remove(f)
}

func writeKeys(t *testing.T, dir string, keys ...testKey) string {
	t.Helper()
	var all []byte
	for _, k := range keys {
		all = append(all, k.exportPublic(t)...)
	}
	p := filepath.Join(dir, "KEYS")
	if err := os.WriteFile(p, all, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// runScript runs one packaging script with GNUPGHOME=home. pass nil leaves
// GPG_PASSPHRASE unset. It returns stdout and stderr apart.
func runScript(t *testing.T, home string, pass *string, script string, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{filepath.Join(appDir(t), "packaging", script)}, args...)...)
	env := []string{"GNUPGHOME=" + home, "PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	if pass != nil {
		env = append(env, "GPG_PASSPHRASE="+*pass)
	}
	cmd.Env = env
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// buildDeb makes a small real .deb with dpkg-deb when it is installed, and
// otherwise a file of fixed bytes: the signer signs whatever file it is given.
func buildDeb(t *testing.T, dir, name string) string {
	t.Helper()
	out := filepath.Join(dir, name)
	if _, err := exec.LookPath("dpkg-deb"); err == nil {
		root := t.TempDir()
		for rel, body := range map[string]string{
			"DEBIAN/control": "Package: relsig-fixture\nVersion: 1.0\nArchitecture: all\n" +
				"Maintainer: test <test@example.invalid>\nDescription: fixture\n",
			"usr/share/relsig-fixture/" + name + ".txt": name + "\n",
		} {
			p := filepath.Join(root, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if b, err := exec.Command("dpkg-deb", "--root-owner-group", "-b", root, out).CombinedOutput(); err != nil {
			t.Fatalf("dpkg-deb -b: %v\n%s", err, b)
		}
		return out
	}
	if err := os.WriteFile(out, []byte("not really a deb: "+name+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return out
}

// verifyAsOperator checks one file the way the runbook tells an operator to:
// a fresh keyring holding only KEYS, then `gpg --verify <file>.asc <file>`.
// Returns the signing and primary fingerprints of a good signature, or ""
// with gpg's output.
func verifyAsOperator(t *testing.T, keys, file string) (string, string, string) {
	t.Helper()
	op := gpgHome(t)
	if out, err := gpgIn(t, op, "--import", keys); err != nil {
		t.Fatalf("gpg --import KEYS: %v\n%s", err, out)
	}
	out, err := gpgIn(t, op, "--status-fd", "1", "--verify", file+".asc", file)
	if err != nil {
		return "", "", string(out)
	}
	m := regexp.MustCompile(`(?m)^\[GNUPG:\] VALIDSIG ([0-9A-F]{40}) .* ([0-9A-F]{40})$`).FindSubmatch(out)
	if m == nil {
		return "", "", string(out)
	}
	return string(m[1]), string(m[2]), string(out)
}

const testPass = "throwaway passphrase"

// ciHome is a home shaped like the release job after its import: the
// release-shaped key's signing subkey, with the primary stubbed.
func ciHome(t *testing.T, k testKey) string {
	t.Helper()
	home := gpgHome(t)
	k.importInto(t, home, testPass, true)
	return home
}

// @ac AC-30
// AC-30: the resolver prints the one imported release key's fingerprint, for
// the release shape and for a KEYS that holds a second primary.
func TestReleaseSigningKey_PinsTheOneImportedKey(t *testing.T) {
	t.Run("release-package-build/AC-30", func(t *testing.T) {
		haveTool(t, "gpg")
		haveTool(t, "gpgconf")
		rel := genKey(t, "Release Shape <rel@example.invalid>", testPass, true, true)
		other := genKey(t, "Other Primary <other@example.invalid>", testPass, false, true)
		home := ciHome(t, rel)
		list, _ := gpgIn(t, home, "--with-colons", "--list-secret-keys")
		if !regexp.MustCompile(`(?m)^sec:[^\n]*:#:`).Match(list) {
			t.Fatalf("the CI-shaped import did not stub the primary:\n%s", list)
		}
		for name, keys := range map[string]string{
			"KEYS holds only the release key":     writeKeys(t, t.TempDir(), rel),
			"KEYS holds a second primary as well": writeKeys(t, t.TempDir(), other, rel),
		} {
			t.Run(name, func(t *testing.T) {
				out, errOut, err := runScript(t, home, nil, "release-signing-key.sh", keys)
				if err != nil {
					t.Fatalf("release-signing-key.sh: %v\n%s", err, errOut)
				}
				if strings.TrimSpace(out) != rel.primary {
					t.Errorf("printed %q, want the primary %s", out, rel.primary)
				}
			})
		}
	})
}

// @ac AC-30
// AC-30: the resolver refuses every keyring it cannot pin, printing nothing,
// and a step built the way release.yml builds it then writes no signature.
func TestReleaseSigningKey_RefusesAndNothingIsSigned(t *testing.T) {
	t.Run("release-package-build/AC-30", func(t *testing.T) {
		haveTool(t, "gpg")
		haveTool(t, "gpgconf")
		rel := genKey(t, "Release Shape <rel@example.invalid>", testPass, true, true)
		other := genKey(t, "Other Primary <other@example.invalid>", testPass, false, true)
		certOnly := genKey(t, "Certify Only <cert@example.invalid>", testPass, true, false)
		stubSigner := genKey(t, "Stub Signer <stub@example.invalid>", testPass, false, true)
		if out, err := gpgIn(t, stubSigner.home, "--passphrase", testPass, "--quick-add-key",
			stubSigner.primary, "cv25519", "encr", "1d"); err != nil {
			t.Fatalf("gpg --quick-add-key (encrypt): %v\n%s", err, out)
		}
		// A release-shaped key whose only signing subkey expired: made under a
		// faked clock in 2020, a certify-only primary that never expires and a
		// signing subkey that lived one day.
		expired := testKey{home: gpgHome(t)}
		if out, err := gpgIn(t, expired.home, "--faked-system-time", "20200101T000000",
			"--passphrase", testPass, "--quick-gen-key", "Expired Subkey <exp@example.invalid>",
			"ed25519", "cert", "never"); err != nil {
			t.Fatalf("gpg --quick-gen-key (expired): %v\n%s", err, out)
		}
		listed, _ := gpgIn(t, expired.home, "--with-colons", "--list-secret-keys")
		expired.primary = fingerprints(listed)[0]
		if out, err := gpgIn(t, expired.home, "--faked-system-time", "20200101T000000",
			"--passphrase", testPass, "--quick-add-key", expired.primary, "ed25519", "sign",
			"1d"); err != nil {
			t.Fatalf("gpg --quick-add-key (expired): %v\n%s", err, out)
		}

		two := ciHome(t, rel)
		other.importInto(t, two, testPass, false)
		cases := []struct {
			name, home, keys, says string
		}{
			{"two secret primaries", two, writeKeys(t, t.TempDir(), rel, other),
				"2 secret primary keys"},
			{"no secret key", gpgHome(t), writeKeys(t, t.TempDir(), rel), "0 secret primary keys"},
			{"a key that is not in KEYS", ciHome(t, rel), writeKeys(t, t.TempDir(), other),
				"is not a primary key in"},
			{"no key that can sign", func() string {
				h := gpgHome(t)
				certOnly.importInto(t, h, testPass, false)
				return h
			}(), writeKeys(t, t.TempDir(), certOnly), "no usable signing key"},
			{"an unreadable KEYS", ciHome(t, rel), filepath.Join(t.TempDir(), "absent"),
				"cannot read"},
			// A key whose primary signs and whose only subkey encrypts,
			// exported the way GPG_PRIVATE_KEY is: the signing part is the
			// stubbed primary, so nothing here can sign.
			{"a stubbed primary as the only signer", ciHome(t, stubSigner),
				writeKeys(t, t.TempDir(), stubSigner), "no usable signing key"},
			{"an expired signing subkey", ciHome(t, expired), writeKeys(t, t.TempDir(), expired),
				"no usable signing key"},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				out, errOut, err := runScript(t, c.home, nil, "release-signing-key.sh", c.keys)
				if err == nil {
					t.Fatalf("release-signing-key.sh exited 0 and printed %q", out)
				}
				if out != "" {
					t.Errorf("printed %q on a refusal; a caller could sign with it", out)
				}
				if !strings.Contains(errOut, c.says) {
					t.Errorf("stderr does not say %q:\n%s", c.says, errOut)
				}
				// The DEB step's own commands: nothing is signed.
				dist := t.TempDir()
				deb := buildDeb(t, dist, "openwatch_1.2.3_amd64.deb")
				step := exec.Command("bash", "-c", `set -euo pipefail
fpr="$(bash "$1/packaging/release-signing-key.sh" "$2")"
bash "$1/packaging/sign-detached.sh" "$fpr" "$3"`, "step", appDir(t), c.keys, deb)
				step.Env = []string{"GNUPGHOME=" + c.home, "PATH=" + os.Getenv("PATH"),
					"GPG_PASSPHRASE=" + testPass}
				b, err := step.CombinedOutput()
				if err == nil {
					t.Errorf("the step exited 0:\n%s", b)
				}
				if strings.Contains(string(b), "sign-detached:") || strings.Contains(string(b), "signed ") {
					t.Errorf("the step reached the signer after the resolver refused:\n%s", b)
				}
				if _, err := os.Stat(deb + ".asc"); err == nil {
					t.Error("a signature was written although the key was refused")
				}
			})
		}
	})
}

// @ac AC-29
// AC-29: sign-detached.sh writes an armored signature per file with the
// pinned key's signing subkey, which an operator verifies with KEYS; a
// changed package or a swapped signature fails.
func TestSignDetached_SignsVerifiablyWithThePinnedKey(t *testing.T) {
	t.Run("release-package-build/AC-29", func(t *testing.T) {
		haveTool(t, "gpg")
		haveTool(t, "gpgconf")
		rel := genKey(t, "Release Shape <rel@example.invalid>", testPass, true, true)
		home := ciHome(t, rel)
		keys := writeKeys(t, t.TempDir(), rel)
		pass := testPass

		dist := t.TempDir()
		amd := buildDeb(t, dist, "openwatch_1.2.3_amd64.deb")
		arm := buildDeb(t, dist, "openwatch_1.2.3_arm64.deb")
		all := buildDeb(t, dist, "kensa-rules_4.5.6_all.deb")
		sums := filepath.Join(dist, "SHA256SUMS")
		if err := os.WriteFile(sums, []byte("0000  x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, errOut, err := runScript(t, home, &pass, "sign-detached.sh", rel.primary, amd, arm, all)
		if err != nil {
			t.Fatalf("sign-detached.sh: %v\n%s", err, errOut)
		}
		if _, errOut, err := runScript(t, home, &pass, "sign-detached.sh", rel.primary, sums); err != nil {
			t.Fatalf("sign-detached.sh SHA256SUMS: %v\n%s", err, errOut)
		}
		for _, f := range []string{amd, arm, all, sums} {
			asc, err := os.ReadFile(f + ".asc")
			if err != nil {
				t.Fatalf("no signature for %s: %v", filepath.Base(f), err)
			}
			if !strings.HasPrefix(string(asc), "-----BEGIN PGP SIGNATURE-----") {
				t.Errorf("%s.asc is not ASCII-armored", filepath.Base(f))
			}
			signer, primary, text := verifyAsOperator(t, keys, f)
			if signer != rel.signer || primary != rel.primary {
				t.Errorf("%s: signer %q primary %q, want the subkey %s of %s\n%s",
					filepath.Base(f), signer, primary, rel.signer, rel.primary, text)
			}
		}

		// A package changed after signing fails, and so does a signature
		// moved onto another package.
		fh, err := os.OpenFile(arm, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fh.Write([]byte{0})
		_ = fh.Close()
		if s, _, text := verifyAsOperator(t, keys, arm); s != "" || !strings.Contains(text, "BADSIG") {
			t.Errorf("a changed DEB verified (%q):\n%s", s, text)
		}
		swapped, _ := os.ReadFile(all + ".asc")
		if err := os.WriteFile(amd+".asc", swapped, 0o644); err != nil {
			t.Fatal(err)
		}
		if s, _, text := verifyAsOperator(t, keys, amd); s != "" || !strings.Contains(text, "BADSIG") {
			t.Errorf("another DEB's signature verified (%q):\n%s", s, text)
		}
	})
}

// @ac AC-29
// AC-29: sign-detached.sh fails closed and leaves no signature behind, not
// even one from an earlier run.
func TestSignDetached_FailsClosed(t *testing.T) {
	t.Run("release-package-build/AC-29", func(t *testing.T) {
		haveTool(t, "gpg")
		haveTool(t, "gpgconf")
		rel := genKey(t, "Release Shape <rel@example.invalid>", testPass, true, true)
		other := genKey(t, "Other Primary <other@example.invalid>", testPass, false, true)
		home := ciHome(t, rel)
		right, wrong := testPass, "wrong"

		cases := []struct {
			name  string
			pass  *string
			fpr   string
			files func(dist string) []string
			says  string
		}{
			{"a short key id", &right, rel.primary[24:], nil, "40-hex fingerprint"},
			{"no file", &right, rel.primary, func(string) []string { return nil }, "no file to sign"},
			{"an unmatched glob", &right, rel.primary,
				func(d string) []string { return []string{filepath.Join(d, "*.deb")} }, "does not exist"},
			{"GPG_PASSPHRASE unset", nil, rel.primary, nil, "GPG_PASSPHRASE is not set"},
			{"a wrong passphrase", &wrong, rel.primary, nil, ""},
			{"a key not in the keyring", &right, other.primary, nil, ""},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				dist := t.TempDir()
				deb := buildDeb(t, dist, "openwatch_1.2.3_amd64.deb")
				if err := os.WriteFile(deb+".asc", []byte("stale\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				files := []string{deb}
				if c.files != nil {
					files = c.files(dist)
				}
				_, errOut, err := runScript(t, home, c.pass, "sign-detached.sh",
					append([]string{c.fpr}, files...)...)
				if err == nil {
					t.Fatalf("sign-detached.sh exited 0 with %s", c.name)
				}
				if c.says != "" && !strings.Contains(errOut, c.says) {
					t.Errorf("stderr does not say %q:\n%s", c.says, errOut)
				}
				if c.files == nil {
					if _, err := os.Stat(deb + ".asc"); err == nil {
						t.Errorf("a signature was left behind after %s:\n%s", c.name, errOut)
					}
				}
			})
		}
	})
}

// buildRPM makes a small noarch RPM with rpmbuild.
func buildRPM(t *testing.T, dir string) string {
	t.Helper()
	top := t.TempDir()
	spec := filepath.Join(top, "relsig.spec")
	if err := os.WriteFile(spec, []byte("Name: relsig-fixture\nVersion: 1.0\nRelease: 1\n"+
		"Summary: fixture\nLicense: MIT\nBuildArch: noarch\n\n%description\nfixture\n\n%files\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	if b, err := exec.Command("rpmbuild", "--quiet", "-bb", "--define", "_topdir "+top, spec).CombinedOutput(); err != nil {
		t.Fatalf("rpmbuild: %v\n%s", err, b)
	}
	built := filepath.Join(top, "RPMS", "noarch", "relsig-fixture-1.0-1.noarch.rpm")
	out := filepath.Join(dir, filepath.Base(built))
	b, err := os.ReadFile(built)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return out
}

// @ac AC-30
// AC-30: sign-rpms.sh signs each RPM header with the pinned key's signing
// subkey and checks it against KEYS alone; an RPM signed by a key outside
// KEYS fails the check.
func TestSignRPMs_SignsWithThePinnedKeyAndChecksAgainstKEYS(t *testing.T) {
	t.Run("release-package-build/AC-30", func(t *testing.T) {
		haveTool(t, "gpg")
		haveTool(t, "gpgconf")
		haveTool(t, "rpmbuild")
		haveTool(t, "rpmsign")
		rel := genKey(t, "Release Shape <rel@example.invalid>", testPass, true, true)
		other := genKey(t, "Other Primary <other@example.invalid>", testPass, false, true)
		home := ciHome(t, rel)
		pass := testPass

		dist := t.TempDir()
		rpm := buildRPM(t, dist)
		keys := writeKeys(t, t.TempDir(), rel)
		out, errOut, err := runScript(t, home, &pass, "sign-rpms.sh", rel.primary, keys, rpm)
		if err != nil {
			t.Fatalf("sign-rpms.sh: %v\n%s%s", err, out, errOut)
		}
		if !strings.Contains(out, "signatures OK") {
			t.Errorf("sign-rpms.sh did not report its rpm -K check:\n%s", out)
		}
		info, err := exec.Command("rpm", "-qpi", rpm).CombinedOutput()
		if err != nil {
			t.Fatalf("rpm -qpi: %v\n%s", err, info)
		}
		// rpm 4.18 prints the signature on the "Signature :" line; rpm 6.0
		// prints it on the next one.
		sig := regexp.MustCompile(`(?m)^Signature\s*:[ \t]*\n?[ \t]*[^\n]*Key ID ([0-9a-f]{16})$`).FindSubmatch(info)
		if sig == nil || strings.ToUpper(string(sig[1])) != rel.signer[24:] {
			t.Errorf("the RPM signature line names %q, want the signing subkey %s\n%s", sig, rel.signer[24:], info)
		}

		// A KEYS without the signing key: the check after signing fails.
		rpm2 := buildRPM(t, t.TempDir())
		wrongKeys := writeKeys(t, t.TempDir(), other)
		if _, errOut, err := runScript(t, home, &pass, "sign-rpms.sh", rel.primary, wrongKeys, rpm2); err == nil {
			t.Errorf("sign-rpms.sh passed an RPM signed by a key outside KEYS:\n%s", errOut)
		}

		// An rpmsign that exits 0 and signs nothing: the check after it must
		// still refuse the unsigned RPM, which rpm -K passes as "digests OK".
		fake := t.TempDir()
		if err := os.WriteFile(filepath.Join(fake, "rpmsign"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		unsigned := buildRPM(t, t.TempDir())
		cmd := exec.Command("bash", filepath.Join(appDir(t), "packaging", "sign-rpms.sh"), rel.primary, keys, unsigned)
		cmd.Env = []string{"GNUPGHOME=" + home, "PATH=" + fake + ":" + os.Getenv("PATH"),
			"HOME=" + os.Getenv("HOME"), "GPG_PASSPHRASE=" + pass}
		if b, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(b), "does not report a signature") {
			t.Errorf("sign-rpms.sh accepted an RPM that rpmsign left unsigned: %v\n%s", err, b)
		}

		for name, args := range map[string][]string{
			"a short key id": {rel.primary[24:], keys, rpm},
			"no RPM":         {rel.primary, keys},
			"a missing RPM":  {rel.primary, keys, filepath.Join(dist, "*.rpm.absent")},
			"an absent KEYS": {rel.primary, filepath.Join(dist, "absent"), rpm},
		} {
			if _, _, err := runScript(t, home, &pass, "sign-rpms.sh", args...); err == nil {
				t.Errorf("sign-rpms.sh exited 0 with %s", name)
			}
		}
		if _, errOut, err := runScript(t, home, nil, "sign-rpms.sh", rel.primary, keys, rpm); err == nil ||
			!strings.Contains(errOut, "GPG_PASSPHRASE is not set") {
			t.Errorf("sign-rpms.sh with GPG_PASSPHRASE unset: %v\n%s", err, errOut)
		}
	})
}

// stepBody returns the YAML of one named step, up to the next step.
func stepBody(t *testing.T, wf, name string) string {
	t.Helper()
	i := strings.Index(wf, "- name: "+name+"\n")
	if i < 0 {
		t.Fatalf("release.yml has no step %q", name)
	}
	rest := wf[i+len("- name: "):]
	if j := strings.Index(rest, "\n      - name: "); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// @ac AC-29
// AC-29: release.yml signs the RPMs, then the DEBs, before the SBOMs
// and checksums, and SHA256SUMS after them; every signing step resolves the
// one pinned key and signs with it through the scripts; a tag push with no
// key fails, so a tag never publishes an unsigned package.
func TestReleaseWorkflow_SignsEverythingWithThePinnedKey(t *testing.T) {
	t.Run("release-package-build/AC-29", func(t *testing.T) {
		wf := readAppFile(t, ".github/workflows/release.yml")
		idx := func(s string) int {
			i := strings.Index(wf, s)
			if i < 0 {
				t.Fatalf("release.yml has no %q", s)
			}
			return i
		}
		detect := idx("- name: Detect signing keys")
		rpms := idx("- name: GPG-sign RPMs")
		debs := idx("- name: GPG-sign DEBs")
		sboms := idx("- name: Generate CycloneDX SBOMs")
		sums := idx("- name: Checksums")
		sumsSig := idx("- name: GPG-sign checksums")
		if !(detect < rpms && rpms < debs && debs < sboms && sboms < sums && sums < sumsSig) {
			t.Errorf("release.yml step order: Detect %d, RPMs %d, DEBs %d, SBOMs %d, Checksums %d, "+
				"checksum signature %d", detect, rpms, debs, sboms, sums, sumsSig)
		}
		if !strings.Contains(wf[rpms:debs], "# Spec: release-package-build C-18.") {
			t.Error("the comment above GPG-sign DEBs does not cite release-package-build C-18")
		}
		if !strings.Contains(wf[detect:rpms], "# Spec: release-package-build C-19 (CP bugs/OW-OW-145).") {
			t.Error("the comment above GPG-sign RPMs does not cite release-package-build C-19")
		}

		resolve := `fpr="$(bash packaging/release-signing-key.sh security/KEYS)"`
		for name, signs := range map[string]string{
			"GPG-sign RPMs":      `bash packaging/sign-rpms.sh "$fpr" security/KEYS dist/*.rpm`,
			"GPG-sign DEBs":      `bash packaging/sign-detached.sh "$fpr" dist/*.deb`,
			"GPG-sign checksums": `bash packaging/sign-detached.sh "$fpr" dist/SHA256SUMS`,
		} {
			step := stepBody(t, wf, name)
			if !strings.Contains(step, "if: steps.keys.outputs.gpg == 'true'") {
				t.Errorf("%s is not gated on the detected key", name)
			}
			if !strings.Contains(step, "set -euo pipefail") {
				t.Errorf("%s does not stop on the resolver's refusal (no set -euo pipefail)", name)
			}
			r, s := strings.Index(step, resolve), strings.Index(step, signs)
			if r < 0 || s < 0 || r > s {
				t.Errorf("%s does not resolve the key and then run %s:\n%s", name, signs, step)
			}
		}
		// Nothing in release.yml signs on its own any more: no inline gpg
		// signature, no rpmsign, no first-secret-key selection.
		for _, banned := range []string{"--detach-sign", "rpmsign --", "-sbo", ".rpmmacros",
			`awk -F: '/^sec/`, "--local-user", "_gpg_name"} {
			if strings.Contains(wf, banned) {
				t.Errorf("release.yml still signs inline (%q); every signature goes through "+
					"the pinned-key scripts", banned)
			}
		}

		// The key check that makes every signing step fail closed on a tag.
		if !regexp.MustCompile(`elif \[ "\$GITHUB_EVENT_NAME" = "push" \]; then[\s\S]*?exit 1`).MatchString(wf[detect:rpms]) {
			t.Error("Detect signing keys no longer fails a tag push that has no GPG_PRIVATE_KEY")
		}
		if !regexp.MustCompile(`sha256sum [^\n]*\*\.deb\.asc[^\n]*> SHA256SUMS`).MatchString(wf) {
			t.Error("SHA256SUMS does not list the DEB signatures")
		}
		if !strings.Contains(wf[sums:sumsSig], "shopt -s nullglob") {
			t.Error("the Checksums step has no nullglob; an unsigned trial would hash a literal *.deb.asc")
		}
		if !regexp.MustCompile(`(?m)^\s+dist/\*\.deb\.asc$`).MatchString(wf) {
			t.Error("release.yml does not upload dist/*.deb.asc")
		}
		for _, stale := range []string{"DEBs are NOT signed", "dpkg-sig --sign", "debsigs --sign"} {
			if strings.Contains(wf, stale) {
				t.Errorf("release.yml still contains %q", stale)
			}
		}
	})
}
