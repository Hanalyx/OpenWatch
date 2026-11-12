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

// DEB signing (release-package-build C-18). packaging/sign-debs.sh is the
// command release.yml runs; these tests run it for real with a throwaway key
// in a throwaway GnuPG home, and read release.yml for where it runs. The real
// release key is never used here.

// gpgHome makes a throwaway GnuPG home under /tmp (gpg-agent's socket path
// must stay short) and stops its daemons at cleanup.
func gpgHome(t *testing.T) string {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "debsig-")
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

// genKey makes a signing key with the given passphrase; returns its
// fingerprint.
func genKey(t *testing.T, home, uid, pass string) string {
	t.Helper()
	if out, err := gpgIn(t, home, "--passphrase", pass, "--quick-gen-key", uid, "ed25519",
		"sign", "1d"); err != nil {
		t.Fatalf("gpg --quick-gen-key: %v\n%s", err, out)
	}
	out, err := gpgIn(t, home, "--with-colons", "--list-secret-keys", uid)
	if err != nil {
		t.Fatalf("gpg --list-secret-keys: %v\n%s", err, out)
	}
	m := regexp.MustCompile(`(?m)^fpr:+([0-9A-F]{40}):`).FindSubmatch(out)
	if m == nil {
		t.Fatalf("no fingerprint for %s in:\n%s", uid, out)
	}
	return string(m[1])
}

// buildDeb makes a small real .deb with dpkg-deb when it is installed, and
// otherwise a file of fixed bytes: the script signs whatever *.deb it finds.
func buildDeb(t *testing.T, dir, name string) string {
	t.Helper()
	out := filepath.Join(dir, name)
	if _, err := exec.LookPath("dpkg-deb"); err == nil {
		root := t.TempDir()
		for rel, body := range map[string]string{
			"DEBIAN/control": "Package: debsig-fixture\nVersion: 1.0\nArchitecture: all\n" +
				"Maintainer: test <test@example.invalid>\nDescription: fixture\n",
			"usr/share/debsig-fixture/" + name + ".txt": name + "\n",
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

// signDebs runs packaging/sign-debs.sh on dir with GNUPGHOME=home. pass nil
// leaves GPG_PASSPHRASE unset.
func signDebs(t *testing.T, home, dir string, pass *string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", filepath.Join(appDir(t), "packaging", "sign-debs.sh"), dir)
	env := []string{"GNUPGHOME=" + home, "PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	if pass != nil {
		env = append(env, "GPG_PASSPHRASE="+*pass)
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// verifyAsOperator checks one package the way the runbook tells an
// operator to: a fresh keyring holding only the exported public key, then
// `gpg --verify <deb>.asc <deb>`. Returns the primary fingerprint of a good
// signature, or "" with gpg's output.
func verifyAsOperator(t *testing.T, keys []byte, deb string) (string, string) {
	t.Helper()
	op := gpgHome(t)
	kf := filepath.Join(op, "KEYS")
	if err := os.WriteFile(kf, keys, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := gpgIn(t, op, "--import", kf); err != nil {
		t.Fatalf("gpg --import KEYS: %v\n%s", err, out)
	}
	out, err := gpgIn(t, op, "--status-fd", "1", "--verify", deb+".asc", deb)
	if err != nil {
		return "", string(out)
	}
	m := regexp.MustCompile(`(?m)^\[GNUPG:\] VALIDSIG .* ([0-9A-F]{40})$`).FindSubmatch(out)
	if m == nil {
		return "", string(out)
	}
	return string(m[1]), string(out)
}

// @ac AC-29
// AC-29: sign-debs.sh writes a detached, armored signature per DEB that an
// operator verifies with KEYS; a changed package or a swapped signature fails.
func TestSignDebs_SignsEachDebVerifiablyWithKEYS(t *testing.T) {
	t.Run("release-package-build/AC-29", func(t *testing.T) {
		haveTool(t, "gpg")
		haveTool(t, "gpgconf")
		home := gpgHome(t)
		pass := "throwaway passphrase"
		fpr := genKey(t, home, "DEB Signing Test <debsig@example.invalid>", pass)
		keys, err := gpgIn(t, home, "--armor", "--export", fpr)
		if err != nil {
			t.Fatalf("gpg --export: %v\n%s", err, keys)
		}

		dist := t.TempDir()
		amd := buildDeb(t, dist, "openwatch_1.2.3_amd64.deb")
		arm := buildDeb(t, dist, "openwatch_1.2.3_arm64.deb")
		all := buildDeb(t, dist, "kensa-rules_4.5.6_all.deb")
		rpm := filepath.Join(dist, "openwatch-1.2.3-1.x86_64.rpm")
		if err := os.WriteFile(rpm, []byte("rpm\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		out, err := signDebs(t, home, dist, &pass)
		if err != nil {
			t.Fatalf("sign-debs.sh: %v\n%s", err, out)
		}
		for _, deb := range []string{amd, arm, all} {
			asc, err := os.ReadFile(deb + ".asc")
			if err != nil {
				t.Fatalf("no signature for %s: %v\n%s", filepath.Base(deb), err, out)
			}
			if !strings.HasPrefix(string(asc), "-----BEGIN PGP SIGNATURE-----") {
				t.Errorf("%s.asc is not ASCII-armored", filepath.Base(deb))
			}
			if got, text := verifyAsOperator(t, keys, deb); got != fpr {
				t.Errorf("%s: operator verification gave %q, want a good signature by %s\n%s",
					filepath.Base(deb), got, fpr, text)
			}
		}
		if _, err := os.Stat(rpm + ".asc"); err == nil {
			t.Error("sign-debs.sh signed an RPM; the RPMs are signed in their header by rpmsign")
		}

		// A package changed after signing fails, and so does a signature
		// moved onto another package.
		f, err := os.OpenFile(arm, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write([]byte{0})
		_ = f.Close()
		if got, text := verifyAsOperator(t, keys, arm); got != "" || !strings.Contains(text, "BADSIG") {
			t.Errorf("a changed DEB verified (%q):\n%s", got, text)
		}
		swapped, _ := os.ReadFile(all + ".asc")
		if err := os.WriteFile(amd+".asc", swapped, 0o644); err != nil {
			t.Fatal(err)
		}
		if got, text := verifyAsOperator(t, keys, amd); got != "" || !strings.Contains(text, "BADSIG") {
			t.Errorf("another DEB's signature verified (%q):\n%s", got, text)
		}
	})
}

// @ac AC-29
// AC-29: sign-debs.sh fails closed and leaves no signature behind.
func TestSignDebs_FailsClosed(t *testing.T) {
	t.Run("release-package-build/AC-29", func(t *testing.T) {
		haveTool(t, "gpg")
		haveTool(t, "gpgconf")
		pass := "right"
		wrong := "wrong"
		empty := ""

		withKey := gpgHome(t)
		genKey(t, withKey, "DEB Signing Test <debsig@example.invalid>", pass)
		noKey := gpgHome(t)

		cases := []struct {
			name    string
			home    string
			pass    *string
			noDebs  bool
			message string
		}{
			{"no .deb to sign", withKey, &pass, true, "no .deb"},
			{"no secret key", noKey, &empty, false, "no secret key"},
			{"GPG_PASSPHRASE unset", withKey, nil, false, "GPG_PASSPHRASE is not set"},
			{"wrong passphrase", withKey, &wrong, false, ""},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				dist := t.TempDir()
				var deb string
				if !c.noDebs {
					deb = buildDeb(t, dist, "openwatch_1.2.3_amd64.deb")
				}
				// A signature from an earlier run must not survive a failure.
				stale := filepath.Join(dist, "openwatch_1.2.2_amd64.deb.asc")
				if err := os.WriteFile(stale, []byte("stale\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				if deb != "" {
					if err := os.WriteFile(deb+".asc", []byte("stale\n"), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				out, err := signDebs(t, c.home, dist, c.pass)
				if err == nil {
					t.Fatalf("sign-debs.sh exited 0 with %s:\n%s", c.name, out)
				}
				if c.message != "" && !strings.Contains(out, c.message) {
					t.Errorf("output does not say %q:\n%s", c.message, out)
				}
				left := []string{stale}
				if deb != "" {
					left = append(left, deb+".asc")
				}
				for _, asc := range left {
					if _, err := os.Stat(asc); err == nil {
						t.Errorf("%s was left behind after a failure:\n%s", filepath.Base(asc), out)
					}
				}
			})
		}
	})
}

// @ac AC-29
// AC-29: release.yml signs the DEBs after the RPMs and before the SBOMs and
// checksums, lists and uploads each signature, and refuses a tag push with no
// signing key, so a tag never publishes an unsigned DEB.
func TestReleaseWorkflow_SignsDebsBeforeChecksums(t *testing.T) {
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
		if !(detect < rpms && rpms < debs && debs < sboms && sboms < sums) {
			t.Errorf("release.yml step order: Detect %d, RPMs %d, DEBs %d, SBOMs %d, Checksums %d; "+
				"the DEBs must be signed after the RPMs and before the SBOMs and SHA256SUMS",
				detect, rpms, debs, sboms, sums)
		}
		// The comment block above the step names the constraint it implements.
		if !strings.Contains(wf[rpms:debs], "# Spec: release-package-build C-18.") {
			t.Error("the comment above GPG-sign DEBs does not cite release-package-build C-18")
		}
		step := wf[debs:sboms]
		if !strings.Contains(step, "if: steps.keys.outputs.gpg == 'true'") {
			t.Error("GPG-sign DEBs is not gated on the detected key the way GPG-sign RPMs is")
		}
		if !strings.Contains(step, "run: bash packaging/sign-debs.sh dist") {
			t.Error("GPG-sign DEBs does not run packaging/sign-debs.sh on dist")
		}
		// The key check that makes both signing steps fail closed on a tag.
		keys := wf[detect:rpms]
		if !regexp.MustCompile(`elif \[ "\$GITHUB_EVENT_NAME" = "push" \]; then[\s\S]*?exit 1`).MatchString(keys) {
			t.Error("Detect signing keys no longer fails a tag push that has no GPG_PRIVATE_KEY")
		}
		if !regexp.MustCompile(`sha256sum [^\n]*\*\.deb\.asc[^\n]*> SHA256SUMS`).MatchString(wf) {
			t.Error("SHA256SUMS does not list the DEB signatures")
		}
		if !strings.Contains(wf[sums:], "shopt -s nullglob") {
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
