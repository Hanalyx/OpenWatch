#!/usr/bin/env python3
"""Tests for the release asset verifier.

    python3 -S scripts/test_release_assets.py

Real: a git repository with an annotated tag on a bare origin, SHA256SUMS and
its signature (a throwaway GnuPG home), the hashing, the SBOM and manifest
binding, and the capture of every command. Faked, because the gates job has
neither Go nor package tools and govulncheck needs a network database: rpm,
rpm2cpio, cpio, dpkg-deb, go, govulncheck and gh, each a small shell script.
A fake package is a tar archive; its "binary" holds the text `go version -m`
would print. The real tools are exercised by running the verifier against a
published release (see the release-prep skill).

Each negative case changes one thing and asserts exactly which checks fail.
One class per criterion of spec release-asset-verification.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

_here = Path(__file__).resolve().parent


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, _here / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ra = _load("release_assets", "release_assets.py")
Keys = _load("test_release_tag", "test_release_tag.py").Keys

VERSION = "0.9.0"
TAG = "v" + VERSION
KENSA = "0.10.0"
NOTICES = b"# Third-party notices\n\nfixture\n"
GOMOD = ("module github.com/Hanalyx/openwatch\n\ngo 1.26.9\n\nrequire (\n"
         "\tgithub.com/Hanalyx/kensa v%s\n\tgolang.org/x/net v0.60.0\n)\n" % KENSA)

FAKES = {
    "rpm": '#!/bin/sh\nif [ "$3" = "--import" ]; then exit 0; fi\n'
           'b=$(basename "$4")\nif grep -qx "$b" "$ASSETS_FAKE/rpm-bad" 2>/dev/null; then\n'
           '  echo "$4: digests SIGNATURES NOT OK"; exit 1; fi\necho "$4: digests signatures OK"\n',
    "rpm2cpio": '#!/bin/sh\nexec cat "$1"\n',
    "cpio": '#!/bin/sh\nexec tar -xf -\n',
    "dpkg-deb": '#!/bin/sh\nexec tar -xf "$2" -C "$3"\n',
    "go": '#!/bin/sh\nexec cat "$3"\n',
    "govulncheck": '#!/bin/sh\nif [ -f "$ASSETS_FAKE/vulns.json" ]; then cat "$ASSETS_FAKE/vulns.json";'
                   ' else echo \'{"config":{"scanner_name":"govulncheck"}}\'; fi\n',
    "gh": '#!/bin/sh\nif [ "$1 $2" = "release download" ]; then cp "$ASSETS_FAKE"/release/* "$7"/; '
          'exit 0; fi\nif [ "$1" = "api" ]; then cat "$ASSETS_FAKE/releases.json"; exit 0; fi\nexit 9\n',
}


def run(argv, cwd=None, env=None, input_bytes=None):
    r = subprocess.run(argv, cwd=cwd, env=env, input=input_bytes, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    if r.returncode != 0:
        raise AssertionError("%s: %s" % (argv, r.stderr.decode()))
    return r


def setUpModule():
    Keys.setup()


def tearDownModule():
    Keys.teardown()


def gover(commit, arch="amd64", go="go1.26.9", net="v0.60.0", modified="false",
          version=VERSION):
    return ("BIN: %s\n\tpath\tgithub.com/Hanalyx/openwatch/cmd/openwatch\n"
            "\tmod\tgithub.com/Hanalyx/openwatch\tv%s\t\n"
            "\tdep\tgithub.com/Hanalyx/kensa\tv%s\th1:k=\n"
            "\tdep\tgolang.org/x/net\t%s\th1:n=\n"
            "\tbuild\t-ldflags=\" -X github.com/Hanalyx/openwatch/internal/version.Version=%s "
            "-X github.com/Hanalyx/openwatch/internal/version.Commit=%s\"\n"
            "\tbuild\tGOARCH=%s\n\tbuild\tvcs.revision=%s\n\tbuild\tvcs.modified=%s\n"
            % (go, version, KENSA, net, version, commit[:8], arch, commit, modified)).encode()


class Case(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="relassets-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.env = dict(Keys.env, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                        GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                        GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
        self.old_env = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(self.old_env)))
        self.fake = os.path.join(self.dir, "fake")
        os.makedirs(os.path.join(self.fake, "release"))
        os.environ.update(self.env, ASSETS_FAKE=self.fake)
        self.tools = {}
        for name, body in FAKES.items():
            p = os.path.join(self.fake, name)
            with open(p, "w") as f:
                f.write(body)
            os.chmod(p, 0o755)
            self.tools[name] = p
        self.keys = run(["gpg", "--batch", "--armor", "--export", Keys.release],
                        env=Keys.env).stdout
        self.repo = os.path.join(self.dir, "repo")
        self.origin = os.path.join(self.dir, "origin.git")
        self.commit = self.make_repo()
        self.assets = os.path.join(self.dir, "assets")
        os.mkdir(self.assets)
        self.build_assets()
        self.evidence = os.path.join(self.dir, "evidence")

    def git(self, *args, **kw):
        return run(["git"] + list(args), cwd=kw.get("cwd", self.repo), env=self.env)

    def make_repo(self):
        self.git("init", "--quiet", "--bare", "--initial-branch=main", self.origin, cwd=self.dir)
        self.git("init", "--quiet", "--initial-branch=main", self.repo, cwd=self.dir)
        files = {"packaging/version.env": 'VERSION="%s"\n' % VERSION, "go.mod": GOMOD,
                 "security/KEYS": self.keys, "THIRD-PARTY-NOTICES.md": NOTICES}
        for rel, data in files.items():
            p = os.path.join(self.repo, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(data if isinstance(data, bytes) else data.encode())
        self.git("add", "-A")
        self.git("commit", "--quiet", "-m", "candidate")
        self.git("remote", "add", "origin", self.origin)
        self.git("tag", "-a", "-m", TAG, TAG)
        self.git("push", "--quiet", "origin", "main", "refs/tags/" + TAG)
        return self.git("rev-parse", "HEAD").stdout.decode().strip()

    def package(self, name, binary=None, licenses=None):
        stage = os.path.join(self.dir, "stage-" + name)
        shutil.rmtree(stage, True)
        files = {}
        if name.startswith("openwatch"):
            arch = ra.package_arch(name)
            files["usr/bin/openwatch"] = gover(self.commit, arch=arch) if binary is None else binary
            lic = {"LICENSE": b"license\n", "THIRD-PARTY-LICENSES.txt": b"texts\n",
                   "THIRD-PARTY-NOTICES.md": NOTICES, "license-manifest.json": b"{}\n"}
            lic.update(licenses or {})
            for k, v in lic.items():
                if v is not None:
                    files["usr/share/licenses/openwatch/" + k] = v
        else:
            files["usr/share/kensa/rules/x.yml"] = b"rule\n"
        for rel, data in files.items():
            p = os.path.join(stage, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(data)
        with tarfile.open(os.path.join(self.assets, name), "w") as tf:
            tf.add(stage, arcname=".")

    def sbom(self, name, digest=None, net="v0.60.0"):
        comps = [{"purl": "pkg:golang/golang.org/x/net@%s" % net},
                 {"purl": "pkg:golang/github.com/Hanalyx/kensa@v%s" % KENSA}]
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.5",
               "metadata": {"component": {"name": name, "version": "sha256:" + (
                   digest or ra.sha256(os.path.join(self.assets, name)))}},
               "components": comps if name.startswith("openwatch") else []}
        with open(os.path.join(self.assets, name + ".cdx.json"), "w") as f:
            json.dump(bom, f)

    PACKAGES = ("openwatch-%s-1.x86_64.rpm" % VERSION, "openwatch_%s_arm64.deb" % VERSION,
                "kensa-rules-%s-1.noarch.rpm" % KENSA)

    def build_assets(self, sign_with=None, skip=(), **over):
        for name in self.PACKAGES:
            if name not in skip:
                self.package(name, **over.get(name, {}))
                self.sbom(name)
        with open(os.path.join(self.assets, "openwatch.cdx.json"), "w") as f:
            json.dump({"bomFormat": "CycloneDX"}, f)
        self.seal(sign_with)

    def seal(self, sign_with=None):
        names = sorted(n for n in os.listdir(self.assets)
                       if n not in ("SHA256SUMS", "SHA256SUMS.asc", "KEYS"))
        sums = "".join("%s  %s\n" % (ra.sha256(os.path.join(self.assets, n)), n) for n in names)
        with open(os.path.join(self.assets, "SHA256SUMS"), "w") as f:
            f.write(sums)
        asc = os.path.join(self.assets, "SHA256SUMS.asc")
        if os.path.exists(asc):
            os.unlink(asc)
        run(["gpg", "--batch", "--yes", "--local-user", sign_with or Keys.release,
             "--armor", "--detach-sign", "--output", asc, os.path.join(self.assets, "SHA256SUMS")],
            env=Keys.env)
        with open(os.path.join(self.assets, "KEYS"), "wb") as f:
            f.write(self.keys)

    def verify(self, *extra, key=None, commit=None, src=True):
        out = io.StringIO()
        argv = ["--tag", TAG, "--commit", commit or self.commit, "--key", key or Keys.release,
                "--evidence", self.evidence, "--repo", self.repo] + (
                    ["--from", self.assets] if src else []) + list(extra)
        code = ra.main(argv, out=out, tools=ra.Tools(**self.tools))
        report = None
        if os.path.exists(os.path.join(self.evidence, "report.json")):
            with open(os.path.join(self.evidence, "report.json")) as f:
                report = json.load(f)
        return code, out.getvalue(), report

    def failures(self, report):
        return sorted((r["area"], r["subject"]) for r in report["checks"] if not r["ok"])

    def assert_only_failures(self, want):
        code, out, report = self.verify()
        self.assertEqual(code, 1, out)
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(self.failures(report), sorted(want), out)
        return report


class AssetsRunAndEvidence(Case):
    """AC-01: inputs, a passing release, and raw evidence for every command."""

    def test_a_good_release_passes_every_check(self):
        before = {n: ra.sha256(os.path.join(self.assets, n)) for n in os.listdir(self.assets)}
        code, out, report = self.verify()
        self.assertEqual(code, 0, out)
        self.assertEqual(report["verdict"], "PASS")
        areas = {r["area"] for r in report["checks"]}
        self.assertEqual(areas, {"release", "manifest", "signature", "rpm", "binary", "vulns",
                                 "notices", "sbom"})
        self.assertEqual({n: ra.sha256(os.path.join(self.assets, n))
                          for n in os.listdir(self.assets)}, before, "assets were modified")
        with open(os.path.join(self.evidence, "REPORT.md")) as f:
            self.assertIn("records no release decision", f.read())

    def test_every_command_is_captured_with_its_declared_timeout(self):
        self.verify()
        caps = os.path.join(self.evidence, "captures")
        names = sorted(os.listdir(caps))
        self.assertTrue(names)
        for n in names:
            rec = ra.ec.verify_capture(os.path.join(caps, n), tag=TAG, commit=self.commit)
            self.assertIn(rec["invocation"]["timeout_seconds"], set(ra.TIMEOUTS.values()), n)
        kinds = " ".join(names)
        for want in ("gpg-verify-sha256sums", "rpm-K-", "rpm2cpio-", "cpio-", "extract-",
                     "go-version-m-", "govulncheck-", "git-ls-remote-tag"):
            self.assertIn(want, kinds)

    def test_bad_inputs_and_existing_evidence_are_refused(self):
        for kw in ({"commit": self.commit[:12]}, {"key": Keys.release[-16:]}):
            code, out, _ = self.verify(**kw)
            self.assertEqual(code, 2, kw)
            self.assertIn("REFUSED", out)
        os.mkdir(self.evidence)
        code, out, _ = self.verify()
        self.assertEqual(code, 2)
        self.assertIn("never overwritten", out)

    def test_a_tag_that_does_not_match_version_is_refused(self):
        out = io.StringIO()
        code = ra.main(["--tag", "v0.9.1", "--commit", self.commit, "--key", Keys.release,
                        "--evidence", self.evidence, "--repo", self.repo, "--from", self.assets],
                       out=out, tools=ra.Tools(**self.tools))
        self.assertEqual(code, 2)
        self.assertIn("does not match VERSION", out.getvalue())

    def test_a_download_is_checked_against_githubs_digests(self):
        release = os.path.join(self.fake, "release")
        for n in os.listdir(self.assets):
            shutil.copy(os.path.join(self.assets, n), release)
        digests = [{"name": n, "digest": "sha256:" + ra.sha256(os.path.join(release, n))}
                   for n in sorted(os.listdir(release))]
        digests[0]["digest"] = "sha256:" + "0" * 64
        with open(os.path.join(self.fake, "releases.json"), "w") as f:
            json.dump([{"tag_name": TAG, "draft": True, "assets": digests}], f)
        code, out, report = self.verify(src=False)
        self.assertEqual(code, 1)
        self.assertEqual(self.failures(report), [("release", digests[0]["name"])])
        self.assertTrue(report["downloaded"])


class AssetsManifestAndRelease(Case):
    """AC-02: the manifest, the KEYS asset and the tag bind the assets to the commit."""

    def test_a_changed_asset_fails_its_entry(self):
        with open(os.path.join(self.assets, self.PACKAGES[2]), "ab") as f:
            f.write(b"x")
        self.assert_only_failures([("manifest", self.PACKAGES[2]), ("sbom", self.PACKAGES[2])])

    def test_an_unlisted_or_missing_asset_fails_coverage(self):
        with open(os.path.join(self.assets, "extra.txt"), "w") as f:
            f.write("x")
        self.assert_only_failures([("manifest", "coverage")])

    def test_a_different_keys_asset_fails(self):
        with open(os.path.join(self.assets, "KEYS"), "ab") as f:
            f.write(b"\n")
        self.assert_only_failures([("manifest", "KEYS")])

    def test_a_tag_on_another_commit_fails(self):
        self.git("commit", "--quiet", "--allow-empty", "-m", "later")
        self.git("tag", "-f", "-a", "-m", TAG, TAG)
        self.git("push", "--quiet", "--force", "origin", "refs/tags/" + TAG)
        self.assert_only_failures([("release", "tag on origin")])


class AssetsSignatures(Case):
    """AC-03: SHA256SUMS and every RPM are signed by the release key."""

    def test_a_signature_by_another_key_fails(self):
        self.seal(sign_with=Keys.other)
        self.assert_only_failures([("signature", "SHA256SUMS.asc")])

    def test_a_key_not_in_keys_fails(self):
        code, out, report = self.verify(key=Keys.other)
        self.assertEqual(code, 1)
        self.assertEqual(self.failures(report), [("signature", "SHA256SUMS.asc"),
                                                 ("signature", "release key")])

    def test_an_rpm_whose_signature_fails_is_reported(self):
        with open(os.path.join(self.fake, "rpm-bad"), "w") as f:
            f.write(self.PACKAGES[0] + "\n")
        self.assert_only_failures([("rpm", self.PACKAGES[0])])


class AssetsBinaries(Case):
    """AC-04: each binary is the commit's build, with go.mod's toolchain and modules."""

    def rebuild(self, name, binary=None, licenses=None):
        self.package(name, binary=binary, licenses=licenses)
        self.sbom(name)
        self.seal()

    def test_each_build_mismatch_fails_the_binary(self):
        name = self.PACKAGES[0]
        for kw in ({"go": "go1.26.8"}, {"net": "v0.59.0"}, {"modified": "true"},
                   {"version": "0.9.1"}, {"arch": "arm64"}):
            with self.subTest(**kw):
                shutil.rmtree(self.evidence, True)
                self.rebuild(name, binary=gover(self.commit, **dict({"arch": "amd64"}, **kw)))
                report = self.assert_only_failures([("binary", name)])
                detail = [r["detail"] for r in report["checks"] if not r["ok"]][0]
                self.assertTrue(detail)

    def test_a_binary_from_another_commit_fails(self):
        name = self.PACKAGES[1]
        self.rebuild(name, binary=gover("1" * 40, arch="arm64"))
        report = self.assert_only_failures([("binary", name)])
        self.assertIn("vcs.revision", [r["detail"] for r in report["checks"] if not r["ok"]][0])

    def test_a_package_without_the_binary_fails(self):
        name = self.PACKAGES[0]
        self.rebuild(name, binary=b"")
        os.unlink(os.path.join(self.assets, name))
        with tarfile.open(os.path.join(self.assets, name), "w") as tf:
            pass
        self.sbom(name)
        self.seal()
        report = self.assert_only_failures([("binary", name), ("notices", name)])
        self.assertIn("not in the package", " ".join(r["detail"] for r in report["checks"]))


class AssetsVulnsNoticesSboms(Case):
    """AC-05: no called vulnerability, the commit's notices, SBOMs bound to packages."""

    def vulns(self, *frames):
        with open(os.path.join(self.fake, "vulns.json"), "w") as f:
            for osv, frame in frames:
                f.write(json.dumps({"finding": {"osv": osv, "trace": [frame]}}) + "\n")

    def test_a_called_vulnerability_fails_every_binary(self):
        self.vulns(("GO-2026-0001", {"module": "golang.org/x/net", "package": "x/net/http2",
                                     "function": "Server.ServeConn"}))
        report = self.assert_only_failures([("vulns", self.PACKAGES[0]),
                                            ("vulns", self.PACKAGES[1])])
        self.assertIn("GO-2026-0001", report["checks"][-1]["detail"] + json.dumps(report))

    def test_required_module_findings_are_reported_not_failed(self):
        self.vulns(("GO-2026-5932", {"module": "golang.org/x/text"}),
                   ("GO-2026-7777", {"module": "golang.org/x/net", "package": "x/net/idna"}))
        code, out, report = self.verify()
        self.assertEqual(code, 0, out)
        details = [r["detail"] for r in report["checks"] if r["area"] == "vulns"]
        self.assertTrue(all("GO-2026-5932" in d and "GO-2026-7777" in d for d in details))

    def test_notices_that_differ_or_a_missing_license_file_fail(self):
        name = self.PACKAGES[1]
        for lic in ({"THIRD-PARTY-NOTICES.md": b"stale\n"}, {"LICENSE": None}):
            with self.subTest(lic=list(lic)):
                shutil.rmtree(self.evidence, True)
                self.package(name, licenses=lic)
                self.sbom(name)
                self.seal()
                self.assert_only_failures([("notices", name)])

    def test_an_sbom_for_another_file_or_with_other_module_versions_fails(self):
        name = self.PACKAGES[0]
        for kw in ({"digest": "0" * 64}, {"net": "v0.59.0"}):
            with self.subTest(**kw):
                shutil.rmtree(self.evidence, True)
                self.sbom(name, **kw)
                self.seal()
                self.assert_only_failures([("sbom", name)])

    def test_a_missing_sbom_or_a_kensa_version_mismatch_fails(self):
        os.unlink(os.path.join(self.assets, self.PACKAGES[2] + ".cdx.json"))
        self.seal()
        self.assert_only_failures([("sbom", self.PACKAGES[2])])
        shutil.rmtree(self.evidence, True)
        other = "kensa-rules-0.9.9-1.noarch.rpm"
        os.rename(os.path.join(self.assets, self.PACKAGES[2]), os.path.join(self.assets, other))
        self.sbom(other)
        self.seal()
        self.assert_only_failures([("sbom", other)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
