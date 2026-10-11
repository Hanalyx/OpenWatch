#!/usr/bin/env python3
"""Tests for the local compatibility runner.

    python3 -S scripts/test_release_compat.py

The fixture is test_release_assets.py's: a real git repository with
release/assets.toml, a real signed SHA256SUMS for the new pair, and here also
an older release's signed assets for the old pair. git, tar and GnuPG are
real. go, make, docker and gh are shell fakes. The fake go plays each outcome
the container test can produce: a pass, a SKIP, a missing final line, a FAIL
line, or an error. The real test runs against real packages in local
containers (see the release-prep skill).

One class per criterion of spec release-compat-runs.
"""

import importlib.util
import io
import json
import os
import shutil
from pathlib import Path

_here = Path(__file__).resolve().parent


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, _here / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rc = _load("release_compat", "release_compat.py")
ta = _load("test_release_assets", "test_release_assets.py")
Keys = ta.Keys
unittest = ta.unittest

OLD_TAG = "v0.8.0"

FAKES = {
    "go": '#!/bin/sh\n'
          'pwd > "$ASSETS_FAKE/go-cwd.$OPENWATCH_KENSA_COMPAT_KIND.$OPENWATCH_KENSA_COMPAT_MODE"\n'
          'env | grep ^OPENWATCH_KENSA_COMPAT_ | sort > "$ASSETS_FAKE/go-env.$OPENWATCH_KENSA_COMPAT_MODE.$OPENWATCH_KENSA_COMPAT_KIND"\n'
          'outcome=$(cat "$ASSETS_FAKE/go-outcome" 2>/dev/null || echo pass)\n'
          'label=$OPENWATCH_KENSA_COMPAT_KIND\n'
          '[ "$OPENWATCH_KENSA_COMPAT_MODE" = scripts ] || label="$label $OPENWATCH_KENSA_COMPAT_MODE"\n'
          'T=TestUpgrade_EngineCorpusPairingInContainers\n'
          'echo "=== RUN   $T"; echo "=== RUN   $T/containers"\n'
          'case $outcome in\n'
          '  skip) echo "    upgrade_test.go:1: set OPENWATCH_KENSA_COMPAT_... to run"\n'
          '        echo "--- SKIP: $T (0.00s)"; echo PASS; exit 0 ;;\n'
          '  touch) echo x >> "$OPENWATCH_KENSA_COMPAT_NEW_DIR"/$(ls "$OPENWATCH_KENSA_COMPAT_NEW_DIR" | head -1) ;;\n'
          '  touch-one) role=$(cut -d: -f1 "$ASSETS_FAKE/touch-target"); f=$(cut -d: -f2 "$ASSETS_FAKE/touch-target")\n'
          '     if [ "$role" = old ]; then d=$OPENWATCH_KENSA_COMPAT_OLD_DIR; else d=$OPENWATCH_KENSA_COMPAT_NEW_DIR; fi\n'
          '     [ -f "$d/$f" ] && echo x >> "$d/$f" ;;\n'
          'esac\n'
          '[ "$outcome" = nopass ] || echo "        PASS: fresh install accepted"\n'
          '[ "$outcome" = failline ] && echo "        FAIL: corpus digest differs"\n'
          '[ "$outcome" = noline ] || echo "        kensa-rules compat ($label): all checks passed"\n'
          'if [ "$outcome" = exit1 ]; then echo "--- FAIL: $T (1.00s)"; exit 1; fi\n'
          '[ "$outcome" = noresult ] && { echo PASS; exit 0; }\n'
          'echo "--- PASS: $T (1.00s)"; echo "    --- PASS: $T/containers (1.00s)"; echo PASS\n',
    "make": '#!/bin/sh\n[ -f "$ASSETS_FAKE/make-fail" ] && { echo "make: *** error" >&2; exit 2; }\n'
            'mkdir -p internal/server/spa && touch internal/server/openapi_embed.yaml '
            'internal/server/spa/index.html\n',
    "docker": '#!/bin/sh\n[ -f "$ASSETS_FAKE/docker-down" ] && { echo "Cannot connect to the Docker '
              'daemon" >&2; exit 1; }\necho 29.4.0\n',
    "gh": '#!/bin/sh\n[ "$1 $2" = "release download" ] || exit 9\n'
          'cp "$ASSETS_FAKE/release-$3"/* "$7"/\n',
}

OLD_PACKAGES = ("openwatch-0.8.0-1.x86_64.rpm", "openwatch_0.8.0_amd64.deb",
                "kensa-rules-0.9.0-1.noarch.rpm", "kensa-rules_0.9.0_all.deb")


class Case(ta.Case):
    def setUp(self):
        ta.Case.setUp(self)
        for name, body in FAKES.items():
            p = os.path.join(self.fake, name)
            with open(p, "w") as f:
                f.write(body)
            os.chmod(p, 0o755)
            self.tools[name] = p
        self.tools.update(env="env", tar="tar")
        self.old = os.path.join(self.dir, "old")
        os.mkdir(self.old)
        self.build_old()

    def build_old(self, sign_with=None, packages=OLD_PACKAGES):
        for name in packages:
            with open(os.path.join(self.old, name), "wb") as f:
                f.write(("old package %s\n" % name).encode())
        names = sorted(n for n in os.listdir(self.old) if not n.startswith("SHA256SUMS"))
        with open(os.path.join(self.old, "SHA256SUMS"), "w") as f:
            f.write("".join("%s  %s\n" % (ta.ra.sha256(os.path.join(self.old, n)), n)
                            for n in names))
        asc = os.path.join(self.old, "SHA256SUMS.asc")
        if os.path.exists(asc):
            os.unlink(asc)
        ta.run(["gpg", "--batch", "--yes", "--local-user", sign_with or Keys.release, "--armor",
                "--detach-sign", "--output", asc, os.path.join(self.old, "SHA256SUMS")],
               env=Keys.env)

    def outcome(self, what):
        with open(os.path.join(self.fake, "go-outcome"), "w") as f:
            f.write(what)

    def flag(self, name):
        open(os.path.join(self.fake, name), "w").close()

    def compat(self, *extra, old_src=True, src=True, commit=None):
        out = io.StringIO()
        argv = ["--tag", ta.TAG, "--commit", commit or self.commit, "--key", Keys.release,
                "--old-tag", OLD_TAG, "--evidence", self.evidence, "--repo", self.repo]
        argv += (["--from", self.assets] if src else []) + (
            ["--old-from", self.old] if old_src else []) + list(extra)
        code = rc.main(argv, out=out, tools=rc.ra.Tools(**self.tools))
        report = None
        if os.path.exists(os.path.join(self.evidence, "report.json")):
            with open(os.path.join(self.evidence, "report.json")) as f:
                report = json.load(f)
        return code, out.getvalue(), report

    def failed(self, report):
        return sorted((r["area"], r["subject"]) for r in report["checks"] if not r["ok"])


class CompatRuns(Case):
    """AC-01: the candidate's own test runs in every mode against the release's packages."""

    def test_every_mode_passes_on_the_candidates_source(self):
        code, out, report = self.compat()
        self.assertEqual(code, 0, out)
        self.assertEqual(report["verdict"], "PASS")
        after = [r for r in report["checks"] if r["area"] == "inputs-after"][0]
        self.assertEqual(after["detail"], "all 8 staged copies unchanged")
        modes = sorted(r["subject"] for r in report["checks"] if r["area"] == "compat")
        self.assertEqual(modes, sorted(m[0] for m in rc.MODES))
        src = os.path.join(self.evidence, "src")
        for kind, mode in (("rpm", "scripts"), ("deb", "scripts"), ("rpm", "noscripts")):
            with open(os.path.join(self.fake, "go-cwd.%s.%s" % (kind, mode))) as f:
                self.assertEqual(f.read().strip(), src)
        # The source is the commit's tree from git archive, not a working tree.
        self.assertTrue(os.path.isfile(os.path.join(src, "release", "assets.toml")))
        self.assertFalse(os.path.exists(os.path.join(src, ".git")))

    def test_the_source_is_the_candidate_even_when_the_repository_moved_on(self):
        with open(os.path.join(self.repo, "LATER.md"), "w") as f:
            f.write("a later commit\n")
        self.git("add", "-A")
        self.git("commit", "--quiet", "-m", "later work, not the candidate")
        code, out, report = self.compat()
        self.assertEqual(code, 0, out)
        src = os.path.join(self.evidence, "src")
        self.assertFalse(os.path.exists(os.path.join(src, "LATER.md")),
                         "the source came from HEAD, not the candidate")
        self.assertTrue(os.path.isfile(os.path.join(src, "go.mod")))

    def test_each_mode_gets_its_image_kind_mode_and_staged_pairs(self):
        self.compat()
        with open(os.path.join(self.fake, "go-env.noscripts.rpm")) as f:
            env = f.read()
        self.assertIn("OPENWATCH_KENSA_COMPAT_IMAGE=rockylinux:9", env)
        self.assertIn("OPENWATCH_KENSA_COMPAT_MODE=noscripts", env)
        new_rpm = os.path.join(self.evidence, "stage", "new-rpm")
        self.assertIn("OPENWATCH_KENSA_COMPAT_NEW_DIR=" + new_rpm, env)
        self.assertEqual(sorted(os.listdir(new_rpm)),
                         sorted(["openwatch-%s-1.x86_64.rpm" % ta.VERSION,
                                 "kensa-rules-%s-1.noarch.rpm" % ta.KENSA]))
        self.assertEqual(sorted(os.listdir(os.path.join(self.evidence, "stage", "old-deb"))),
                         ["kensa-rules_0.9.0_all.deb", "openwatch_0.8.0_amd64.deb"])

    def test_every_command_is_a_capture_with_its_timeout(self):
        self.compat()
        caps = os.path.join(self.evidence, "captures")
        for n in sorted(os.listdir(caps)):
            rec = rc.ec.verify_capture(os.path.join(caps, n), tag=ta.TAG, commit=self.commit)
            self.assertIn(rec["invocation"]["timeout_seconds"], set(rc.TIMEOUTS.values()), n)
        names = " ".join(sorted(os.listdir(caps)))
        for want in ("git-archive", "tar-extract", "make-prerequisites", "docker-info",
                     "compat-rocky9-rpm", "compat-ubuntu2404-deb", "compat-rocky9-rpm-noscripts"):
            self.assertIn(want, names)

    def test_downloads_both_releases_when_no_directories_are_given(self):
        for tag, d in ((ta.TAG, self.assets), (OLD_TAG, self.old)):
            dest = os.path.join(self.fake, "release-" + tag)
            shutil.copytree(d, dest)
        code, out, report = self.compat(src=False, old_src=False)
        self.assertEqual(code, 0, out)
        self.assertIn(("inputs", "download " + OLD_TAG),
                      [(r["area"], r["subject"]) for r in report["checks"] if r["ok"]])


class CompatNoFalsePass(Case):
    """AC-02: a skipped, incomplete or failing run is never a pass."""

    def assert_modes_fail(self, reason):
        code, out, report = self.compat()
        self.assertEqual(code, 1, out)
        self.assertEqual(self.failed(report), sorted(("compat", m[0]) for m in rc.MODES))
        for r in report["checks"]:
            if r["area"] == "compat":
                self.assertIn(reason, r["detail"])

    def test_a_skipped_test_fails(self):
        self.outcome("skip")
        self.assert_modes_fail("SKIPPED")

    def test_a_missing_final_line_fails(self):
        self.outcome("noline")
        self.assert_modes_fail("all checks passed")

    def test_a_fail_line_fails(self):
        self.outcome("failline")
        self.assert_modes_fail("FAIL check lines")

    def test_no_pass_lines_fails(self):
        self.outcome("nopass")
        self.assert_modes_fail("no PASS check lines")

    def test_a_failing_go_test_fails(self):
        self.outcome("exit1")
        self.assert_modes_fail("go test ended with exit=1")

    def test_a_run_without_the_tests_pass_result_fails(self):
        # Exit 0 and the container's lines, but go never reported the test or
        # its subtest as passing.
        self.outcome("noresult")
        self.assert_modes_fail("no '--- PASS: TestUpgrade_EngineCorpusPairingInContainers'")

    def test_no_docker_means_no_mode_ran(self):
        self.flag("docker-down")
        code, out, report = self.compat()
        self.assertEqual(code, 1)
        self.assertEqual(self.failed(report), [("compat", "(area)"), ("docker", "daemon"),
                                               ("inputs-after", "(area)")])

    def test_unmade_prerequisites_mean_no_mode_ran(self):
        self.flag("make-fail")
        code, out, report = self.compat()
        self.assertEqual(code, 1)
        self.assertIn(("source", self.commit), self.failed(report))
        self.assertIn(("compat", "(area)"), self.failed(report))


class CompatInputs(Case):
    """AC-03: only verified packages from both releases are used, and they do not change."""

    def test_a_new_release_signed_by_another_key_stops_before_any_run(self):
        self.seal(sign_with=Keys.other)
        code, out, report = self.compat()
        self.assertEqual(code, 1)
        failed = self.failed(report)
        self.assertIn(("signature", "new SHA256SUMS.asc"), failed)
        self.assertIn(("compat", "(area)"), failed)
        self.assertFalse(os.path.exists(os.path.join(self.evidence, "src")))

    def test_an_old_release_signed_by_another_key_stops_before_any_run(self):
        self.build_old(sign_with=Keys.other)
        code, out, report = self.compat()
        self.assertEqual(code, 1)
        self.assertIn(("signature", "old SHA256SUMS.asc"), self.failed(report))

    def test_a_package_that_differs_from_its_manifest_entry_stops(self):
        name = "openwatch_%s_amd64.deb" % ta.VERSION
        with open(os.path.join(self.assets, name), "ab") as f:
            f.write(b"x")
        code, out, report = self.compat()
        self.assertEqual(code, 1)
        self.assertIn(("inputs", "new " + name), self.failed(report))
        self.assertIn(("compat", "(area)"), self.failed(report))

    def test_an_old_release_without_one_kensa_pair_stops(self):
        # An old release that ships no kensa-rules DEB at all, consistently signed.
        os.unlink(os.path.join(self.old, OLD_PACKAGES[3]))
        with open(os.path.join(self.old, "SHA256SUMS")) as f:
            lines = [l for l in f if OLD_PACKAGES[3] not in l]
        with open(os.path.join(self.old, "SHA256SUMS"), "w") as f:
            f.writelines(lines)
        self.build_old_signature_only()
        code, out, report = self.compat()
        self.assertEqual(code, 1)
        self.assertIn(("inputs", "old kensa-rules"), self.failed(report))

    def build_old_signature_only(self):
        asc = os.path.join(self.old, "SHA256SUMS.asc")
        os.unlink(asc)
        ta.run(["gpg", "--batch", "--yes", "--local-user", Keys.release, "--armor",
                "--detach-sign", "--output", asc, os.path.join(self.old, "SHA256SUMS")],
               env=Keys.env)

    def test_a_package_changed_during_the_runs_fails(self):
        self.outcome("touch")
        code, out, report = self.compat()
        self.assertEqual(code, 1)
        self.assertEqual(self.failed(report), [("inputs-after", "staged packages")])

    def test_bad_input_is_refused_before_anything_runs(self):
        out = io.StringIO()
        code = rc.main(["--tag", ta.TAG, "--commit", self.commit, "--key", Keys.release,
                        "--old-tag", "0.8.0", "--evidence", self.evidence, "--repo", self.repo],
                       out=out, tools=rc.ra.Tools(**self.tools))
        self.assertEqual(code, 2)
        self.assertIn("malformed", out.getvalue())
        out = io.StringIO()
        code = rc.main(["--tag", ta.TAG, "--commit", self.commit, "--key", Keys.release,
                        "--old-tag", OLD_TAG, "--evidence", self.evidence, "--repo", self.repo,
                        "--old-from", os.path.join(self.dir, "absent")],
                       out=out, tools=rc.ra.Tools(**self.tools))
        self.assertEqual(code, 2)
        self.assertIn("is not a directory", out.getvalue())
        os.mkdir(self.evidence)
        code, out, _ = self.compat()
        self.assertEqual(code, 2)
        self.assertIn("never overwritten", out)

    def test_a_candidate_without_the_inventory_is_refused_unless_told(self):
        self.git("rm", "--quiet", "release/assets.toml")
        self.git("commit", "--quiet", "-m", "no inventory")
        commit = self.git("rev-parse", "HEAD").stdout.decode().strip()
        code, out, _ = self.compat(commit=commit)
        self.assertEqual(code, 2)
        self.assertIn("--inventory-from-tree", out)
        code, out, report = self.compat("--inventory-from-tree", commit=commit)
        self.assertTrue(any("not the candidate" in n for n in report["notes"]))


class CompatSameCorpusVersion(Case):
    """AC-04: identically named packages in both pairs are compared separately."""

    def setUp(self):
        Case.setUp(self)
        # The old release ships the same kensa-rules version as the new one, so
        # both pairs stage files with identical names.
        for name in list(os.listdir(self.old)):
            os.unlink(os.path.join(self.old, name))
        self.build_old(packages=("openwatch-0.8.0-1.x86_64.rpm", "openwatch_0.8.0_amd64.deb",
                                 "kensa-rules-%s-1.noarch.rpm" % ta.KENSA,
                                 "kensa-rules_%s_all.deb" % ta.KENSA))

    def test_the_unchanged_case_accounts_for_all_eight_copies(self):
        code, out, report = self.compat()
        self.assertEqual(code, 0, out)
        stage = os.path.join(self.evidence, "stage")
        names = {}
        for d in os.listdir(stage):
            for n in os.listdir(os.path.join(stage, d)):
                names.setdefault(n, []).append(d)
        shared = sorted(n for n, ds in names.items() if len(ds) > 1)
        self.assertEqual(shared, sorted(["kensa-rules-%s-1.noarch.rpm" % ta.KENSA,
                                         "kensa-rules_%s_all.deb" % ta.KENSA]))
        self.assertEqual(sum(len(v) for v in names.values()), 8)
        after = [r for r in report["checks"] if r["area"] == "inputs-after"][0]
        self.assertEqual(after["detail"], "all 8 staged copies unchanged")

    def test_a_comparison_that_misses_a_copy_fails(self):
        # A map keyed without the role would lose an entry; the count of
        # staged copies, read from the file system, must catch that.
        before = {("new", "rpm", "x.rpm"): "1", ("old", "rpm", "x.rpm"): "1"}
        self.assertEqual(rc.compare(before, dict(before), 2), [])
        lossy = {("rpm", "x.rpm"): "1"}
        self.assertEqual(rc.compare(lossy, dict(lossy), 2),
                         ["compared 1 and 1 of 2 staged copies"])

    def test_changing_either_copy_of_a_shared_name_fails(self):
        for role in ("new", "old"):
            for kind, name in (("rpm", "kensa-rules-%s-1.noarch.rpm" % ta.KENSA),
                               ("deb", "kensa-rules_%s_all.deb" % ta.KENSA)):
                with self.subTest(role=role, kind=kind):
                    shutil.rmtree(self.evidence, True)
                    self.outcome("touch-one")
                    with open(os.path.join(self.fake, "touch-target"), "w") as f:
                        f.write("%s:%s" % (role, name))
                    code, out, report = self.compat()
                    self.assertEqual(code, 1, out)
                    self.assertEqual(self.failed(report), [("inputs-after", "staged packages")])
                    detail = [r["detail"] for r in report["checks"]
                              if r["area"] == "inputs-after"][0]
                    self.assertIn("CHANGED during the runs: %s/%s/%s" % (role, kind, name),
                                  detail)
                    other = "old" if role == "new" else "new"
                    self.assertNotIn("%s/%s/%s" % (other, kind, name), detail)


setUpModule = ta.setUpModule
tearDownModule = ta.tearDownModule

if __name__ == "__main__":
    unittest.main(verbosity=2)
