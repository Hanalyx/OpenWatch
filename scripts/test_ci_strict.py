#!/usr/bin/env python3
"""Tests for scripts/ci-strict.py (release-ci-gates C-20).

Run: python3 -S scripts/test_ci_strict.py
"""

import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("ci_strict", HERE / "ci-strict.py")
cs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cs)

ALL_TOOLS = {"specter", "golangci-lint", "govulncheck", "rpmbuild", "rpm", "dpkg-deb", "dpkg",
             "go", "git", "node", "npx", "make"}
PKGS = ["github.com/Hanalyx/openwatch/internal/a", cs.SERVER_PKG]


def ev(action, pkg, test=None, output=None):
    e = {"Action": action, "Package": pkg}
    if test:
        e["Test"] = test
    if output is not None:
        e["Output"] = output
    return json.dumps(e)


def stream(pkg, tests):
    """tests: [(name, 'pass'|'fail'|'skip', skip message or None)]"""
    lines = []
    for name, action, msg in tests:
        if msg:
            lines.append(ev("output", pkg, name, f"    x_test.go:10: {msg}\n"))
        lines.append(ev(action, pkg, name))
    lines.append(ev("pass" if all(a != "fail" for _, a, _ in tests) else "fail", pkg))
    return "\n".join(lines) + "\n"


class FakeProbe(cs.Probe):
    """A machine where every command is scripted. gate_rc maps gate-ish
    command prefixes to exit codes; streams sets what go test writes."""

    def __init__(self, root, tools=ALL_TOOLS, env=None, versions=None, gate_rc=None,
                 others=None, server=None, alive=True, on_run=None):
        super().__init__(repo=root, env=env if env is not None else
                         {"OPENWATCH_TEST_DSN": "postgres://u:p@127.0.0.1:5455/openwatch_go_test", "PATH": ""})
        self.tools = set(tools)
        self.versions = versions or {"specter": "specter version 0.15.1", "golangci-lint": "golangci-lint has version 1.64.8"}
        self.gate_rc = gate_rc or {}
        self.others = others if others is not None else stream(PKGS[0], [("TestA", "pass", None)])
        self.server = server if server is not None else stream(cs.SERVER_PKG, [("TestS", "pass", None)])
        self.alive = alive
        self.on_run = on_run
        self.calls = []

    def which(self, name):
        return f"/bin/{name}" if name in self.tools else None

    def tcp_open(self, host, port):
        return True

    def pid_alive(self, pid):
        return self.alive

    def capture(self, cmd, cwd=None):
        if cmd[:2] == ["git", "rev-parse"] and "--absolute-git-dir" in cmd:
            return 0, str(self.repo / ".git")
        if cmd == ["git", "rev-parse", "HEAD"]:
            return 0, "a" * 40
        if cmd[0] == "git":
            return 0, ""
        if cmd == ["specter", "--version"]:
            return 0, self.versions["specter"]
        if cmd == ["golangci-lint", "version"]:
            return 0, self.versions["golangci-lint"]
        if cmd == ["go", "list", "./..."]:
            return 0, "\n".join(PKGS)
        if cmd[:3] == ["go", "list", "-m"]:
            return 0, "/mod/kensa"
        return 1, ""

    def run(self, cmd, cwd=None, env=None, stdout=None, merge_stderr=False):
        self.calls.append((cmd, env))
        if self.on_run:
            self.on_run(cmd)
        joined = " ".join(map(str, cmd))
        for key, rc in self.gate_rc.items():
            if key in joined:
                return rc
        if stdout:
            Path(stdout).write_text(self.server if "internal/server" in joined else self.others)
        if "vitest" in joined:
            for c in cmd:
                if str(c).startswith("--outputFile="):
                    Path(str(c).split("=", 1)[1]).write_text(
                        '<testsuites><testsuite><testcase name="v"/></testsuite></testsuites>')
        return 0


def make_repo():
    root = Path(tempfile.mkdtemp(prefix="ci-strict-"))
    (root / ".git").mkdir()
    (root / "Makefile").write_text("GOLANGCI_VERSION := 1.64.8\n")
    (root / ".specter-version").write_text("0.15.1\n")
    (root / "frontend" / "node_modules").mkdir(parents=True)
    lock = {"packages": {"": {}, "node_modules/a": {"version": "1.0.0"}}}
    (root / "frontend" / "package-lock.json").write_text(json.dumps(lock))
    (root / "frontend" / "node_modules" / ".package-lock.json").write_text(json.dumps(lock))
    return root


def results(root):
    return sorted((root / ".git" / "ci-strict" / "runs").glob("*/result.json"))


class Verdicts(unittest.TestCase):
    def setUp(self):
        self.root = make_repo()
        self.lines = []

    def strict(self, probe, allow=()):
        return cs.strict(probe, set(allow), out=self.lines.append)

    def test_a_complete_run_exits_0_and_only_hosted_skips_are_allowed(self):
        others = stream(PKGS[0], [("TestA", "pass", None), ("TestR", "skip", cs.HOSTED_SKIPS[3])])
        rc = self.strict(FakeProbe(self.root, others=others))
        self.assertEqual(rc, cs.EXIT_COMPLETE, "\n".join(self.lines))
        r = json.loads(results(self.root)[0].read_text())
        self.assertEqual((r["verdict"], r["exit"]), ("complete", 0))
        self.assertIn("LOCAL CI COMPLETE", self.lines[-1])

    def test_a_failing_gate_or_test_exits_1(self):
        self.assertEqual(self.strict(FakeProbe(self.root, gate_rc={"make vet": 2})), cs.EXIT_FAILED)
        others = stream(PKGS[0], [("TestA", "fail", None)])
        self.assertEqual(self.strict(FakeProbe(self.root, others=others, gate_rc={"-p 1": 1})), cs.EXIT_FAILED)

    def test_a_failed_test_in_the_stream_fails_even_if_go_test_exited_0(self):
        others = stream(PKGS[0], [("TestA", "fail", None)])
        rc = self.strict(FakeProbe(self.root, others=others))
        self.assertEqual(rc, cs.EXIT_FAILED, "\n".join(self.lines))

    def test_a_skip_hosted_ci_does_not_make_is_incomplete(self):
        others = stream(PKGS[0], [("TestA", "pass", None),
                                  ("TestD", "skip", "set OPENWATCH_TEST_DSN to run runtime boot tests")])
        rc = self.strict(FakeProbe(self.root, others=others))
        self.assertEqual(rc, cs.EXIT_INCOMPLETE, "\n".join(self.lines))
        self.assertTrue(any("NOT skipped on hosted CI" in ln for ln in self.lines))

    def test_unaccepted_missing_prerequisites_stop_before_any_work(self):
        probe = FakeProbe(self.root, tools=ALL_TOOLS - {"specter"},
                          versions={"specter": "", "golangci-lint": "golangci-lint has version 2.12.2"},
                          env={"PATH": ""})
        rc = self.strict(probe)
        self.assertEqual(rc, cs.EXIT_INCOMPLETE)
        self.assertEqual(probe.calls, [], "a gate ran although preflight failed")
        text = "\n".join(self.lines)
        # Every missing prerequisite is reported at once.
        for name in ("test-database", "specter", "golangci-lint"):
            self.assertIn(f"MISSING {name}", text)
        self.assertIn("golangci-lint 2.12.2, the pin is 1.64.8", text)
        r = json.loads(results(self.root)[0].read_text())
        self.assertEqual(r["verdict"], "incomplete")
        self.assertEqual(r["unaccepted_missing"], ["golangci-lint", "specter", "test-database"])

    def test_an_accepted_gap_still_exits_3_and_is_recorded(self):
        probe = FakeProbe(self.root, versions={"specter": "specter version 0.15.1",
                                               "golangci-lint": "golangci-lint has version 2.12.2"})
        rc = self.strict(probe, allow={"lint"})
        self.assertEqual(rc, cs.EXIT_INCOMPLETE, "\n".join(self.lines))
        self.assertFalse(any("make lint" in " ".join(map(str, c)) for c, _ in probe.calls))
        self.assertTrue(any("make vet" in " ".join(map(str, c)) for c, _ in probe.calls), "other gates must still run")
        r = json.loads(results(self.root)[0].read_text())
        self.assertEqual(r["accepted_gaps"], ["lint"])
        lint = [g for g in r["gates"] if g["gate"] == "lint"][0]
        self.assertEqual((lint["outcome"], lint.get("accepted")), ("not run", True))
        self.assertIn("[accepted gap]", "\n".join(self.lines))

    def test_coverage_is_not_evaluated_over_incomplete_tests(self):
        probe = FakeProbe(self.root, gate_rc={"vitest": 1})
        rc = self.strict(probe)
        self.assertEqual(rc, cs.EXIT_FAILED)
        self.assertFalse(any("specter" == str(c[0]) for c, _ in probe.calls))

    def test_local_go_tests_run_one_phase_at_a_time_with_p_1(self):
        probe = FakeProbe(self.root)
        self.strict(probe)
        go = [c for c, _ in probe.calls if c[:2] == ["go", "test"]]
        self.assertEqual(len(go), 2)
        self.assertIn("./internal/server/", go[0], "internal/server runs first, alone")
        self.assertEqual(go[1][go[1].index("-p") + 1], "1")
        self.assertNotIn(cs.SERVER_PKG, go[1])
        envs = [e for c, e in probe.calls if c[:2] == ["go", "test"]]
        self.assertTrue(all(e.get("OPENWATCH_PACKAGING_BUILD") == "1" for e in envs))

    def test_node_modules_drift_ignores_only_absent_optional_packages(self):
        fe = self.root / "frontend"
        lock = {"packages": {"": {}, "node_modules/a": {"version": "1.0.0"},
                             "node_modules/win-only": {"version": "2.0.0", "optional": True},
                             "node_modules/b": {"version": "3.0.0"}}}
        (fe / "package-lock.json").write_text(json.dumps(lock))
        cases = {
            "optional package for another platform absent": ({"node_modules/a": "1.0.0", "node_modules/b": "3.0.0"}, True),
            "required package absent": ({"node_modules/a": "1.0.0"}, False),
            "version differs": ({"node_modules/a": "1.0.1", "node_modules/b": "3.0.0"}, False),
            "installed package not in the lockfile": ({"node_modules/a": "1.0.0", "node_modules/b": "3.0.0",
                                                       "node_modules/extra": "9.9.9"}, False),
        }
        for name, (installed, want_ok) in cases.items():
            with self.subTest(case=name):
                (fe / "node_modules" / ".package-lock.json").write_text(
                    json.dumps({"packages": {k: {"version": v} for k, v in installed.items()}}))
                ok, detail = cs.preflight(FakeProbe(self.root))["frontend-dependencies"]
                self.assertEqual(ok, want_ok, detail)

    def test_the_output_never_claims_safe_to_push(self):
        self.strict(FakeProbe(self.root))
        for text in ["\n".join(self.lines), (HERE / "ci-strict.py").read_text(),
                     (HERE.parent / "Makefile").read_text()]:
            self.assertNotRegex(text.lower(), r"safe to push")


class ConcurrencyAndResults(unittest.TestCase):
    def setUp(self):
        self.root = make_repo()
        self.state = self.root / ".git" / "ci-strict"

    def test_a_second_invocation_is_refused_and_touches_nothing(self):
        self.state.mkdir(parents=True)
        (self.state / "lock").mkdir()
        (self.state / "lock" / "owner.json").write_text(json.dumps({"pid": 1, "id": "first", "started": "t"}))
        earlier = self.state / "runs" / "first"
        earlier.mkdir(parents=True)
        (earlier / "result.json").write_text('{"id": "first"}')
        before = sorted(p.name for p in self.state.rglob("*"))
        probe = FakeProbe(self.root, alive=True)
        lines = []
        rc = cs.strict(probe, set(), out=lines.append)
        self.assertEqual(rc, cs.EXIT_REFUSED)
        self.assertEqual(probe.calls, [])
        self.assertIn("REFUSED", lines[0])
        self.assertEqual(sorted(p.name for p in self.state.rglob("*")), before,
                         "a refused invocation changed another's state")
        self.assertEqual((earlier / "result.json").read_text(), '{"id": "first"}')

    def test_a_stale_lock_is_reclaimed_and_kept_aside(self):
        self.state.mkdir(parents=True)
        (self.state / "lock").mkdir()
        (self.state / "lock" / "owner.json").write_text(json.dumps({"pid": 999999, "id": "dead"}))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = cs.strict(FakeProbe(self.root, alive=False), set(), out=lambda *_: None)
        self.assertEqual(rc, cs.EXIT_COMPLETE)
        self.assertIn("reclaimed a stale lock from invocation dead", err.getvalue())
        self.assertTrue(list(self.state.glob("lock.stale-*")), "the stale lock record was not kept")
        self.assertFalse((self.state / "lock").exists(), "the lock was not released")

    def test_each_invocation_writes_only_its_own_directory(self):
        cs.strict(FakeProbe(self.root), set(), out=lambda *_: None)
        first = results(self.root)
        first_bytes = first[0].read_bytes()
        cs.strict(FakeProbe(self.root), set(), out=lambda *_: None)
        both = results(self.root)
        self.assertEqual(len(both), 2)
        self.assertEqual(first[0].read_bytes(), first_bytes, "a later run changed an earlier run's result")
        latest = json.loads((self.state / "latest.json").read_text())
        newer = [p for p in both if p != first[0]][0]
        self.assertEqual(latest["result"], str(newer))

    def test_an_interrupted_run_leaves_no_result_and_releases_the_lock(self):
        cs.strict(FakeProbe(self.root), set(), out=lambda *_: None)
        latest_before = (self.state / "latest.json").read_text()

        def interrupt(cmd):
            if "vet" in " ".join(map(str, cmd)):
                raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            cs.strict(FakeProbe(self.root, on_run=interrupt), set(), out=lambda *_: None)
        runs = sorted((self.state / "runs").iterdir())
        self.assertEqual(len(runs), 2)
        interrupted = [r for r in runs if not (r / "result.json").exists()]
        self.assertEqual(len(interrupted), 1, "the interrupted run wrote a result")
        self.assertEqual((self.state / "latest.json").read_text(), latest_before,
                         "an interrupted run moved latest.json")
        self.assertFalse((self.state / "lock").exists())
        ok, msg = cs.check_result(interrupted[0] / "result.json")
        self.assertFalse(ok)
        self.assertIn("did not finish", msg)

    def test_writes_are_atomic(self):
        target = self.root / "r.json"
        cs.write_atomic(target, {"v": 1})
        real = os.replace

        def crash(src, dst):
            raise OSError("crash during rename")
        os.replace = crash
        try:
            with self.assertRaises(OSError):
                cs.write_atomic(target, {"v": 2})
        finally:
            os.replace = real
        self.assertEqual(json.loads(target.read_text()), {"v": 1}, "a failed write changed the result")

    def test_check_result_accepts_only_a_finished_complete_matching_result(self):
        probe = FakeProbe(self.root)
        cs.strict(probe, set(), out=lambda *_: None)
        path = results(self.root)[0]
        r = json.loads(path.read_text())
        self.assertTrue(cs.check_result(path, r["id"], probe)[0])
        self.assertFalse(cs.check_result(path, "someone-else", probe)[0])
        self.assertFalse(cs.check_result(self.root / "missing.json")[0])
        bad = self.root / "bad.json"
        bad.write_text("{not json")
        self.assertFalse(cs.check_result(bad)[0])
        partial = self.root / "partial.json"
        partial.write_text(json.dumps({k: v for k, v in r.items() if k != "finished"}))
        self.assertFalse(cs.check_result(partial)[0])
        for verdict, code in (("incomplete", 3), ("failed", 1)):
            other = self.root / f"{verdict}.json"
            other.write_text(json.dumps(dict(r, verdict=verdict, exit=code)))
            self.assertFalse(cs.check_result(other)[0])
        moved = self.root / "moved.json"
        moved.write_text(json.dumps(dict(r, tree="0" * 64)))
        self.assertFalse(cs.check_result(moved, None, probe)[0], "a result for another tree was accepted")


class Wiring(unittest.TestCase):
    def test_hosted_skips_are_still_literals_in_the_tests(self):
        repo = HERE.parent
        out = subprocess.run(["git", "grep", "-h", "-F", "-e", "t.Skip", "--", "*_test.go"],
                             cwd=repo, capture_output=True, text=True).stdout
        for msg in cs.HOSTED_SKIPS:
            with self.subTest(msg=msg):
                self.assertIn(msg, out, "a hosted-skip entry no longer matches any t.Skip in the tests")

    def test_the_make_targets_delegate_to_the_script(self):
        mk = (HERE.parent / "Makefile").read_text()
        self.assertRegex(mk, r"(?m)^ci-strict:\n\tpython3 -S scripts/ci-strict\.py")
        self.assertRegex(mk, r"(?m)^ci-local: ci-strict\s*$")
        for gate in ("docs-style", "spec-check", "lint", "vuln", "vet", "check-generated", "license-bundle"):
            self.assertIn(gate, cs.MAKE_GATES, f"the strict runner does not run {gate}")

    def test_unknown_allow_names_are_refused(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(cs.main(["--allow-not-run", "nonsense"]), cs.EXIT_REFUSED)
        self.assertIn("unknown gate or prerequisite", err.getvalue())


# --------------------------------------------- readiness from the commit
#
# bugs/OW-124: a local gate passed on a commit whose test file had been left
# out of it by an ignore rule, because the file was still on disk. These
# tests use a real git repository and a stand-in for the Specter gate that,
# like Specter, walks the files on disk for an annotated test.

AC_MARKER = "// @ac AC-1"


def git(root, *args):
    subprocess.run(["git", "-C", str(root)] + list(args), check=True, capture_output=True)


def make_git_repo(test):
    root = Path(tempfile.mkdtemp(prefix="ci-strict-git-"))
    test.addCleanup(lambda: subprocess.run(["rm", "-rf", str(root)]))
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "t@example.invalid")
    git(root, "config", "user.name", "t")
    (root / "Makefile").write_text("GOLANGCI_VERSION := 1.64.8\n")
    (root / ".specter-version").write_text("0.15.1\n")
    (root / ".gitignore").write_text("*credential*\nfrontend/node_modules/\n.specter-results.json\n")
    lock = {"packages": {"": {}, "node_modules/a": {"version": "1.0.0"}}}
    (root / "frontend").mkdir()
    (root / "frontend" / "package-lock.json").write_text(json.dumps(lock))
    (root / "internal" / "x").mkdir(parents=True)
    (root / "internal" / "x" / "x.go").write_text("package x\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    # The source checkout has its dependencies installed (ignored).
    (root / "frontend" / "node_modules").mkdir()
    (root / "frontend" / "node_modules" / ".package-lock.json").write_text(json.dumps(lock))
    return root


def gate_sees_annotation(repo):
    """The stand-in Specter gate: passes when any file under internal/
    carries the AC annotation, or when a results file says AC-1 passed."""
    for f in (repo / "internal").rglob("*_test.go"):
        if AC_MARKER in f.read_text():
            return True
    results = repo / ".specter-results.json"
    return results.is_file() and "AC-1" in results.read_text()


class RealGitProbe(FakeProbe):
    """FakeProbe, except git runs for real, `npm ci` installs a matching
    lockfile record, and spec-check is the stand-in gate."""

    def capture(self, cmd, cwd=None):
        if cmd and cmd[0] == "git":
            # Real git, with the real PATH; tool discovery stays scripted.
            p = subprocess.run(cmd, cwd=cwd or self.repo, capture_output=True, text=True)
            return p.returncode, (p.stdout + p.stderr).strip()
        return FakeProbe.capture(self, cmd, cwd)

    def run(self, cmd, cwd=None, env=None, stdout=None, merge_stderr=False):
        joined = " ".join(map(str, cmd))
        if cmd[:2] == ["npm", "ci"]:
            fe = Path(cwd)
            (fe / "node_modules").mkdir(exist_ok=True)
            (fe / "node_modules" / ".package-lock.json").write_text((fe / "package-lock.json").read_text())
            if stdout:
                Path(stdout).write_text("added 1 package\n")
            self.calls.append((cmd, env))
            return 0
        if "spec-check" in joined:
            self.calls.append((cmd, env))
            return 0 if gate_sees_annotation(self.repo) else 1
        return FakeProbe.run(self, cmd, cwd, env, stdout, merge_stderr)


class ReadinessFromCommit(unittest.TestCase):
    """release-ci-gates C-26, AC-45 to AC-47."""

    def setUp(self):
        self.root = make_git_repo(self)
        self.lines = []

    def strict(self, mode):
        probe = RealGitProbe(self.root)
        rc = cs.strict(probe, set(), out=self.lines.append, mode=mode)
        res = json.loads(sorted((self.root / ".git" / "ci-strict" / "runs").glob("*/result.json"),
                                key=lambda p: p.stat().st_mtime)[-1].read_text())
        return rc, res, probe

    def head(self):
        return subprocess.run(["git", "-C", str(self.root), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()

    def plant(self, name, staged=False):
        f = self.root / "internal" / "x" / name
        f.write_text("package x\n\n" + AC_MARKER + "\n")
        if staged:
            git(self.root, "add", "-f", str(f.relative_to(self.root)))
        return f

    def test_an_uncommitted_test_cannot_make_a_commit_result_pass(self):
        # AC-45. Each way a test can be on disk but not in the commit.
        cases = {
            "ignored by a pattern": dict(name="credential_ac_test.go"),
            "untracked": dict(name="untracked_ac_test.go"),
            "staged, not committed": dict(name="staged_ac_test.go", staged=True),
        }
        for label, kw in cases.items():
            with self.subTest(label):
                f = self.plant(**kw)
                self.assertTrue(gate_sees_annotation(self.root), "the stand-in must see the planted file")
                rc, res, _ = self.strict("commit")
                self.assertEqual(rc, cs.EXIT_FAILED, f"{label}: {self.lines[-3:]}")
                self.assertEqual(res["mode"], "commit")
                self.assertEqual(res["commit"], self.head())
                spec = [g for g in res["gates"] if g["gate"] == "spec-check"][0]
                self.assertEqual(spec["outcome"], "failed")
                if kw.get("staged"):
                    git(self.root, "rm", "-q", "--cached", str(f.relative_to(self.root)))
                f.unlink()

    def test_a_stale_results_file_cannot_make_a_commit_result_pass(self):
        # AC-46, a preservation test: the stand-in would trust it.
        (self.root / ".specter-results.json").write_text('{"results": [{"ac_id": "AC-1", "passed": true}]}')
        self.assertTrue(gate_sees_annotation(self.root))
        rc, res, _ = self.strict("commit")
        self.assertEqual(rc, cs.EXIT_FAILED)
        self.assertEqual(res["mode"], "commit")

    def test_a_committed_test_does_pass_in_commit_mode(self):
        # The control: the export does carry what the commit carries.
        self.plant("committed_ac_test.go", staged=True)
        git(self.root, "commit", "-q", "-m", "add the test")
        rc, res, _ = self.strict("commit")
        self.assertEqual(rc, cs.EXIT_COMPLETE, self.lines[-5:])
        self.assertEqual(res["export"]["outcome"], "exported")
        self.assertEqual(res["export"]["dependencies"], "installed")
        tree = subprocess.run(["git", "-C", str(self.root), "rev-parse", "HEAD^{tree}"],
                              capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(res["tree"], tree)
        self.assertIn("committed files only", res["tested"])

    def test_a_development_run_says_what_it_tested_and_is_not_readiness(self):
        # AC-47. Development mode may test the working tree, and says so.
        f = self.plant("credential_ac_test.go")
        rc, res, probe = self.strict("development")
        self.assertEqual(rc, cs.EXIT_COMPLETE)
        self.assertEqual(res["mode"], "development")
        rel = str(f.relative_to(self.root))
        self.assertIn(rel, res["working_tree"]["ignored_check_inputs"])
        self.assertIn("working-tree changes", res["tested"])
        out = "\n".join(self.lines)
        self.assertIn("DEVELOPMENT MODE", self.lines[0])
        self.assertIn("Not readiness evidence for any commit", self.lines[1])
        self.assertIn(rel, out)
        self.assertIn("not readiness evidence", self.lines[-1])
        path = sorted((self.root / ".git" / "ci-strict" / "runs").glob("*/result.json"))[0]
        ok, msg = cs.check_result(path, probe=probe)
        self.assertTrue(ok, msg)
        ok, msg = cs.check_result(path, probe=probe, readiness=True)
        self.assertFalse(ok)
        self.assertIn("not readiness evidence", msg)

    def test_a_commit_result_is_readiness_evidence_for_head_only(self):
        self.plant("committed_ac_test.go", staged=True)
        git(self.root, "commit", "-q", "-m", "add the test")
        rc, res, probe = self.strict("commit")
        self.assertEqual(rc, cs.EXIT_COMPLETE)
        path = sorted((self.root / ".git" / "ci-strict" / "runs").glob("*/result.json"))[0]
        # Working-tree changes do not affect it: it never tested them.
        (self.root / "internal" / "x" / "scratch.go").write_text("package x\n")
        ok, msg = cs.check_result(path, probe=probe, readiness=True)
        self.assertTrue(ok, msg)
        self.assertIn("only", msg)
        # A new commit does.
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "more")
        ok, msg = cs.check_result(path, probe=probe, readiness=True)
        self.assertFalse(ok)
        self.assertIn("not HEAD", msg)

    def test_commit_mode_leaves_the_checkout_as_it_was(self):
        f = self.plant("staged_ac_test.go", staged=True)
        (self.root / "notes.txt").write_text("untracked\n")
        def snapshot():
            st = subprocess.run(["git", "-C", str(self.root), "status", "--porcelain", "--ignored"],
                                capture_output=True, text=True, check=True).stdout
            wt = subprocess.run(["git", "-C", str(self.root), "worktree", "list", "--porcelain"],
                                capture_output=True, text=True, check=True).stdout
            refs = subprocess.run(["git", "-C", str(self.root), "for-each-ref"],
                                  capture_output=True, text=True, check=True).stdout
            return st, wt, refs, self.head()
        before = snapshot()
        tmp_before = set(Path(tempfile.gettempdir()).glob("ci-strict-commit-*"))
        self.strict("commit")
        after = snapshot()
        # The run adds only its own result under .git/ci-strict, which is not
        # in the working tree.
        self.assertEqual(before, after)
        self.assertEqual(set(Path(tempfile.gettempdir()).glob("ci-strict-commit-*")), tmp_before,
                         "the export was not removed")
        self.assertTrue(f.exists())

    def test_a_failed_export_runs_no_gate_and_is_incomplete(self):
        probe = RealGitProbe(self.root)
        def broken(_probe, _commit, _owned):
            raise RuntimeError("simulated clone failure")
        saved = cs.export_commit
        cs.export_commit = broken
        try:
            rc = cs.strict(probe, set(), out=self.lines.append, mode="commit")
        finally:
            cs.export_commit = saved
        self.assertEqual(rc, cs.EXIT_INCOMPLETE)
        self.assertFalse([c for c, _ in probe.calls if "spec-check" in " ".join(map(str, c))])
        res = json.loads(sorted((self.root / ".git" / "ci-strict" / "runs").glob("*/result.json"))[0].read_text())
        self.assertEqual(res["export"]["outcome"], "failed")
        self.assertIn("export", res["unaccepted_missing"])

    def commit_coverage(self):
        self.plant("committed_ac_test.go", staged=True)
        git(self.root, "commit", "-q", "-m", "committed coverage")

    def test_a_failed_npm_ci_runs_no_gate_and_fails(self):
        # AC-45. A failed install is FAILED, never COMPLETE, and its exit code
        # and output are recorded rather than diagnosed.
        self.commit_coverage()
        merged = []  # how npm ci was asked to handle stderr; the export's probe is a copy

        class NpmFails(RealGitProbe):
            def run(self, cmd, cwd=None, env=None, stdout=None, merge_stderr=False):
                if cmd[:2] == ["npm", "ci"]:
                    self.calls.append((cmd, env))
                    merged.append(merge_stderr)
                    Path(stdout).write_text("npm error code E_SIMULATED\nnpm error simulated install failure\n")
                    return 23
                return RealGitProbe.run(self, cmd, cwd, env, stdout, merge_stderr)

        probe = NpmFails(self.root)
        rc = cs.strict(probe, set(), out=self.lines.append, mode="commit")
        self.assertEqual(rc, cs.EXIT_FAILED, self.lines[-3:])
        res = json.loads(results(self.root)[0].read_text())
        self.assertEqual(res["verdict"], "failed")
        self.assertEqual(res["export"]["dependencies"], "failed: npm ci exited 23")
        log = Path(res["export"]["dependencies_log"])
        self.assertEqual(log.parent, results(self.root)[0].parent, "the npm log is not in the run's directory")
        self.assertIn("E_SIMULATED", log.read_text())
        self.assertEqual(merged, [True], "npm's stderr is not recorded")
        self.assertIn("  | npm error simulated install failure", self.lines)
        self.assertEqual({g["outcome"] for g in res["gates"]}, {"not run"})
        self.assertFalse([c for c, _ in probe.calls if "spec-check" in " ".join(map(str, c))])
        self.assertIn("LOCAL CI FAILED", self.lines[-1])
        ok, _ = cs.check_result(results(self.root)[0], probe=probe, readiness=True)
        self.assertFalse(ok)

    @unittest.skipUnless(shutil.which("npm") and shutil.which("node"), "needs npm and node")
    def test_a_real_failing_npm_ci_fails_the_run(self):
        # AC-45, with npm itself: a postinstall script that exits 23. The
        # lockfile has one local file: dependency, so nothing is fetched.
        self.commit_coverage()
        fe = self.root / "frontend"
        (fe / "fixture").mkdir()
        (fe / "fixture" / "package.json").write_text(json.dumps({"name": "fixture", "version": "1.0.0"}))
        (fe / "package.json").write_text(json.dumps({
            "name": "ci-strict-fixture", "version": "1.0.0",
            "dependencies": {"fixture": "file:fixture"},
            "scripts": {"postinstall": "node -e \"process.exit(23)\""}}))
        (fe / "package-lock.json").unlink()
        cache = Path(self.enterContext(tempfile.TemporaryDirectory()))
        subprocess.run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
                        "--cache", str(cache)], cwd=fe, check=True, capture_output=True)
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "a failing install script")

        class RealNpm(RealGitProbe):
            def run(self, cmd, cwd=None, env=None, stdout=None, merge_stderr=False):
                if cmd[:2] == ["npm", "ci"]:
                    self.calls.append((cmd, env))
                    with open(stdout, "wb") as log:
                        return subprocess.run(cmd + ["--cache", str(cache)], cwd=cwd, stdout=log,
                                              stderr=subprocess.STDOUT if merge_stderr else None).returncode
                return RealGitProbe.run(self, cmd, cwd, env, stdout, merge_stderr)

        rc = cs.strict(RealNpm(self.root), set(), out=self.lines.append, mode="commit")
        self.assertEqual(rc, cs.EXIT_FAILED, self.lines[-3:])
        res = json.loads(results(self.root)[0].read_text())
        self.assertTrue(res["export"]["dependencies"].startswith("failed: npm ci exited "), res["export"])
        self.assertIn("postinstall", Path(res["export"]["dependencies_log"]).read_text())

    def test_a_commit_result_must_record_its_commits_tree(self):
        # AC-47. The recorded tree is checked against the commit's own git
        # tree, not taken on trust; working-tree edits stay irrelevant.
        self.commit_coverage()
        rc, res, probe = self.strict("commit")
        self.assertEqual(rc, cs.EXIT_COMPLETE)
        path = results(self.root)[0]
        (self.root / "internal" / "x" / "scratch.go").write_text("package x\n")
        self.assertTrue(cs.check_result(path, probe=probe, readiness=True)[0])
        parent_tree = subprocess.run(["git", "-C", str(self.root), "rev-parse", "HEAD~1^{tree}"],
                                     capture_output=True, text=True, check=True).stdout.strip()
        for label, tree in {"another commit's tree": parent_tree, "a made-up tree": "f" * 40,
                            "no tree": None}.items():
            with self.subTest(label):
                path.write_text(json.dumps(dict(res, tree=tree)))
                for readiness in (True, False):
                    ok, msg = cs.check_result(path, probe=probe, readiness=readiness)
                    self.assertFalse(ok, f"readiness={readiness}: {msg}")

    def test_an_interrupt_while_exporting_leaves_no_export(self):
        # AC-45. The export directory is owned from the moment it exists, so
        # an interrupt during the clone, the checkout or npm ci removes it,
        # and releases the lock.
        self.commit_coverage()
        own_tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.addCleanup(setattr, tempfile, "tempdir", tempfile.tempdir)
        tempfile.tempdir = str(own_tmp)
        for step in ("clone", "checkout", "npm ci"):
            seen = []  # the export as it stood when npm ci was interrupted
            with self.subTest(step):
                class Interrupted(RealGitProbe):
                    def capture(self, cmd, cwd=None):
                        if cmd[0] == "git" and step in cmd:
                            raise KeyboardInterrupt(f"interrupted during git {step}")
                        return RealGitProbe.capture(self, cmd, cwd)

                    def run(self, cmd, cwd=None, env=None, stdout=None, merge_stderr=False):
                        if " ".join(cmd[:2]) == step:
                            seen.extend(own_tmp.iterdir())
                            raise KeyboardInterrupt("interrupted during npm ci")
                        return RealGitProbe.run(self, cmd, cwd, env, stdout, merge_stderr)

                probe = Interrupted(self.root)
                with self.assertRaises(KeyboardInterrupt):
                    cs.strict(probe, set(), out=self.lines.append, mode="commit")
                if step == "npm ci":
                    self.assertTrue(seen, "the npm ci case must interrupt after the export exists")
                self.assertEqual(list(own_tmp.iterdir()), [], f"interrupted during {step}: export left behind")
                self.assertFalse((self.root / ".git" / "ci-strict" / "lock").exists(), "the lock was kept")

    SIGNAL_CHILD = textwrap.dedent("""
        import importlib.util, signal, sys, time
        from pathlib import Path
        # A runner may start this process with SIGINT ignored; restore
        # Python's default, which is what an interactive run has.
        signal.signal(signal.SIGINT, signal.default_int_handler)
        here, root, ready = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
        spec = importlib.util.spec_from_file_location("t", here / "test_ci_strict.py")
        t = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(t)

        class Slow(t.RealGitProbe):
            def run(self, cmd, cwd=None, env=None, stdout=None, merge_stderr=False):
                if cmd[:2] == ["npm", "ci"]:
                    ready.write_text("in npm ci")
                    time.sleep(60)
                return t.RealGitProbe.run(self, cmd, cwd, env, stdout, merge_stderr)

        if sys.argv[4] == "handled":
            t.cs.cleanup_on_sigterm()
        t.cs.strict(Slow(root), set(), out=lambda _: None, mode="commit")
    """)

    def test_a_real_signal_during_npm_ci_leaves_no_export(self):
        # AC-45, with real signals to a separate process paused inside npm
        # ci, after the export exists. SIGINT is cleaned up by default and
        # SIGTERM once cleanup_on_sigterm is installed, as main() does.
        # SIGKILL cannot be handled and is not tested.
        self.commit_coverage()
        for sig, mode in ((signal.SIGINT, "default"), (signal.SIGTERM, "handled")):
            with self.subTest(sig.name):
                tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
                ready = tmp / "ready"
                (tmp / "t").mkdir()
                child = subprocess.Popen(
                    [sys.executable, "-S", "-c", self.SIGNAL_CHILD, str(HERE), str(self.root), str(ready), mode],
                    env=dict(os.environ, TMPDIR=str(tmp / "t")), stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
                self.addCleanup(child.kill)
                deadline = time.monotonic() + 30
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(ready.exists(), "the child never reached npm ci")
                self.assertTrue(list((tmp / "t").glob("ci-strict-commit-*")), "no export existed to clean up")
                child.send_signal(sig)
                child.wait(timeout=30)
                self.assertEqual(list((tmp / "t").glob("ci-strict-commit-*")), [], f"{sig.name} left the export")
                self.assertFalse((self.root / ".git" / "ci-strict" / "lock").exists(), f"{sig.name} kept the lock")

    def test_main_installs_the_sigterm_cleanup_before_running(self):
        seen = []
        saved = cs.strict, cs.Probe, signal.getsignal(signal.SIGTERM)
        cs.strict = lambda *a, **k: seen.append(signal.getsignal(signal.SIGTERM)) or 0
        cs.Probe = lambda: RealGitProbe(self.root)
        try:
            cs.main(["--commit"])
        finally:
            cs.strict, cs.Probe = saved[:2]
            signal.signal(signal.SIGTERM, saved[2])
        self.assertTrue(seen and callable(seen[0]), "main() ran strict() without a SIGTERM handler")

    def test_the_development_identity_covers_untracked_and_ignored_contents(self):
        probe = RealGitProbe(self.root)
        base = cs.tree_identity(probe)
        u = self.root / "internal" / "x" / "untracked.go"
        u.write_text("package x\n")
        with_untracked = cs.tree_identity(probe)
        self.assertNotEqual(base, with_untracked)
        u.write_text("package x\n// changed\n")
        self.assertNotEqual(with_untracked, cs.tree_identity(probe), "untracked contents are not covered")
        u.unlink()
        i = self.plant("credential_ac_test.go")
        with_ignored = cs.tree_identity(probe)
        self.assertNotEqual(base, with_ignored, "an ignored source file is not covered")
        i.write_text("package x\n")
        self.assertNotEqual(with_ignored, cs.tree_identity(probe), "ignored source contents are not covered")
        # Dependencies and the results file are not check inputs.
        i.unlink()
        (self.root / ".specter-results.json").write_text("{}")
        (self.root / "frontend" / "node_modules" / "x.js").write_text("1")
        self.assertEqual(base, cs.tree_identity(probe))


if __name__ == "__main__":
    unittest.main(verbosity=2)
