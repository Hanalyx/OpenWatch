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
import subprocess
import sys
import tempfile
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

    def run(self, cmd, cwd=None, env=None, stdout=None):
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
