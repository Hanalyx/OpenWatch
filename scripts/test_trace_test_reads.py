#!/usr/bin/env python3
"""Tests for the test-read trace diagnostic.

    python3 -S scripts/test_trace_test_reads.py

The parser is fed strace -f -y lines in the forms strace prints, including
split (unfinished and resumed) calls. The report is built over a throwaway
git repository holding a copy of the real go-ci.yml, so the documentation
pattern is the workflow's own. For run, `strace` and `go` are fakes on PATH
that record their arguments, so the tests show what is invoked without
tracing a real kernel. No network.

One class per criterion of spec ci-test-read-trace.
"""

import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_here = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("trace_test_reads", _here / "trace-test-reads.py")
tr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tr)

GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def read_text(p):
    with open(p) as f:
        return f.read()


class ParsesStrace(unittest.TestCase):
    """AC-01: successful opens and executions are read from strace -f -y output."""

    def test_successful_opens_are_kept_and_failures_are_not(self):
        lines = [
            '1201 openat(AT_FDCWD, "docs/a.md", O_RDONLY|O_CLOEXEC) = 3</repo/docs/a.md>',
            '1201 openat(AT_FDCWD, "missing.md", O_RDONLY) = -1 ENOENT (No such file or directory)',
            '1202 open("/repo/README.md", O_RDONLY) = 4</repo/README.md>',
            '1203 openat2(AT_FDCWD, "x", {flags=O_RDONLY, resolve=0}, 24) = 5</repo/x>',
        ]
        self.assertEqual(tr.opened_paths(lines), {"/repo/docs/a.md", "/repo/README.md", "/repo/x"})

    def test_a_split_call_counts_its_resumed_result(self):
        lines = ['1300 openat(AT_FDCWD, "docs/b.md", O_RDONLY <unfinished ...>',
                 '1301 read(3, "x", 1) = 1',
                 '1300 <... openat resumed>) = 6</repo/docs/b.md>']
        self.assertEqual(tr.opened_paths(lines), {"/repo/docs/b.md"})

    def test_executions_with_an_absolute_program_count(self):
        lines = ['1400 execve("/repo/scripts/x.sh", ["/repo/scripts/x.sh"], 0x7ffd /* 3 vars */) = 0',
                 '1401 execve("relative.sh", ["relative.sh"], 0x7ffd /* 3 vars */) = 0',
                 '1402 execve("/repo/scripts/y.sh", ["y"], 0x7ffd /* 3 vars */) = -1 ENOENT (No such file)']
        self.assertEqual(tr.opened_paths(lines), {"/repo/scripts/x.sh"})

    def test_escaped_paths_are_unescaped(self):
        lines = ['1500 openat(AT_FDCWD, "a", O_RDONLY) = 3</repo/docs/caf\\xc3\\xa9 \\"q\\".md>']
        self.assertEqual(tr.opened_paths(lines), {'/repo/docs/caf\xc3\xa9 "q".md'})


class ReadsThePattern(unittest.TestCase):
    """AC-02: the documentation pattern is go-ci.yml's own, read at run time."""

    def test_the_real_workflow_classifies_code_and_documentation(self):
        p = tr.code_pattern((_here.parent / ".github" / "workflows" / "go-ci.yml").read_text())
        for path in ("internal/server/x.go", "specs/a.spec.yaml", ".github/workflows/go-ci.yml",
                     "THIRD-PARTY-NOTICES.md", "scripts/x.py", "packaging/version.env"):
            self.assertTrue(p.search(path), path)
        for path in ("docs/guides/QUICKSTART.md", "README.md", "CHANGELOG.md", "SECURITY.md",
                     ".github/BRANCH_MANAGEMENT.md"):
            self.assertFalse(p.search(path), path)

    def test_zero_or_two_selector_patterns_are_refused(self):
        line = "if grep -qE '^(cmd/)' <<<\"$changed\"; then\n"
        for text in ("no selector here\n", line + line):
            with self.subTest(n=text.count("grep")):
                with self.assertRaises(tr.TraceError):
                    tr.code_pattern(text)


class ReportFixture(unittest.TestCase):
    """A throwaway repository with the real go-ci.yml, and helpers to write traces."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="trrep-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.repo = os.path.realpath(os.path.join(self.dir, "repo"))
        self.out = os.path.join(self.dir, "out")
        os.makedirs(os.path.join(self.out, "traces"))
        for rel, text in (("docs/guide.md", "g\n"), ("README.md", "r\n"), ("SECURITY.md", "s\n"),
                          ("internal/x/x.go", "package x\n"), ("frontend/a.ts", "x\n"),
                          ("docs/unread.md", "u\n")):
            p = os.path.join(self.repo, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(text)
        os.makedirs(os.path.join(self.repo, ".github", "workflows"))
        shutil.copy(_here.parent / ".github" / "workflows" / "go-ci.yml",
                    os.path.join(self.repo, ".github", "workflows"))
        env = dict(os.environ, **GIT_ENV)
        for cmd in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-q", "-m", "c"]):
            subprocess.run(["git", "-C", self.repo] + cmd, check=True, env=env)
        with open(os.path.join(self.repo, "untracked.md"), "w") as f:
            f.write("u\n")

    def trace(self, suite, paths, exit=0, kind=None):
        name = "traces/%s.trace" % suite.replace("/", "_").replace(":", "_")
        with open(os.path.join(self.out, name), "w") as f:
            for i, p in enumerate(paths):
                f.write('%d openat(AT_FDCWD, "x", O_RDONLY) = 3<%s>\n' % (100 + i, p))
        s = {"name": suite, "traces": [name]}
        if kind:
            s["kind"] = kind
        else:
            s["exit"] = exit
        return s

    def report(self, suites, stream="", go_exit=0):
        with open(os.path.join(self.out, "manifest.json"), "w") as f:
            json.dump({"commit": "c" * 40, "go_exit": go_exit, "suites": suites}, f)
        with open(os.path.join(self.out, "go-test.json"), "w") as f:
            f.write(stream)
        return tr.build_report(self.out, repo=self.repo)

    def at(self, rel):
        return os.path.join(self.repo, rel)


class ReportsGaps(ReportFixture):
    """AC-03: gaps, tests not exercised, unread files and the limits are reported."""

    def test_a_documentation_file_read_outside_the_documentation_path_is_a_gap(self):
        r = self.report([
            self.trace("go:./internal/x", [self.at("docs/guide.md"), self.at("internal/x/x.go")],
                       kind="go"),
            self.trace("vitest", [self.at("README.md")]),
            self.trace("go:./packaging/tests", [self.at("SECURITY.md")], kind="go"),
            self.trace("python:test_a.py", [self.at("SECURITY.md"), self.at("docs/guide.md")]),
        ])
        self.assertEqual(r["gaps"], [{"path": "README.md", "read_by": ["vitest"]},
                                     {"path": "docs/guide.md", "read_by": ["go:./internal/x"]}])

    def test_reads_by_the_documentation_path_code_files_and_strangers_are_not_gaps(self):
        r = self.report([
            self.trace("go:./packaging/tests", [self.at("docs/guide.md")], kind="go"),
            self.trace("python:test_a.py", [self.at("README.md")]),
            self.trace("go:./internal/x", [self.at("internal/x/x.go"), self.at("untracked.md"),
                                           "/etc/hosts", self.at("docs/../SECURITY.md.bak")],
                       kind="go"),
        ])
        self.assertEqual(r["gaps"], [])
        self.assertIn("docs/unread.md", r["unread"])
        self.assertNotIn("docs/guide.md", r["unread"])

    def test_a_suite_named_like_the_documentation_package_is_not_in_it(self):
        r = self.report([self.trace("go:./packaging/testsX", [self.at("README.md")], kind="go")])
        self.assertEqual(r["gaps"], [{"path": "README.md", "read_by": ["go:./packaging/testsX"]}])

    def test_a_path_outside_the_repository_is_never_taken_for_a_tracked_file(self):
        # Sliced at the root's length, this outside path would read as
        # docs/guide.md: a copy of the tree elsewhere, for instance.
        root = os.path.realpath(self.repo) + "/"
        outside = "/" + "x" * (len(root) - 1) + "docs/guide.md"
        self.assertNotEqual(outside[:len(root)], root)
        r = self.report([self.trace("go:./internal/x", [outside], kind="go")])
        self.assertEqual(r["gaps"], [])
        self.assertIn("docs/guide.md", r["unread"])

    def test_tests_not_exercised_are_reported(self):
        stream = "\n".join(json.dumps(e) for e in [
            {"Action": "output", "Package": "p/a", "Test": "TestS", "Output": "=== RUN   TestS\n"},
            {"Action": "output", "Package": "p/a", "Test": "TestS",
             "Output": "    a_test.go:9: set OPENWATCH_TEST_DSN to run DB integration tests\n"},
            {"Action": "output", "Package": "p/a", "Test": "TestS", "Output": "--- SKIP: TestS\n"},
            {"Action": "skip", "Package": "p/a", "Test": "TestS"},
            {"Action": "output", "Package": "p/b", "Output": "?   \tp/b\t[no test files]\n"},
            {"Action": "fail", "Package": "p/c"},
            {"Action": "pass", "Package": "p/d"}])
        r = self.report([self.trace("python:test_bad.py", [], exit=1),
                         {"name": "vitest", "exit": None, "traces": []}], stream)
        ne = r["not_exercised"]
        self.assertEqual(ne["skipped_tests"], [{"package": "p/a", "test": "TestS",
                                                "reason": "a_test.go:9: set OPENWATCH_TEST_DSN "
                                                          "to run DB integration tests"}])
        self.assertEqual(ne["no_test_files"], ["p/b"])
        self.assertEqual(ne["failed_packages"], ["p/c"])
        self.assertEqual(ne["failed_suites"], ["python:test_bad.py"])
        self.assertEqual(ne["suites_not_run"], ["vitest"])

    def test_a_go_package_is_judged_by_the_stream_not_the_overall_exit(self):
        r = self.report([self.trace("go:./internal/x", [], kind="go")],
                        json.dumps({"Action": "pass", "Package": "p/x"}))
        self.assertEqual(r["not_exercised"]["failed_suites"], [])
        self.assertEqual(r["not_exercised"]["suites_not_run"], [])

    def test_the_report_states_its_limits_and_the_exit_follows_the_gaps(self):
        r = self.report([self.trace("go:./internal/x", [self.at("docs/guide.md")], kind="go")])
        md = read_text(os.path.join(self.out, "report.md"))
        self.assertIn("A diagnostic, not a gate.", md)
        for limit in tr.LIMITS:
            self.assertIn(limit, md)
        self.assertIn("- `docs/guide.md`: go:./internal/x", md)
        index = json.loads(read_text(os.path.join(self.out, "index.json")))
        self.assertEqual(index["go:./internal/x"], ["docs/guide.md"])
        real_repo = tr.REPO
        tr.REPO = Path(self.repo)
        try:
            code = tr.main(["report", "--out", self.out], out=io.StringIO())
            self.assertEqual(code, 1, "a gap fails the diagnostic run")
            self.report([self.trace("go:./packaging/tests", [self.at("docs/guide.md")],
                                    kind="go")])
            self.assertEqual(tr.main(["report", "--out", self.out], out=io.StringIO()), 0)
        finally:
            tr.REPO = real_repo
        self.assertEqual(r["documentation_files"], 4)

    def test_a_report_without_a_run_is_refused(self):
        with self.assertRaises(tr.TraceError):
            tr.build_report(os.path.join(self.dir, "nothing"), repo=self.repo)


FAKE_STRACE = r'''#!/bin/sh
# Record the arguments, write one open line to the -o file, run the command.
printf '%s\n' "$*" >> "$FAKES/strace.log"
out=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    --) shift; break ;;
    *) shift ;;
  esac
done
printf '1 openat(AT_FDCWD, "f", O_RDONLY) = 3<%s/README.md>\n' "$REPO" > "$out"
exec "$@"
'''

FAKE_GO = r'''#!/bin/sh
# Record the arguments, then run the -exec wrapper once from a package dir.
printf '%s\n' "$*" >> "$FAKES/go.log"
wrapper=""
prev=""
for a in "$@"; do
  [ "$prev" = "-exec" ] && wrapper=$a
  prev=$a
done
( cd "$REPO/internal/x" && "$wrapper" /bin/true )
printf '{"Action":"pass","Package":"example/internal/x"}\n'
'''


class ReportsCompleteness(ReportFixture):
    """AC-06: go test's own result and unfinished packages make an incomplete trace fail."""

    def exit_code(self):
        real = tr.REPO
        tr.REPO = Path(self.repo)
        try:
            return tr.main(["report", "--out", self.out], out=io.StringIO())
        finally:
            tr.REPO = real

    def test_a_timeout_with_a_started_package_is_incomplete(self):
        # The reviewer's first reproduction: go_exit "timeout", a start event,
        # no completion.
        stream = json.dumps({"Action": "start", "Package": "p/slow"})
        r = self.report([self.trace("python:test_a.py", [])], stream, go_exit="timeout")
        self.assertEqual(r["go_test"], {"exit": "timeout"})
        self.assertIn("go test timed out", r["incomplete"])
        self.assertEqual(r["not_exercised"]["unfinished_packages"], ["p/slow"])
        self.assertTrue(any("started without a result: p/slow" in i for i in r["incomplete"]))
        self.assertEqual(self.exit_code(), 3)
        md = read_text(os.path.join(self.out, "report.md"))
        self.assertIn("**Incomplete trace.**", md)
        self.assertIn("go test exit: timeout.", md)

    def test_an_early_go_failure_with_no_package_is_incomplete(self):
        # The reviewer's second reproduction: go_exit 1 from a module download
        # error before any package ran; the stream names no package.
        stream = json.dumps({"Action": "output", "Output": "go: downloading example.com/m "
                                                          "v1.0.0: connection refused\n"})
        r = self.report([self.trace("python:test_a.py", [])], stream, go_exit=1)
        self.assertEqual(r["not_exercised"]["failed_packages"], [])
        self.assertTrue(any("exited 1 and no package failed" in i for i in r["incomplete"]))
        self.assertEqual(self.exit_code(), 3)

    def test_one_failed_package_is_that_package_only(self):
        stream = "\n".join(json.dumps(e) for e in [
            {"Action": "start", "Package": "p/a"}, {"Action": "fail", "Package": "p/a"},
            {"Action": "start", "Package": "p/b"}, {"Action": "pass", "Package": "p/b"}])
        r = self.report([self.trace("go:./p/a", [], kind="go"),
                         self.trace("go:./p/b", [], kind="go")], stream, go_exit=1)
        ne = r["not_exercised"]
        self.assertEqual(ne["failed_packages"], ["p/a"])
        self.assertEqual(ne["unfinished_packages"], [])
        self.assertEqual(ne["failed_suites"], [])
        self.assertFalse(any("no package failed" in i for i in r["incomplete"]))
        self.assertIn("1 package(s) failed, so their reads may be cut short", r["incomplete"])
        self.assertEqual(self.exit_code(), 3)

    def test_go_not_run_and_suites_not_run_are_incomplete(self):
        r = self.report([{"name": "vitest", "exit": None, "traces": []}], go_exit=None)
        self.assertIn("go test did not run", r["incomplete"])
        self.assertIn("suite(s) did not run: vitest", r["incomplete"])

    def test_a_complete_trace_exits_0_and_gaps_still_exit_1(self):
        stream = "\n".join(json.dumps(e) for e in [
            {"Action": "start", "Package": "p/a"}, {"Action": "pass", "Package": "p/a"},
            {"Action": "output", "Package": "p/n", "Output": "?   \tp/n\t[no test files]\n"},
            {"Action": "skip", "Package": "p/n"}])
        r = self.report([self.trace("go:./p/a", [], kind="go")], stream)
        self.assertEqual(r["incomplete"], [])
        self.assertIn("Complete:", read_text(os.path.join(self.out, "report.md")))
        self.assertEqual(self.exit_code(), 0)
        self.report([self.trace("go:./internal/x", [self.at("docs/guide.md")], kind="go")],
                    json.dumps({"Action": "start", "Package": "p/a"}), go_exit="timeout")
        self.assertEqual(self.exit_code(), 1, "gaps report first; the report still says incomplete")


class RunsUntimedAndTraced(unittest.TestCase):
    """AC-04: run disables caching, traces every binary and suite, and keeps the evidence."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="trrun-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.repo = os.path.realpath(os.path.join(self.dir, "repo"))
        self.fakes = os.path.join(self.dir, "fakes")
        bin_ = os.path.join(self.dir, "bin")
        for d in (os.path.join(self.repo, "internal", "x"), os.path.join(self.repo, "scripts"),
                  self.fakes, bin_):
            os.makedirs(d, exist_ok=True)
        with open(os.path.join(self.repo, "scripts", "test_one.py"), "w") as f:
            f.write("print('ok')\n")
        with open(os.path.join(self.repo, "README.md"), "w") as f:
            f.write("r\n")
        env = dict(os.environ, **GIT_ENV)
        for cmd in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-q", "-m", "c"]):
            subprocess.run(["git", "-C", self.repo] + cmd, check=True, env=env)
        for name, body in (("strace", FAKE_STRACE), ("go", FAKE_GO)):
            p = os.path.join(bin_, name)
            with open(p, "w") as f:
                f.write(body)
            os.chmod(p, 0o755)
        old = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(old)))
        os.environ.update(FAKES=self.fakes, REPO=self.repo,
                          PATH=bin_ + os.pathsep + os.environ.get("PATH", ""))
        self.out = os.path.join(self.dir, "out")

    def test_a_run_traces_go_python_and_records_vitest_as_not_run(self):
        suites = tr.run(self.out, ["./..."], ["-p", "4"], repo=self.repo)
        go_args = read_text(os.path.join(self.fakes, "go.log")).split()
        self.assertEqual(go_args[:4], ["test", "-count=1", "-json", "-exec"])
        self.assertIn("-p", go_args)
        names = [s["name"] for s in suites]
        self.assertIn("go:./internal/x", names)
        self.assertIn("python:test_one.py", names)
        vitest = [s for s in suites if s["name"] == "vitest"][0]
        self.assertIsNone(vitest["exit"])
        self.assertIn("node_modules is absent", vitest["reason"])
        straced = read_text(os.path.join(self.fakes, "strace.log")).splitlines()
        self.assertEqual(len(straced), 2, "the Go binary and the Python check, each traced")
        for line in straced:
            for flag in ("-f", "-qq", "-y", "trace=open,openat,openat2,execve"):
                self.assertIn(flag, line.split())
        self.assertTrue(any("/bin/true" in l for l in straced))
        m = json.loads(read_text(os.path.join(self.out, "manifest.json")))
        self.assertEqual(m["commit"], subprocess.run(["git", "-C", self.repo, "rev-parse", "HEAD"],
                                                     capture_output=True, text=True).stdout.strip())
        for s in m["suites"]:
            for t in s["traces"]:
                self.assertIn("README.md", read_text(os.path.join(self.out, t)))
        self.assertTrue(os.path.isfile(os.path.join(self.out, "go-test.json")))

    def test_the_workflows_flag_form_is_accepted(self):
        # The workflow passes --go-flags="-p 4 -timeout 1800s"; argparse refuses
        # a value starting with - in the two-word form.
        wf = read_text(_here.parent / ".github" / "workflows" / "trace-test-reads.yml")
        self.assertIn('--go-flags="-p 4 -timeout 1800s"', wf)
        real = tr.REPO
        tr.REPO = Path(self.repo)
        try:
            code = tr.main(["run", "--out", self.out, '--go-flags=-p 4 -timeout 1800s'],
                           out=io.StringIO())
        finally:
            tr.REPO = real
        self.assertEqual(code, 0)
        self.assertIn("-timeout 1800s", read_text(os.path.join(self.fakes, "go.log")))

    def test_an_output_directory_in_use_is_refused(self):
        os.makedirs(self.out)
        with open(os.path.join(self.out, "x"), "w") as f:
            f.write("x")
        with self.assertRaises(tr.TraceError):
            tr.run(self.out, ["./..."], repo=self.repo)

    def test_caching_and_the_wrapper_cannot_be_overridden(self):
        real = tr.REPO
        tr.REPO = Path(self.repo)  # so the guard, not a missing repository, refuses
        try:
            for flags in ("-count=2", "-exec /bin/env", "-p 4 -count 3"):
                with self.subTest(flags=flags):
                    out = io.StringIO()
                    code = tr.main(["run", "--out", self.out, "--go-flags=" + flags], out=out)
                    self.assertEqual(code, 2)
                    self.assertIn("may not set -count or -exec", out.getvalue())
        finally:
            tr.REPO = real
        self.assertFalse(os.path.exists(os.path.join(self.fakes, "go.log")))


class StaysADiagnostic(unittest.TestCase):
    """AC-05: the workflow runs weekly or by hand, reads only, and gates nothing."""

    def setUp(self):
        self.wf = read_text(_here.parent / ".github" / "workflows" / "trace-test-reads.yml")

    def test_it_runs_only_on_a_schedule_or_by_hand(self):
        top = self.wf.split("\njobs:")[0]
        on = top.split("\non:\n", 1)[1].split("\n\n", 1)[0]
        keys = [l.strip().rstrip(":") for l in on.splitlines() if l.startswith("  ") and
                not l.startswith("    ")]
        self.assertEqual(keys, ["schedule", "workflow_dispatch"])
        self.assertIn("permissions:\n  contents: read\n", top)

    def test_no_gate_or_required_check_reads_it(self):
        gates = read_text(_here.parent / "release" / "gates.toml")
        goci = read_text(_here.parent / ".github" / "workflows" / "go-ci.yml")
        for text in (gates, goci):
            self.assertNotIn("trace-test-reads", text)
            self.assertNotIn("Test read trace", text)

    def test_it_runs_the_tool_and_keeps_the_trace(self):
        self.assertIn("scripts/trace-test-reads.py run", self.wf)
        self.assertIn("scripts/trace-test-reads.py report", self.wf)
        self.assertIn("GITHUB_STEP_SUMMARY", self.wf)
        self.assertIn("if: always()", self.wf)
        self.assertIn("OPENWATCH_TEST_DSN:", self.wf)


if __name__ == "__main__":
    unittest.main(verbosity=2)
