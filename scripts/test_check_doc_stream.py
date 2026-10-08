#!/usr/bin/env python3
"""Tests for scripts/check-doc-stream.py (release-ci-gates AC-30).

Run: python3 -S scripts/test_check_doc_stream.py
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "check-doc-stream.py")
PKG = "github.com/Hanalyx/openwatch/packaging/tests"
BUILD = "set OPENWATCH_PACKAGING_BUILD=1 to run native package build tests (full make rpm/deb)"


def ev(action, test=None, output=None, pkg=PKG, **extra):
    e = {"Action": action, "Package": pkg}
    if test is not None:
        e["Test"] = test
    if output is not None:
        e["Output"] = output
    e.update(extra)
    return json.dumps(e)


def skipped(test, message, line=42):
    """The events go test -json writes for a test that calls t.Skip(message)."""
    return [
        ev("run", test),
        ev("output", test, f"=== RUN   {test}\n"),
        ev("output", test, f"    package_test.go:{line}: {message}\n"),
        ev("output", test, f"--- SKIP: {test} (0.00s)\n"),
        ev("skip", test, Elapsed=0),
    ]


def passed(test):
    return [ev("run", test), ev("output", test, f"--- PASS: {test} (0.01s)\n"), ev("pass", test, Elapsed=0.01)]


GOOD = passed("TestA") + skipped("TestB/release-package-build/AC-01", BUILD) + [ev("pass", Elapsed=1.0)]


class CheckDocStream(unittest.TestCase):
    def run_check(self, lines=None, raw=None, missing=False):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "go-test-docs.json")
            if not missing:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(raw if raw is not None else "\n".join(lines) + "\n")
            p = subprocess.run([sys.executable, "-S", SCRIPT, "--stream", path],
                               capture_output=True, text=True)
            return p.returncode, p.stdout + p.stderr

    def assertFails(self, needle, **kw):
        code, out = self.run_check(**kw)
        self.assertNotEqual(code, 0, f"accepted, want a failure naming {needle!r}:\n{out}")
        self.assertIn(needle, out)

    def test_a_clean_partial_run_passes_and_is_labeled_partial(self):
        code, out = self.run_check(GOOD)
        self.assertEqual(code, 0, out)
        self.assertIn("PARTIAL validation", out)
        self.assertIn(f"not run (1): {BUILD}", out)

    def test_every_permitted_reason_is_accepted(self):
        for msg in (BUILD,
                    "set OPENWATCH_ROLLBACK_IMAGE (for example postgres:16) to run the rollback blocks against PostgreSQL",
                    "set OPENWATCH_KENSA_COMPAT_{IMAGE,KIND,OLD_DIR,NEW_DIR} to run the container pairing test"):
            with self.subTest(msg=msg):
                code, out = self.run_check(passed("TestA") + skipped("TestS", msg) + [ev("pass")])
                self.assertEqual(code, 0, out)

    def test_missing_empty_and_malformed_streams_fail(self):
        self.assertFails("is missing", missing=True)
        self.assertFails("is empty", raw="\n\n")
        self.assertFails("is not JSON", raw=GOOD[0] + "\n{\"Action\":\"pa\n")
        self.assertFails("not a JSON object", raw="[1]\n")

    def test_the_package_result_must_be_one_pass_for_packaging_tests(self):
        self.assertFails("want exactly one package result", lines=passed("TestA"))
        self.assertFails("want exactly one package result", lines=GOOD + [ev("pass")])
        self.assertFails("ended 'fail'", lines=passed("TestA") + [ev("fail")])
        self.assertFails("this path tests only", lines=passed("TestA") + [ev("pass", pkg="example.com/other")])

    def test_a_build_failure_fails(self):
        lines = [json.dumps({"ImportPath": PKG + " [" + PKG + ".test]", "Action": "build-fail"}),
                 ev("fail", FailedBuild=PKG + " [" + PKG + ".test]")]
        self.assertFails("build failure", lines=lines)

    def test_a_failed_test_or_no_pass_fails(self):
        self.assertFails("test failed: TestC", lines=GOOD[:-1] + [ev("fail", "TestC"), ev("pass")])
        self.assertFails("no test passed", lines=skipped("TestB", BUILD) + [ev("pass")])

    def test_a_skip_for_another_reason_fails(self):
        for msg in ("set OPENWATCH_TEST_DSN to run FIPS runtime test",
                    "git not available",
                    "rpm not available: exec: \"rpm\": executable file not found in $PATH",
                    BUILD + " (and more)"):
            with self.subTest(msg=msg):
                self.assertFails("does not permit", lines=passed("TestA") + skipped("TestS", msg) + [ev("pass")])

    def test_a_skip_without_a_message_fails(self):
        lines = passed("TestA") + [ev("run", "TestS"), ev("output", "TestS", "--- SKIP: TestS (0.00s)\n"),
                                   ev("skip", "TestS"), ev("pass")]
        self.assertFails("(no skip message)", lines=lines)

    def test_a_permitted_message_counts_only_as_the_skipped_tests_own_last_line(self):
        # The permitted text logged earlier, then a different skip reason.
        lines = passed("TestA") + [
            ev("run", "TestS"),
            ev("output", "TestS", f"    package_test.go:10: {BUILD}\n"),
            ev("output", "TestS", "    package_test.go:11: git not available\n"),
            ev("skip", "TestS"), ev("pass")]
        self.assertFails("git not available", lines=lines)
        # The permitted text in ANOTHER test's output does not excuse this skip.
        lines = [ev("output", "TestA", f"    package_test.go:10: {BUILD}\n")] + passed("TestA") + [
            ev("run", "TestS"), ev("output", "TestS", "--- SKIP: TestS (0.00s)\n"), ev("skip", "TestS"), ev("pass")]
        self.assertFails("(no skip message)", lines=lines)

    def test_a_permitted_message_on_a_test_that_passed_is_not_a_skip(self):
        lines = [ev("run", "TestA"), ev("output", "TestA", f"    package_test.go:10: {BUILD}\n"),
                 ev("pass", "TestA"), ev("pass")]
        code, out = self.run_check(lines)
        self.assertEqual(code, 0, out)
        self.assertIn("1 passed, 0 failed, 0 not run", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
