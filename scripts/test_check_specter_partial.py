#!/usr/bin/env python3
"""Tests for scripts/check-specter-partial.py (release-ci-gates AC-31).

Run: python3 -S scripts/test_check_specter_partial.py
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "check-specter-partial.py")


def stream(*tests):
    return "".join(json.dumps({"Action": "pass", "Package": "p", "Test": t}) + "\n" for t in tests)


STREAM = stream("TestX/release-changelog/AC-01", "TestY/release-ci-gates/AC-16", "TestZ")


def entry(spec, ac, status):
    return {"spec_id": spec, "ac_id": ac, "status": status, "passed": status == "passed"}


GOOD = {"results": [entry("release-changelog", "AC-01", "passed"),
                    entry("release-ci-gates", "AC-16", "skipped")]}


class CheckSpecterPartial(unittest.TestCase):
    def run_check(self, results=GOOD, raw=None, missing=False, since_offset=-60.0, stream_text=STREAM):
        with tempfile.TemporaryDirectory() as d:
            rpath, spath = os.path.join(d, ".specter-results.json"), os.path.join(d, "s.json")
            with open(spath, "w", encoding="utf-8") as f:
                f.write(stream_text)
            if not missing:
                with open(rpath, "w", encoding="utf-8") as f:
                    f.write(raw if raw is not None else json.dumps(results))
            since = time.time() + since_offset
            p = subprocess.run([sys.executable, "-S", SCRIPT, "--results", rpath, "--stream", spath,
                                "--since", repr(since)], capture_output=True, text=True)
            return p.returncode, p.stdout + p.stderr

    def assertFails(self, needle, **kw):
        code, out = self.run_check(**kw)
        self.assertNotEqual(code, 0, f"accepted, want a failure naming {needle!r}:\n{out}")
        self.assertIn(needle, out)

    def test_fresh_results_with_a_pass_and_no_failure_pass_labeled_partial(self):
        code, out = self.run_check()
        self.assertEqual(code, 0, out)
        self.assertIn("PARTIAL results", out)
        self.assertIn("Coverage thresholds are not evaluated", out)

    def test_missing_or_malformed_results_fail(self):
        self.assertFails("is missing", missing=True)
        self.assertFails("is malformed", raw="{not json")
        self.assertFails("is malformed", raw="[]")
        self.assertFails("is malformed", results={"results": "x"})
        self.assertFails("entry 0 is malformed", results={"results": [{"spec_id": "a", "ac_id": "AC-01"}]})
        self.assertFails("entry 0 is malformed", results={"results": [entry("a", "AC-01", "unknown")]})

    def test_stale_results_fail(self):
        # Written before this run's ingest started.
        self.assertFails("is stale", since_offset=+60.0)
        # Or naming criteria this run's stream did not exercise.
        foreign = {"results": GOOD["results"] + [entry("system-db", "AC-03", "passed")]}
        self.assertFails("did not exercise", results=foreign)

    def test_a_failed_criterion_fails(self):
        bad = {"results": [entry("release-changelog", "AC-01", "passed"),
                           entry("release-ci-gates", "AC-16", "failed")]}
        self.assertFails("criterion failed: release-ci-gates/AC-16", results=bad)

    def test_zero_passes_fail(self):
        self.assertFails("no criterion passed", results={"results": [entry("release-ci-gates", "AC-16", "skipped")]})
        self.assertFails("no criterion passed", results={"results": []})


if __name__ == "__main__":
    unittest.main(verbosity=2)
