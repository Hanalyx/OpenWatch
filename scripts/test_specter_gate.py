#!/usr/bin/env python3
"""Guards for scripts/specter-gate.py.

Standard library only, and run under `python3 -S`, because the gate it tests
declares itself dependency-free and CI installs no Python packages.

Both classes here exist because the gate had a false-green path that looked
fine by inspection:

  * It parsed Specter's JSON and never looked at the exit status, so a run
    that failed while printing a zeroed summary passed.
  * Its .tsx title scan was a raw regex, so a commented-out decoy carrying the
    token kept the gate green while the real test had lost it.
"""

import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GATE = REPO / "scripts" / "specter-gate.py"

_spec = importlib.util.spec_from_file_location("specter_gate", GATE)
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

TOKEN = "frontend-demo/AC-01"


class ReachabilityGateRejectsWhatIsNotACollectedTitle(unittest.TestCase):
    """Drives check_tsx_reachability itself, not a helper it happens to call.

    An earlier version of this file exercised the title scanner directly, so
    replacing the whole reachability check with a no-op left every test green.
    These write real .test.tsx files into a temporary root and feed the
    collected-title map the runner would have produced.

    The decoys matter because two hand-written scanners were wrong about them:
    a raw regex accepted a commented-out test, and the lexer that replaced it
    read `return /test("...")/` as an executable call.
    """

    TOKEN = "frontend-demo/AC-01"

    def run_gate(self, body, collected):
        """Write one annotated .test.tsx and run the real check over it."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            f = root / "demo.test.tsx"
            f.write_text("// @spec frontend-demo\n//\n// @ac AC-01\n" + body)
            titles = {str(f.resolve()): list(collected)}
            try:
                gate.check_tsx_reachability(root=root, titles_by_file=titles)
                return True
            except SystemExit:
                return False

    def test_a_collected_title_passes(self):
        self.assertTrue(self.run_gate(
            f'test("{self.TOKEN} — real", () => {{}});\n', [f"{self.TOKEN} — real"]))

    def test_no_collected_title_fails(self):
        self.assertFalse(self.run_gate(
            'test("some other name", () => {});\n', ["some other name"]))

    def test_a_line_comment_decoy_fails(self):
        # The source LOOKS annotated and covered; the runner collected only
        # the real, untokened title.
        self.assertFalse(self.run_gate(
            f'// test("{self.TOKEN}", () => {{}})\ntest("real", () => {{}});\n',
            ["real"]))

    def test_a_block_comment_decoy_fails(self):
        self.assertFalse(self.run_gate(
            f'/* test("{self.TOKEN}", () => {{}}) */\ntest("real", () => {{}});\n',
            ["real"]))

    def test_an_ordinary_string_decoy_fails(self):
        self.assertFalse(self.run_gate(
            f'const s = \'test("{self.TOKEN}")\';\ntest("real", () => {{}});\n',
            ["real"]))

    def test_a_regex_after_return_decoy_fails(self):
        # The exact shape that defeated the hand-written lexer: a `/` after
        # `return` read as division, then the regex body lexed as code.
        self.assertFalse(self.run_gate(
            'function f() {\n  return /test("frontend-demo\\/AC-01")/;\n}\n'
            'test("real", () => {});\n',
            ["real"]))

    def test_an_unannotated_file_is_ignored(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "x.test.tsx").write_text('test("no annotations here", () => {});\n')
            try:
                gate.check_tsx_reachability(root=root, titles_by_file={})
            except SystemExit:
                self.fail("a file with no @spec must not be checked")


class SummaryDoesNotOutrankExitStatus(unittest.TestCase):
    """A clean summary from a failed run must not pass.

    The gate shells out to `specter`, so the fake below is a `specter` earlier
    on PATH that prints {"errors":0,"warnings":0,"info":0} and exits 1. That
    is the shape the old code accepted.
    """

    def _fake_specter(self, tmp, exit_code, summary):
        d = Path(tmp)
        (d / "specter").write_text(
            "#!/usr/bin/env python3\n"
            "import sys, json\n"
            "if '--version' in sys.argv:\n"
            "    print('specter version ' + open(%r).read().strip()); sys.exit(0)\n"
            "if '--json' in sys.argv:\n"
            "    print(json.dumps({'diagnostics': None, 'summary': %r}))\n"
            "    sys.exit(%d)\n"
            "print('coverage'); sys.exit(0)\n"
            % (str(REPO / ".specter-version"), summary, exit_code)
        )
        (d / "specter").chmod(0o755)
        env = dict(os.environ, PATH=f"{d}:{os.environ['PATH']}")
        # --only annotations: this class is about the summary-versus-exit-code
        # rule, and CI runs this file BEFORE `npm ci`, so nothing here may
        # depend on a Vitest collection.
        return subprocess.run([sys.executable, "-S", str(GATE), "--only", "annotations"],
                              capture_output=True, text=True, env=env, cwd=REPO)

    def test_clean_json_with_a_nonzero_exit_fails(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            r = self._fake_specter(tmp, 1, {"errors": 0, "warnings": 0, "info": 0})
        self.assertNotEqual(r.returncode, 0,
                            "a failed specter run reporting a clean summary must not pass")
        self.assertIn("does not describe the run", r.stdout + r.stderr)

    def test_clean_json_with_a_zero_exit_passes_this_stage(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            r = self._fake_specter(tmp, 0, {"errors": 0, "warnings": 0, "info": 0})
        self.assertIn("annotations clean", r.stdout)


class EveryStageIsWiredIntoMain(unittest.TestCase):
    """main() must call every stage, proven WITHOUT frontend dependencies.

    An earlier version of this guard ran the whole gate and skipped when
    Vitest was unavailable. CI runs this file before `npm ci`, so the skip
    fired there and deleting the .tsx stage from main() passed a clean build.
    A guard that opts out on the machine it is meant to protect is not a
    guard.

    Stubbing the four stage functions removes every external dependency, so
    this can never skip.
    """

    def dispatch(self, argv):
        calls = []
        originals = {}
        names = ("check_version", "check_annotations",
                 "check_tsx_reachability", "check_structural_coverage")
        for n in names:
            originals[n] = getattr(gate, n)
            setattr(gate, n, (lambda n: lambda *a, **k: calls.append(n))(n))
        try:
            gate.main(argv)
        finally:
            for n, fn in originals.items():
                setattr(gate, n, fn)
        return calls

    def test_a_full_run_calls_every_stage_exactly_once(self):
        calls = self.dispatch([])
        for stage in ("check_version", "check_annotations",
                      "check_tsx_reachability", "check_structural_coverage"):
            self.assertEqual(calls.count(stage), 1,
                             f"main() called {stage} {calls.count(stage)} times; "
                             "every stage must run exactly once")

    def test_only_tsx_runs_that_stage_alone(self):
        calls = self.dispatch(["--only", "tsx"])
        self.assertEqual(calls, ["check_tsx_reachability"])

    def test_each_named_stage_dispatches_to_itself(self):
        for stage, fn in (
            ("version", "check_version"),
            ("annotations", "check_annotations"),
            ("tsx", "check_tsx_reachability"),
            ("coverage", "check_structural_coverage"),
        ):
            with self.subTest(stage=stage):
                self.assertEqual(self.dispatch(["--only", stage]), [fn])

    def test_an_unknown_stage_is_refused(self):
        with self.assertRaises(SystemExit):
            self.dispatch(["--only", "nonsense"])


class CollectedTitlesDoNotCrossFiles(unittest.TestCase):
    """Two files may share a basename. Their titles must not."""

    TOKEN = "frontend-demo/AC-01"

    def test_a_same_named_file_elsewhere_does_not_satisfy_an_annotation(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = root / "a" / "demo.test.tsx"
            b = root / "b" / "demo.test.tsx"
            for f in (a, b):
                f.parent.mkdir(parents=True)
                f.write_text("// @spec frontend-demo\n//\n// @ac AC-01\n"
                             'test("whatever", () => {});\n')
            # The token was collected for a/ only. b/ must still fail.
            titles = {str(a.resolve()): [f"{self.TOKEN} — real"]}
            with self.assertRaises(SystemExit):
                gate.check_tsx_reachability(root=root, titles_by_file=titles)

    def test_the_file_that_owns_the_title_passes_alone(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = root / "a" / "demo.test.tsx"
            a.parent.mkdir(parents=True)
            a.write_text("// @spec frontend-demo\n//\n// @ac AC-01\n"
                         'test("whatever", () => {});\n')
            titles = {str(a.resolve()): [f"{self.TOKEN} — real"]}
            gate.check_tsx_reachability(root=root, titles_by_file=titles)


class GateIsStandardLibraryOnly(unittest.TestCase):
    def test_the_gate_imports_no_third_party_module(self):
        r = subprocess.run([sys.executable, "-S", "-c",
                            f"import importlib.util as u;"
                            f"s=u.spec_from_file_location('g', {str(GATE)!r});"
                            f"m=u.module_from_spec(s);s.loader.exec_module(m)"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0,
                         f"the gate does not import under -S:\n{r.stderr[-2000:]}")


if __name__ == "__main__":
    unittest.main(verbosity=2, argv=[sys.argv[0]])
