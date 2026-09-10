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


class TitleScannerKnowsWhatCodeIs(unittest.TestCase):
    """Only a string a test/it/describe call opens counts as a title."""

    def found(self, src):
        return any(TOKEN in t for t in gate.test_titles(src))

    def test_a_line_comment_decoy_is_not_a_title(self):
        self.assertFalse(self.found(
            f'// test("{TOKEN}", () => {{}})\ntest("real title", () => {{}})'))

    def test_a_block_comment_decoy_is_not_a_title(self):
        self.assertFalse(self.found(
            f'/* test("{TOKEN}", () => {{}}) */\ntest("real title", () => {{}})'))

    def test_an_ordinary_string_containing_a_call_is_not_a_title(self):
        self.assertFalse(self.found(
            f"const s = 'test(\"{TOKEN}\", () => {{}})';\ntest(\"real title\", () => {{}})"))

    def test_a_regex_literal_containing_a_call_is_not_a_title(self):
        self.assertFalse(self.found(
            f'const re = /test\\("{TOKEN}"\\)/;\ntest("real title", () => {{}})'))

    def test_a_real_executable_title_is_found(self):
        self.assertTrue(self.found(f'test("{TOKEN} — does the thing", () => {{}})'))

    def test_a_nested_it_title_is_found(self):
        self.assertTrue(self.found(
            f"describe('outer', () => {{\n  it('{TOKEN} — inner', () => {{}});\n}});"))

    def test_a_word_ending_in_test_does_not_open_a_title(self):
        # `latest(` and `mytest(` are not the test() function.
        self.assertFalse(self.found(f'latest("{TOKEN}");'))


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
        return subprocess.run([sys.executable, "-S", str(GATE)],
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
        # The annotation stage is satisfied; a later stage may still fail on
        # the fake's coverage output, which is not what this test is about.
        self.assertIn("annotations clean", r.stdout)


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
