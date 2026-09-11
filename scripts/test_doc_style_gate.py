#!/usr/bin/env python3
"""Gate tests for the documentation style check.

Runs under `python3 -S` with nothing but the standard library, because the thing under test
claims to need nothing else and a claim no one checks is not a contract.

Two kinds of test live here.

Structural tests read the three production callers (the Makefile, the CI workflow and the
pre-commit configuration) and assert that each one reaches the full tracked tree through the
SAME make target. Every such assertion is paired with a mutation: the check is re-run against
edited text and must report a problem. A structural test that only ever sees a passing input
proves nothing about what it would reject. Comments are stripped before matching, so a sentence
describing the gate can never stand in for the gate.

Behavioral tests build a throwaway Git repository and run the real checker in it. They cover the
case that motivated this gate: a violation sitting in an already-tracked file that nobody is
editing. `--changed` resolves a commit range and cannot see it. `--all` can.

Contract: specs/release/ci-gates.spec.yaml, C-08 / AC-12.
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKER = os.path.join(REPO, "scripts", "check-doc-style.py")
MAKEFILE = os.path.join(REPO, "Makefile")
WORKFLOW = os.path.join(REPO, ".github", "workflows", "go-ci.yml")
PRECOMMIT = os.path.join(REPO, ".pre-commit-config.yaml")

MAKE_TARGET = "docs-style"
FULL_INVOCATION = "python3 -S scripts/check-doc-style.py --all"


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def uncommented(lines):
    """Drop whole-line comments. A test that a comment can satisfy is decoration."""
    return [ln for ln in lines if not ln.strip().startswith("#")]


# --- Structural checks over the production callers ---------------------------------------------

def check_makefile(text):
    """Problems with the Makefile's docs-style target and its use by ci-local."""
    problems = []
    lines = text.splitlines()
    recipe, seen_target = [], False
    for i, ln in enumerate(lines):
        if re.match(rf"^{MAKE_TARGET}:", ln):
            seen_target = True
            for follow in lines[i + 1:]:
                if follow.startswith("\t"):
                    recipe.append(follow.strip())
                elif follow.strip() == "":
                    continue
                else:
                    break
            break
    if not seen_target:
        return [f"no `{MAKE_TARGET}:` target in the Makefile"]

    commands = uncommented(recipe)
    if not commands:
        problems.append(f"`{MAKE_TARGET}` has no command in its recipe")
    joined = " ".join(commands)
    if FULL_INVOCATION not in joined:
        problems.append(f"`{MAKE_TARGET}` does not run `{FULL_INVOCATION}`; it runs {commands!r}")
    if "--changed" in joined:
        problems.append(f"`{MAKE_TARGET}` runs --changed, which cannot see the working tree")
    if re.search(r"python3\s+(?!-S\b)", joined):
        problems.append(f"`{MAKE_TARGET}` invokes python3 without -S")

    for ln in uncommented(lines):
        if ln.startswith("ci-local:"):
            if MAKE_TARGET not in ln.split(":", 1)[1].split():
                problems.append(f"ci-local does not depend on {MAKE_TARGET}")
            break
    else:
        problems.append("no ci-local target in the Makefile")
    return problems


def _job_block(text, job):
    """The lines of one workflow job, by indentation. No YAML parser, no third-party import."""
    lines = text.splitlines()
    out, depth = [], None
    for ln in lines:
        if depth is None:
            m = re.match(rf"^(\s*){re.escape(job)}:\s*$", ln)
            if m:
                depth = len(m.group(1))
            continue
        if ln.strip() and (len(ln) - len(ln.lstrip())) <= depth:
            break
        out.append(ln)
    return out


def check_workflow(text):
    """Problems with the CI job: it must call the make target, not rebuild the command."""
    block = _job_block(text, "doc-style")
    if not block:
        return ["no `doc-style` job in the workflow"]
    problems = []
    runs = []
    for ln in uncommented(block):
        m = re.match(r"^\s*(?:-\s*)?run:\s*(.+?)\s*$", ln)
        if m and m.group(1) != "|":
            runs.append(m.group(1))
        elif re.match(r"^\s*(?:-\s*)?run:\s*\|\s*$", ln):
            runs.append("|")
    body = "\n".join(uncommented(block))
    if f"make {MAKE_TARGET}" not in body:
        problems.append(f"the doc-style job never runs `make {MAKE_TARGET}`")
    if not any(r.strip() == f"make {MAKE_TARGET}" for r in runs):
        problems.append(f"`make {MAKE_TARGET}` is not a run step of the doc-style job")
    if "--changed" in body:
        problems.append("the doc-style job still runs --changed")
    for r in runs:
        if "check-doc-style.py" in r:
            if "--selftest" not in r:
                problems.append(f"the job rebuilds the checker command instead of the "
                                f"make target: {r!r}")
            if "-S" not in r.split():
                problems.append(f"checker invoked without -S: {r!r}")
    return problems


def _hook_block(text, hook_id):
    lines = text.splitlines()
    out, depth = [], None
    for ln in lines:
        if depth is None:
            m = re.match(rf"^(\s*)-\s*id:\s*{re.escape(hook_id)}\s*$", ln)
            if m:
                depth = len(m.group(1))
            continue
        if ln.strip() and (len(ln) - len(ln.lstrip())) <= depth:
            break
        out.append(ln)
    return out


def check_precommit(text):
    """Problems with the pre-commit hook. It must run the target and ignore any file list."""
    block = _hook_block(text, "doc-style")
    if not block:
        return ["no `doc-style` hook in .pre-commit-config.yaml"]
    body = "\n".join(uncommented(block))
    problems = []
    if not re.search(rf"^\s*entry:\s*make\s+{MAKE_TARGET}\s*$", body, re.M):
        problems.append(f"the hook's entry is not `make {MAKE_TARGET}`")
    if not re.search(r"^\s*pass_filenames:\s*false\s*$", body, re.M):
        problems.append("the hook does not set pass_filenames: false, so a staged file list "
                        "can narrow it back to the vacuous case")
    if not re.search(r"^\s*always_run:\s*true\s*$", body, re.M):
        problems.append("the hook does not set always_run: true, so a commit touching no "
                        "matched path skips it")
    if "--changed" in body:
        problems.append("the hook runs --changed")
    return problems


class CallersReachTheSharedFullTreeGate(unittest.TestCase):
    def test_makefile_runs_the_full_tree_under_dash_S(self):
        self.assertEqual([], check_makefile(read(MAKEFILE)))

    def test_workflow_calls_the_make_target(self):
        self.assertEqual([], check_workflow(read(WORKFLOW)))

    def test_precommit_hook_calls_the_make_target(self):
        self.assertEqual([], check_precommit(read(PRECOMMIT)))


class EachCheckRejectsTheMutationItExistsToCatch(unittest.TestCase):
    """Every structural assertion above, paired with the edit it must refuse."""

    def test_swapping_all_for_changed_fails(self):
        broken = read(MAKEFILE).replace(FULL_INVOCATION,
                                        "python3 -S scripts/check-doc-style.py --changed", 1)
        self.assertTrue(check_makefile(broken), "--changed in the make target was accepted")

    def test_dropping_dash_S_fails(self):
        broken = read(MAKEFILE).replace(FULL_INVOCATION,
                                        "python3 scripts/check-doc-style.py --all", 1)
        self.assertTrue(check_makefile(broken), "a python3 invocation without -S was accepted")

    def test_ci_local_dropping_the_gate_fails(self):
        text = read(MAKEFILE)
        line = [ln for ln in text.splitlines() if ln.startswith("ci-local:")][0]
        broken = text.replace(line, line.replace(f" {MAKE_TARGET}", ""), 1)
        self.assertTrue(check_makefile(broken), "ci-local without the gate was accepted")

    def test_ci_job_bypassing_the_make_target_fails(self):
        broken = read(WORKFLOW).replace(f"run: make {MAKE_TARGET}",
                                        "run: python3 -S scripts/check-doc-style.py --all", 1)
        self.assertTrue(check_workflow(broken), "a job rebuilding the command was accepted")

    def test_ci_job_reverting_to_changed_fails(self):
        broken = read(WORKFLOW).replace(f"run: make {MAKE_TARGET}",
                                        "run: python3 -S scripts/check-doc-style.py --changed", 1)
        self.assertTrue(check_workflow(broken), "a --changed job was accepted")

    def test_removing_the_precommit_hook_fails(self):
        text = read(PRECOMMIT)
        block = _hook_block(text, "doc-style")
        broken = text.replace("      - id: doc-style\n" + "\n".join(block), "", 1)
        self.assertNotIn("id: doc-style", broken, "the hook was not actually removed")
        self.assertTrue(check_precommit(broken), "a missing hook was accepted")

    def test_hook_taking_filenames_fails(self):
        broken = read(PRECOMMIT).replace(
            "      - id: doc-style\n"
            "        name: Documentation style (full tracked tree)\n"
            "        entry: make docs-style\n"
            "        language: system\n"
            "        pass_filenames: false\n",
            "      - id: doc-style\n"
            "        name: Documentation style (full tracked tree)\n"
            "        entry: make docs-style\n"
            "        language: system\n"
            "        pass_filenames: true\n", 1)
        self.assertTrue(check_precommit(broken), "pass_filenames: true was accepted")

    def test_a_comment_cannot_satisfy_the_checks(self):
        """Strip every recipe command but leave the prose. The check must still fail."""
        text = read(MAKEFILE)
        broken = text.replace("\t" + FULL_INVOCATION, "\t# " + FULL_INVOCATION, 1)
        self.assertTrue(check_makefile(broken), "a commented-out command was accepted")


# --- Behavioral tests against a throwaway repository -------------------------------------------

MD_CLEAN = "# Title\n\nThe scan runs once a day.\n"
MD_VIOLATION = "# Title\n\nThe organisation owns the signing key.\n"
GO_VIOLATION = "package sample\n\n// The behaviour of the scheduler changed.\nvar Sample = 1\n"


class TheRealCheckerCatchesWhatChangedCannotSee(unittest.TestCase):
    def run_checker(self, cwd, *args):
        return subprocess.run([sys.executable, "-S", CHECKER, *args],
                              cwd=cwd, capture_output=True, text=True)

    def make_repo(self, committed, staged=None):
        d = tempfile.mkdtemp(prefix="doc-style-gate-")
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.path.join(d, ".gitconfig"),
               "GIT_CONFIG_SYSTEM": os.devnull}
        def g(*a):
            subprocess.run(["git", *a], cwd=d, check=True, capture_output=True, env=env)
        g("init", "-q")
        g("config", "user.email", "t@example.com")
        g("config", "user.name", "T")
        for name, body in committed.items():
            with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                fh.write(body)
            g("add", name)
        g("commit", "-qm", "seed")
        for name, body in (staged or {}).items():
            with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                fh.write(body)
            g("add", name)
        return d

    def test_a_clean_tracked_tree_passes(self):
        d = self.make_repo({"README.md": MD_CLEAN})
        r = self.run_checker(d, "--all")
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)

    def test_an_unchanged_tracked_violation_is_caught(self):
        """The case that justifies the whole slice. Nobody is editing this file."""
        d = self.make_repo({"README.md": MD_CLEAN, "GUIDE.md": MD_VIOLATION})
        r = self.run_checker(d, "--all")
        self.assertEqual(1, r.returncode, r.stdout + r.stderr)
        self.assertIn("organisation", r.stdout + r.stderr)

    def test_changed_mode_misses_the_unchanged_violation(self):
        """Proves --all is load-bearing rather than a longer spelling of the same gate."""
        d = self.make_repo({"README.md": MD_CLEAN, "GUIDE.md": MD_VIOLATION})
        changed = self.run_checker(d, "--changed")
        every = self.run_checker(d, "--all")
        self.assertEqual(0, changed.returncode,
                         "--changed unexpectedly saw it; this test no longer proves anything")
        self.assertEqual(1, every.returncode, every.stdout + every.stderr)

    def test_a_staged_new_violation_is_caught(self):
        d = self.make_repo({"README.md": MD_CLEAN}, staged={"NEW.md": MD_VIOLATION})
        r = self.run_checker(d, "--all")
        self.assertEqual(1, r.returncode, r.stdout + r.stderr)
        self.assertIn("NEW.md", r.stdout + r.stderr)

    def test_a_source_comment_violation_is_caught(self):
        """The gate is not a Markdown gate. Source comments are in scope."""
        d = self.make_repo({"README.md": MD_CLEAN, "sample.go": GO_VIOLATION})
        r = self.run_checker(d, "--all")
        self.assertEqual(1, r.returncode, r.stdout + r.stderr)
        self.assertIn("sample.go", r.stdout + r.stderr)
        self.assertIn("behaviour", r.stdout + r.stderr)


class LocalCarryForwardsSurviveAnAdoption(unittest.TestCase):
    """The shared checker is refetched wholesale on each version bump, which silently drops any
    OpenWatch-only fix. Each carry-forward gets a test here so the loss is loud."""

    def test_sql_is_still_checked(self):
        """Shared v6 has no .sql. Dropping it again would blind the gate to 64 migrations."""
        src = read(CHECKER)
        self.assertIn('"*.sql"', src, "*.sql fell out of GLOBS; see Context Plane bugs/OW-015")
        self.assertIn('".sql": ("--",)', src, '.sql comment marker fell out of COMMENT_STARTS')
        d = tempfile.mkdtemp(prefix="doc-style-sql-")
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.path.join(d, ".gitconfig"),
               "GIT_CONFIG_SYSTEM": os.devnull}
        def g(*a):
            subprocess.run(["git", *a], cwd=d, check=True, capture_output=True, env=env)
        g("init", "-q")
        g("config", "user.email", "t@example.com")
        g("config", "user.name", "T")
        with open(os.path.join(d, "m.sql"), "w", encoding="utf-8") as fh:
            fh.write("-- The behaviour of this migration is documented.\nSELECT 1;\n")
        g("add", "m.sql")
        g("commit", "-qm", "seed")
        r = subprocess.run([sys.executable, "-S", CHECKER, "--all"],
                           cwd=d, capture_output=True, text=True)
        self.assertEqual(1, r.returncode, "a British spelling in a SQL comment was not caught")
        self.assertIn("behaviour", r.stdout + r.stderr)


class TheGateIsStandardLibraryOnly(unittest.TestCase):
    def test_checker_and_tests_import_no_third_party_module(self):
        for path in (CHECKER, os.path.abspath(__file__)):
            r = subprocess.run([sys.executable, "-S", "-c",
                                "import ast,sys;"
                                "src=open(sys.argv[1],encoding='utf-8').read();"
                                "print(' '.join(sorted({(n.module or '').split('.')[0] "
                                "if isinstance(n,ast.ImportFrom) else "
                                "n.names[0].name.split('.')[0] "
                                "for n in ast.walk(ast.parse(src)) "
                                "if isinstance(n,(ast.Import,ast.ImportFrom))})))", path],
                               capture_output=True, text=True, check=True)
            for mod in r.stdout.split():
                self.assertIn(mod, sys.stdlib_module_names, f"{path} imports {mod}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
