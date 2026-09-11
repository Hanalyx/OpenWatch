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
GATE = os.path.join(REPO, "scripts", "doc-style-gate.py")
PIN_FILE = os.path.join(REPO, ".doc-style-version")
EXEMPT_PATH = ".github/pull_request_template.md"

MAKE_TARGET = "docs-style"
FULL_INVOCATION = "python3 -S scripts/doc-style-gate.py"
# A caller declaring its own checker version. The pinned value is a bare digit, so a plain
# substring search would match anything; this looks for a DECLARATION, which is the shape
# that can drift from the pin.
VERSION_DECL = r"(?i)version[\"\'\s:=-]+[\"\']?%s\b"


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
    if "check-doc-style.py" in joined:
        problems.append(f"`{MAKE_TARGET}` calls the checker directly, skipping the version gate")
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


def check_no_caller_declares_a_version(pinned):
    """No caller may carry its own copy of the checker version. Comments are stripped first,
    because every caller explains the pin in prose and must be free to."""
    problems = []
    for path in (MAKEFILE, WORKFLOW, PRECOMMIT):
        for code in uncommented(read(path).splitlines()):
            if re.search(VERSION_DECL % re.escape(pinned), code):
                problems.append(f"{os.path.basename(path)} declares its own version: "
                                f"{code.strip()!r}")
    return problems


class ThePinIsTheOnlySourceOfTheCheckerVersion(unittest.TestCase):
    """The checker is refetched whole on an upgrade, so a superseded copy can stay authoritative
    in silence. It did, for a month. The pin makes that loud."""

    def make_tree(self, pin=None, checker_version=None, extra=None):
        """A copy of the gate, the checker and the pin, so a mutation never touches the real tree.
        The gate resolves its repository from its own path, so copying it is enough."""
        d = tempfile.mkdtemp(prefix="doc-style-pin-")
        os.makedirs(os.path.join(d, "scripts"))
        for src in (GATE, CHECKER):
            body = read(src)
            if src == CHECKER and checker_version is not None:
                body = body.replace('VERSION = "6"', f'VERSION = "{checker_version}"', 1)
            with open(os.path.join(d, "scripts", os.path.basename(src)), "w",
                      encoding="utf-8") as fh:
                fh.write(body)
        if pin is not None:
            with open(os.path.join(d, ".doc-style-version"), "w", encoding="utf-8") as fh:
                fh.write(pin)
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.path.join(d, ".gitconfig"),
               "GIT_CONFIG_SYSTEM": os.devnull}
        def g(*a):
            subprocess.run(["git", *a], cwd=d, check=True, capture_output=True, env=env)
        g("init", "-q")
        g("config", "user.email", "t@example.com")
        g("config", "user.name", "T")
        for name, body in (extra or {"README.md": MD_CLEAN}).items():
            full = os.path.join(d, name)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(body)
            g("add", name)
        g("commit", "-qm", "seed")
        return d

    def run_gate(self, d, *args):
        return subprocess.run([sys.executable, "-S",
                               os.path.join(d, "scripts", "doc-style-gate.py"), *args],
                              cwd=d, capture_output=True, text=True)

    def test_the_real_pin_matches_the_real_checker(self):
        self.assertTrue(os.path.exists(PIN_FILE), ".doc-style-version is missing")
        pinned = read(PIN_FILE).strip()
        self.assertRegex(pinned, r"^[0-9]+(?:\.[0-9]+)*$", f"the pin is not a version: {pinned!r}")
        r = subprocess.run([sys.executable, "-S", CHECKER, "--version"],
                           cwd=REPO, capture_output=True, text=True, check=True)
        m = re.search(r"\bversion\s+([0-9]+(?:\.[0-9]+)*)\b", r.stdout + r.stderr)
        self.assertIsNotNone(m, "the checker printed no version")
        self.assertEqual(pinned, m.group(1),
                         "the pin and the checker disagree in the real tree")

    def test_a_matching_pin_passes(self):
        d = self.make_tree(pin="6\n")
        r = self.run_gate(d, "--only", "version")
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)

    def test_a_missing_pin_fails_closed(self):
        r = self.run_gate(self.make_tree(pin=None), "--only", "version")
        self.assertEqual(1, r.returncode, "a missing pin was treated as a skip")
        self.assertIn("missing", r.stderr)

    def test_an_empty_pin_fails_closed(self):
        for blank in ("", "\n", "   \n"):
            r = self.run_gate(self.make_tree(pin=blank), "--only", "version")
            self.assertEqual(1, r.returncode, f"an empty pin {blank!r} was accepted")

    def test_a_malformed_pin_fails_closed(self):
        for junk in ("six", "6.x", "v6", "6 6"):
            r = self.run_gate(self.make_tree(pin=junk), "--only", "version")
            self.assertEqual(1, r.returncode, f"a malformed pin {junk!r} was accepted")

    def test_changing_the_pin_alone_fails(self):
        """Required mutation: pin 6 -> 5."""
        r = self.run_gate(self.make_tree(pin="5\n"), "--only", "version")
        self.assertEqual(1, r.returncode, "a pin naming another version was accepted")
        self.assertIn("5", r.stderr)

    def test_changing_the_checker_alone_fails(self):
        """Required mutation: the checker moves and the pin does not."""
        d = self.make_tree(pin="6\n", checker_version="7")
        r = self.run_gate(d, "--only", "version")
        self.assertEqual(1, r.returncode, "an unpinned checker upgrade was accepted")
        self.assertIn("7", r.stderr)

    def test_the_version_is_compared_before_anything_is_scanned(self):
        """A gate that scans first and verifies afterwards has already trusted the tool."""
        d = self.make_tree(pin="5\n", extra={"BAD.md": MD_VIOLATION})
        r = self.run_gate(d)
        self.assertEqual(1, r.returncode)
        self.assertNotIn("organisation", r.stdout + r.stderr,
                         "the tree was scanned before the version was checked")

    def test_no_caller_declares_its_own_version(self):
        self.assertEqual([], check_no_caller_declares_a_version(read(PIN_FILE).strip()))

    def test_a_caller_declaring_a_version_is_caught(self):
        """Required mutation: a caller introduces its own literal."""
        original = read(MAKEFILE)
        broken = original.replace("docs-style:\n", 'docs-style:\n\tDOC_STYLE_VERSION=6; \\\n', 1)
        self.assertNotEqual(original, broken, "the mutation did not apply")
        saved = read(MAKEFILE)
        try:
            with open(MAKEFILE, "w", encoding="utf-8") as fh:
                fh.write(broken)
            self.assertTrue(check_no_caller_declares_a_version("6"),
                            "a caller-side version literal was accepted")
        finally:
            with open(MAKEFILE, "w", encoding="utf-8") as fh:
                fh.write(saved)
        self.assertEqual(saved, read(MAKEFILE), "the Makefile was not restored")


# Content that scores above the gate. Taken from the real exempt file so the test measures the
# thing the ledger actually caps, rather than a synthetic string tuned to a number.
def exempt_file_body():
    return read(os.path.join(REPO, EXEMPT_PATH))


class TheReadingExemptionIsScopedToOneFileAndOneRule(unittest.TestCase):
    """A cap is a hole in the gate. These tests describe its exact shape."""

    def make_tree(self, files):
        d = tempfile.mkdtemp(prefix="doc-style-exempt-")
        os.makedirs(os.path.join(d, "scripts"))
        with open(os.path.join(d, "scripts", "check-doc-style.py"), "w", encoding="utf-8") as fh:
            fh.write(read(CHECKER))
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.path.join(d, ".gitconfig"),
               "GIT_CONFIG_SYSTEM": os.devnull}
        def g(*a):
            subprocess.run(["git", *a], cwd=d, check=True, capture_output=True, env=env)
        g("init", "-q")
        g("config", "user.email", "t@example.com")
        g("config", "user.name", "T")
        for name, body in files.items():
            full = os.path.join(d, name)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(body)
            g("add", name)
        g("commit", "-qm", "seed")
        return d

    def scan(self, d):
        return subprocess.run([sys.executable, "-S",
                               os.path.join(d, "scripts", "check-doc-style.py"), "--all"],
                              cwd=d, capture_output=True, text=True)

    def test_the_exempt_form_passes_at_its_cap(self):
        r = self.scan(self.make_tree({EXEMPT_PATH: exempt_file_body()}))
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)

    def test_the_same_content_at_another_path_fails(self):
        """Required mutation guard: no other file inherits the cap."""
        d = self.make_tree({"docs/NOT_A_FORM.md": exempt_file_body()})
        r = self.scan(d)
        self.assertEqual(1, r.returncode,
                         "over-limit content was excused at a path with no exemption")
        self.assertIn("reading-level", r.stdout + r.stderr)
        self.assertIn("NOT_A_FORM.md", r.stdout + r.stderr)

    def test_every_other_rule_still_binds_inside_the_exempt_file(self):
        """Required mutation guard: the cap covers the reading level and nothing else."""
        cases = {
            "em dash": "\nA line with an em dash \u2014 right here.\n",
            "emoji": "\nA line with an emoji \U0001F600 right here.\n",
            "ai speak": "\nWe leverage the queue for this.\n",
            "us english": "\nThe organisation owns the key.\n",
        }
        for label, addition in cases.items():
            with self.subTest(rule=label):
                d = self.make_tree({EXEMPT_PATH: exempt_file_body() + addition})
                r = self.scan(d)
                out = r.stdout + r.stderr
                self.assertEqual(1, r.returncode,
                                 f"a {label} violation was excused inside the exempt file")
                # Printed, not merely counted. A mutation that silenced findings
                # for exempt paths while leaving the exit code alone survived an
                # exit-code-only assertion here, which is how this line exists.
                self.assertIn(os.path.basename(EXEMPT_PATH), out,
                              f"the {label} finding was counted but never reported")

    def test_the_ledger_names_exactly_one_path(self):
        src = read(CHECKER)
        block = src[src.index("READING_EXEMPT = {"):]
        block = block[:block.index("\n}")]
        paths = re.findall(r'^\s*"([^"]+)":\s*\(', block, re.M)
        self.assertEqual([EXEMPT_PATH], paths,
                         "the exemption ledger grew; it is a ratchet and may only shrink")


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
