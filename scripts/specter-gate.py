#!/usr/bin/env python3
"""The Specter gate. One implementation, called by `make spec-check` and by CI.

Standard library only, matching scripts/check-doc-style.py and
scripts/release-status.py. CI installs no Python packages.

Why this exists rather than two shell snippets. The workflow and the Makefile
used to run their own greps over Specter's text output, which is two policies
that drift apart silently: a formatting change upstream turns a grep into a
gate that matches nothing and reports success. This file is the only place the
policy is written, and spec release-ci-gates AC-11 asserts both callers invoke
it.

Why it keys on the JSON summary rather than the exit code. Measured against
v0.15 on this repository:

  * `specter check --test` exited 0 with 277 warnings present: 130
    unreachable_annotation, 102 unreachable_annotation_unknown and 45
    domain_tier_conflict.
  * `specter check --test --strict` on that same tree promoted the 130 and
    the 45 to errors and deliberately left unreachable_annotation_unknown at
    warning: 175 errors, 102 warnings. Both numbers describe ONE baseline;
    232 is the reachability subset of it, not a total to pair with 175.

So neither the exit code nor --strict is a safe signal. An annotation naming
no reachable test is a criterion whose evidence nobody can find, which is the
same defect as an untested criterion; severity does not change that.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PIN_FILE = REPO / ".specter-version"


def fail(msg):
    print(f"specter-gate: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def run(args):
    """Run specter and return (exit code, stdout, stderr)."""
    p = subprocess.run(["specter"] + args, capture_output=True, text=True, cwd=REPO)
    return p.returncode, p.stdout, p.stderr


def pinned_version():
    if not PIN_FILE.exists():
        fail(f"{PIN_FILE.name} is missing; the pinned Specter version has no single source")
    v = PIN_FILE.read_text().strip()
    if not v:
        fail(f"{PIN_FILE.name} is empty")
    return v


def check_version(want):
    code, out, err = run(["--version"])
    if code != 0:
        fail(f"specter --version exited {code}: {err.strip() or out.strip()}")
    got = (out + err).strip().split()[-1]
    if got != want:
        fail(
            f"specter {got} is installed but {PIN_FILE.name} pins {want}. "
            "A gate proven against one build says nothing about another."
        )
    print(f"specter-gate: version {got} matches {PIN_FILE.name}")


def check_annotations():
    """Reject every ERROR and WARNING diagnostic.

    Info diagnostics are not blocking. The contract says so in as many words
    (release-ci-gates C-07); an earlier draft of both said "any severity",
    which described something this function never did.
    """
    code, out, err = run(["check", "--test", "--json"])
    blob = out if out.lstrip().startswith("{") else out[out.index("{"):] if "{" in out else ""
    if not blob:
        fail(f"specter check --test --json produced no JSON (exit {code}): {err.strip()}")
    try:
        doc = json.loads(blob)
    except json.JSONDecodeError as e:
        fail(f"could not parse specter JSON: {e}")
    summary = doc.get("summary", {})
    # A clean run sends `null`, not an empty list.
    diags = doc.get("diagnostics") or []
    errors = summary.get("errors", 0)
    warnings = summary.get("warnings", 0)
    # The exit status is checked TOO, not instead. Reading only the summary
    # trusts the report to describe the run that produced it: a crash after
    # the counters were zeroed, or any failure mode that still prints
    # {"errors":0,"warnings":0}, would have been reported as a clean gate.
    if code != 0 and not (errors or warnings):
        print(err.strip() or out.strip(), file=sys.stderr)
        fail(
            f"specter check --test exited {code} while reporting a clean summary. "
            "The report does not describe the run."
        )
    if errors or warnings:
        # Print what was rejected. A count alone tells a reader something is
        # wrong without telling them what.
        by_kind = {}
        for d in diags:
            by_kind.setdefault((d.get("severity"), d.get("kind")), []).append(d)
        for (sev, kind), items in sorted(by_kind.items(), key=lambda t: -len(t[1])):
            print(f"  {len(items):5}  {sev:8} {kind}", file=sys.stderr)
            for d in items[:5]:
                print(f"           {d.get('message', '')[:200]}", file=sys.stderr)
            if len(items) > 5:
                print(f"           ... and {len(items) - 5} more", file=sys.stderr)
        fail(
            f"{errors} error(s) and {warnings} warning(s) from specter check --test. "
            "Every annotation must name a test the runner can see."
        )
    print(f"specter-gate: annotations clean ({len(diags)} diagnostics)")


TSX_SPEC = re.compile(r"^// @spec (\S+)", re.M)
TSX_AC = re.compile(r"^\s*// @ac (AC-\d+)", re.M)


def collect_vitest_titles(frontend):
    r"""Ask Vitest for the titles it actually collects, keyed by file.

    NOT a hand-written parser. Two earlier versions were, and both were
    unsound on valid TypeScript: a raw regex accepted a commented-out decoy,
    and the lexer that replaced it read

        function f() { return /test("frontend-demo\/AC-01")/; }

    as a real title, because a `/` after `return` looked like division and the
    regex body was then lexed as code. The requirement is a RUNNER-VISIBLE
    title, so the runner is the right authority; every further heuristic is a
    new way to be confidently wrong.

    `vitest list --json=<path>` performs collection only. Note the `=`: the
    bare `--json` form takes the next argument as an output PATH and will
    happily overwrite a source file.
    """
    # The repository's OWN vitest, never `npx vitest`. npx will fetch a
    # version from the network when the local package is missing, which would
    # let the gate parse its input with a tool nobody pinned. A gate must fail
    # closed rather than acquire its own parser.
    binary = Path(frontend) / "node_modules" / ".bin" / "vitest"
    if not binary.exists():
        fail(f"{binary} is missing. Run `npm ci` in frontend/ first.")

    # A unique temporary file, not a fixed name inside frontend/: two runs at
    # once would otherwise share one path and read each other's output.
    fd, tmp = tempfile.mkstemp(prefix="specter-gate-titles-", suffix=".json")
    os.close(fd)
    out = Path(tmp)
    try:
        p = subprocess.run(
            [str(binary), "list", f"--json={out}"],
            capture_output=True, text=True, cwd=frontend,
        )
        if p.returncode != 0 or not out.exists() or not out.read_text().strip():
            fail(
                "could not collect Vitest test titles "
                f"(exit {p.returncode}). Run `npm ci` in frontend/ first.\n"
                + (p.stderr or p.stdout)[-2000:]
            )
        entries = json.loads(out.read_text())
    finally:
        out.unlink(missing_ok=True)
    by_file = {}
    for e in entries:
        raw = e.get("file", "")
        key = str(Path(raw).resolve()) if raw else ""
        by_file.setdefault(key, []).append(e.get("name", ""))
    return by_file


def check_tsx_reachability(root=None, titles_by_file=None):
    """Reachability for .tsx, which Specter does not analyze.

    Measured, not assumed: removing the literal token from a test title in a
    .ts file raises unreachable_annotation, and the identical removal in a
    .tsx file raises nothing at all. Most of the frontend suite is .tsx, so
    without this the gate reports a clean run over annotations nobody checked.

    Filed upstream as SP-OW-082. Delete this function when it lands, rather
    than leaving a local reimplementation to rot beside a fixed scanner.

    `root` and `titles_by_file` are injectable so the enforcement path itself
    can be tested, not merely the helper it calls.
    """
    root = Path(root) if root else REPO / "frontend" / "tests"
    if titles_by_file is None:
        titles_by_file = collect_vitest_titles(REPO / "frontend")
    # Vitest reports absolute paths. Match on the RESOLVED path and nothing
    # looser: a basename fallback let two files named the same in different
    # directories share titles, so a token collected from one could satisfy an
    # annotation in the other.
    resolved = {str(Path(k).resolve()): v for k, v in titles_by_file.items() if k}

    def titles_for(f):
        return resolved.get(str(Path(f).resolve()), [])

    bad = []
    for f in sorted(root.rglob("*.test.tsx")):
        text = f.read_text(errors="ignore")
        m = TSX_SPEC.search(text)
        if not m:
            continue
        spec_id = m.group(1)
        titles = titles_for(f)
        for ac in dict.fromkeys(TSX_AC.findall(text)):
            token = f"{spec_id}/{ac}"
            if not any(token in t for t in titles):
                bad.append(f"{f}: @ac {ac} has no collected test title containing {token!r}")
    if bad:
        for b in bad:
            print(f"  {b}", file=sys.stderr)
        fail(f"{len(bad)} .tsx annotation(s) name no runner-visible test title")
    print("specter-gate: .tsx reachability checked locally (Specter does not)")


def check_structural_coverage():
    code, out, err = run(["coverage", "--strictness", "annotation"])
    text = out + err
    if code != 0:
        print(text, file=sys.stderr)
        fail(f"specter coverage exited {code}")
    below = [
        ln
        for ln in text.splitlines()
        if " T" in ln and "%" in ln and "100%" not in ln
    ]
    if below:
        for ln in below:
            print(f"  {ln}", file=sys.stderr)
        fail(f"{len(below)} spec(s) below 100% structural coverage")
    if "0 failing" not in text:
        print(text, file=sys.stderr)
        fail("coverage summary does not report 0 failing")
    for ln in text.splitlines():
        if "specs:" in ln:
            print(f"specter-gate: {ln.strip()}")
    print("specter-gate: structural coverage 100%")


STAGES = ("version", "annotations", "tsx", "coverage")


def main(argv=None):
    """Run every stage, or one named stage.

    `--only <stage>` exists so the gate's own guards can drive a single stage
    against a stubbed specter without the others interfering. A CALLER must
    never use it: running a subset is not running the gate, and
    release-ci-gates AC-11 fails if `--only` appears in one.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    only = None
    if argv and argv[0] == "--only":
        if len(argv) < 2 or argv[1] not in STAGES:
            fail(f"--only takes one of {', '.join(STAGES)}")
        only = argv[1]
    elif argv:
        fail(f"unexpected argument {argv[0]!r}")

    want = pinned_version()
    if only in (None, "version"):
        check_version(want)
    if only in (None, "annotations"):
        check_annotations()
    if only in (None, "tsx"):
        check_tsx_reachability()
    if only in (None, "coverage"):
        check_structural_coverage()
    print("specter-gate: PASS")


if __name__ == "__main__":
    main()
