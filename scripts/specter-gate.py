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

  * `specter check --test` exited 0 with 232 warnings present.
  * `specter check --test --strict` promotes unreachable_annotation and
    domain_tier_conflict to errors but deliberately leaves
    unreachable_annotation_unknown at warning: 175 errors, 102 warnings.

So neither the exit code nor --strict is a safe signal. An annotation naming
no reachable test is a criterion whose evidence nobody can find, which is the
same defect as an untested criterion; severity does not change that.
"""

import json
import re
import subprocess
import sys
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
    """Reject EVERY annotation diagnostic, at any severity."""
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
TSX_TITLE = re.compile(r"""(?:test|it|describe)\(\s*(['"`])(.*?)\1""", re.S)


def check_tsx_reachability():
    """Reachability for .tsx, which Specter does not analyze.

    Measured, not assumed: removing the literal token from a test title in a
    .ts file raises unreachable_annotation, and the identical removal in a
    .tsx file raises nothing at all. Most of the frontend suite is .tsx, so
    without this the gate reports a clean run over annotations nobody checked.

    The rule is the one Specter applies to .ts: every `// @ac AC-NN` in a file
    that declares `// @spec <id>` must have the literal token `<id>/AC-NN` in
    a test, it or describe title in that same file. A token in a comment does
    not count, which is deliberate: a header index that spells out the token
    would otherwise keep the check green after the real title lost it.
    """
    root = REPO / "frontend" / "tests"
    bad = []
    for f in sorted(root.rglob("*.test.tsx")):
        text = f.read_text(errors="ignore")
        m = TSX_SPEC.search(text)
        if not m:
            continue
        spec_id = m.group(1)
        titles = [t for _, t in TSX_TITLE.findall(text)]
        for ac in dict.fromkeys(TSX_AC.findall(text)):
            token = f"{spec_id}/{ac}"
            if not any(token in t for t in titles):
                bad.append(f"{f.relative_to(REPO)}: @ac {ac} has no test title containing {token!r}")
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


def main():
    want = pinned_version()
    check_version(want)
    check_annotations()
    check_tsx_reachability()
    check_structural_coverage()
    print("specter-gate: PASS")


if __name__ == "__main__":
    main()
