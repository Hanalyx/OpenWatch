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
CALLER = re.compile(r"(?:^|[^\w$.])(?:test|it|describe)\s*\(\s*$")


def test_titles(src):
    """Every string literal used as a test, it or describe title.

    A raw regex over the file was wrong, and provably so: it accepted

        // test("frontend-demo/AC-01", () => {})

    as a title, which let a real test lose its token while a commented-out
    decoy kept the gate green. That is the exact failure this check exists to
    catch, so the scanner has to know what is code.

    This walks the source once, tracking line comments, block comments, the
    three string forms and regex literals, and returns only the contents of
    strings that a call to test, it or describe opens.
    """
    titles = []
    i, n = 0, len(src)
    code = []          # source with comments and string bodies blanked out
    spans = {}         # index in `code` of a string start -> its content
    prev_significant = ""
    while i < n:
        c = src[i]
        two = src[i:i + 2]
        if two == "//":
            j = src.find("\n", i)
            j = n if j < 0 else j
            code.append(" " * (j - i))
            i = j
            continue
        if two == "/*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            code.append(" " * (j - i))
            i = j
            continue
        if c in "'\"`":
            quote, j, buf = c, i + 1, []
            while j < n:
                if src[j] == "\\":
                    buf.append(src[j:j + 2])
                    j += 2
                    continue
                if src[j] == quote:
                    break
                buf.append(src[j])
                j += 1
            spans[len("".join(code))] = "".join(buf)
            code.append(" " * (j + 1 - i))
            i = j + 1
            prev_significant = "str"
            continue
        if c == "/" and prev_significant in ("", "op"):
            # A regex literal, not division: only an operator or the start of
            # an expression can precede one.
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == "[":
                    while j < n and src[j] != "]":
                        j += 2 if src[j] == "\\" else 1
                if src[j] == "/" or src[j] == "\n":
                    break
                j += 1
            code.append(" " * (j + 1 - i))
            i = j + 1
            continue
        code.append(c)
        if not c.isspace():
            prev_significant = "val" if (c.isalnum() or c in "_$)]}") else "op"
        i += 1
    code = "".join(code)
    for start, content in spans.items():
        if CALLER.search(code[:start]):
            titles.append(content)
    return titles


def check_tsx_reachability():
    """Reachability for .tsx, which Specter does not analyze.

    Measured, not assumed: removing the literal token from a test title in a
    .ts file raises unreachable_annotation, and the identical removal in a
    .tsx file raises nothing at all. Most of the frontend suite is .tsx, so
    without this the gate reports a clean run over annotations nobody checked.

    Filed upstream as SP-OW-082. Delete this function when it lands, rather
    than leaving a local reimplementation to rot beside a fixed scanner.

    The rule is the one Specter applies to .ts: every `// @ac AC-NN` in a file
    that declares `// @spec <id>` must have the literal token `<id>/AC-NN` in
    a test, it or describe title in that same file. A token in a comment or in
    an ordinary string does not count.
    """
    root = REPO / "frontend" / "tests"
    bad = []
    for f in sorted(root.rglob("*.test.tsx")):
        text = f.read_text(errors="ignore")
        m = TSX_SPEC.search(text)
        if not m:
            continue
        spec_id = m.group(1)
        titles = test_titles(text)
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
