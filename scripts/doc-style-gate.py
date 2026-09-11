#!/usr/bin/env python3
"""The documentation style gate: verify the checker, then run it.

`make docs-style`, the CI "Doc Style" job and the pre-commit hook all run this one script, so the
three cannot drift into different policies.

Why a gate rather than calling the checker directly. `scripts/check-doc-style.py` is a SHARED tool
owned by hanalyx-platform-agent and published at Context Plane `dev/tools/doc-style-check`. The
documented upgrade path is to refetch the whole file and verify its hash, which overwrites
everything local. Nothing recorded which version this repository ran, and the one comment that
named a version said v3 while the tree ran v5 and v6 had been published for a month. Four defects
this repository had itself reported and seen fixed upstream were still live here, and one of them
cost a wasted rewrite of CONTRIBUTING.md to satisfy a measure that was already known to be wrong.

So the version is pinned in ONE tracked file and checked before anything is scanned. The pin is
the only literal: no caller carries a second copy to fall out of step with it.

Fails closed. A missing, empty, malformed or mismatched pin is a failure, not a skip, because a
gate that quietly stops verifying is the exact shape of the defect it exists to prevent.

Standard library only, and callers run it under `python3 -S`, so the checker's dependency-free
claim is enforced rather than asserted.

Contract: specs/release/ci-gates.spec.yaml, C-08 / AC-12.
"""
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PIN_FILE = REPO / ".doc-style-version"
CHECKER = REPO / "scripts" / "check-doc-style.py"

# A version is digits, optionally dotted. The shared tool numbers itself "6"; the pattern also
# accepts "6.1" so a point release does not need this gate changed.
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")
# `--version` prints "doc-style check version 6  sha256 ..." then a line about what the hash covers.
REPORTED_RE = re.compile(r"\bversion\s+([0-9]+(?:\.[0-9]+)*)\b")

STAGES = ("version", "scan")


def fail(msg):
    print(f"doc-style-gate: FAIL: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def pinned_version():
    """The version this repository has adopted. Every failure here is fail-closed."""
    if not PIN_FILE.exists():
        fail(f"{PIN_FILE.name} is missing; the adopted checker version has no single source")
    raw = PIN_FILE.read_text()
    v = raw.strip()
    if not v:
        fail(f"{PIN_FILE.name} is empty; it must name the adopted checker version")
    if not VERSION_RE.match(v):
        fail(f"{PIN_FILE.name} contains {v!r}, which is not a version")
    return v


def reported_version():
    """What the checker says it is. Read from the tool, not from its source text: the point is to
    verify the thing that will do the scanning."""
    if not CHECKER.exists():
        fail(f"{CHECKER} is missing")
    p = subprocess.run([sys.executable, "-S", str(CHECKER), "--version"],
                       capture_output=True, text=True, cwd=REPO)
    if p.returncode != 0:
        fail(f"{CHECKER.name} --version exited {p.returncode}: "
             f"{p.stderr.strip() or p.stdout.strip()}")
    m = REPORTED_RE.search(p.stdout + p.stderr)
    if not m:
        fail(f"{CHECKER.name} --version printed no version: {(p.stdout + p.stderr).strip()!r}")
    return m.group(1)


def check_version():
    want = pinned_version()
    got = reported_version()
    if got != want:
        fail(
            f"{CHECKER.name} reports version {got} but {PIN_FILE.name} pins {want}. "
            "Adopt the pinned version, or change the pin deliberately after re-deriving "
            "READING_GATE, because a new version can change what the numbers mean."
        )
    # Flushed, because the scan below writes straight to the terminal from a child process.
    # Unflushed, this line lands after the scan output and reads as though the version were
    # checked afterwards.
    print(f"doc-style-gate: checker version {got} matches {PIN_FILE.name}", flush=True)
    return got


def run_scan():
    """The whole tracked tree, not the changed files. `--changed` resolves a commit range and
    cannot see the working tree, so it is blind exactly when an author runs it."""
    p = subprocess.run([sys.executable, "-S", str(CHECKER), "--all"], cwd=REPO)
    if p.returncode != 0:
        sys.exit(p.returncode)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    only = None
    if argv and argv[0] == "--only":
        # A test seam, so one stage can be driven on its own. A CALLER using it would be running
        # a subset of the gate and calling it the gate, which is why AC-12 forbids it in callers.
        if len(argv) < 2 or argv[1] not in STAGES:
            fail(f"--only takes one of {', '.join(STAGES)}")
        only = argv[1]
        argv = argv[2:]
    if argv:
        fail(f"unexpected arguments: {' '.join(argv)}")

    if only in (None, "version"):
        check_version()
    if only in (None, "scan"):
        run_scan()


if __name__ == "__main__":
    main()
