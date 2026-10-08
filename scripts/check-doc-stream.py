#!/usr/bin/env python3
"""Check the documentation path's test results before they count.

    python3 -S scripts/check-doc-stream.py --stream /tmp/go-test-docs.json

The documentation path of Go CI runs only `go test -json ./packaging/tests/`,
without native package builds (release-ci-gates C-18). This is TARGETED
validation of the tests that read documents and other non-code inputs. It
is not full coverage; the full pipeline remains responsible for that.

The stream passes only if all of these hold:

  * it exists, is not empty, and every non-blank line is a JSON object;
  * it reports exactly one package result, for packaging/tests, and that
    result is a pass;
  * it carries no build-failure event;
  * at least one test passed and none failed;
  * every skipped test logged, as its own last test-file line, one of the
    PERMITTED skip messages, exactly as the tests write it.

The last rule is the skip policy. A permitted message counts only on a test
that actually skipped. A test that skips for any other reason fails the
check: a missing database, a missing tool, an unreadable file, or setup that
did not happen. Known limitation: a test that wrongly started to use a
permitted message would be accepted; nothing here compares with a previous
run.

Standard library only.
"""

import argparse
import json
import re
import sys

PACKAGE = "github.com/Hanalyx/openwatch/packaging/tests"

# The only reasons a test may skip on the documentation path. Each string is
# the literal a test passes to t.Skip; release-ci-gates AC-30 checks that
# each one still appears in packaging/tests, so an entry cannot outlive the
# skip it permits.
PERMITTED = (
    # requirePackagingBuild: native builds are off on this path by design.
    "set OPENWATCH_PACKAGING_BUILD=1 to run native package build tests (full make rpm/deb)",
    # Opt-in container tests. They skip on the full path too.
    "set OPENWATCH_ROLLBACK_IMAGE (for example postgres:16) to run the rollback blocks against PostgreSQL",
    "set OPENWATCH_KENSA_COMPAT_{IMAGE,KIND,OLD_DIR,NEW_DIR} to run the container pairing test",
)

# A line a test logs through t.Log / t.Skip: "    file_test.go:123: message".
LOGGED = re.compile(r"^\s*[\w./-]+_test\.go:\d+: (.*?)\s*$")


def check(path):
    """Return (problems, summary)."""
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        return [f"{path} is missing"], ""
    except OSError as e:
        return [f"{path} cannot be read: {e}"], ""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return [f"{path} is empty"], ""

    problems = []
    package_results = []
    final = {}                   # test -> last pass/fail/skip
    output = {}                  # test -> its own output lines
    for n, ln in enumerate(lines, 1):
        try:
            ev = json.loads(ln)
        except json.JSONDecodeError as e:
            return [f"{path} line {n} is not JSON: {e}"], ""
        if not isinstance(ev, dict):
            return [f"{path} line {n} is not a JSON object"], ""
        action = ev.get("Action")
        # go test -json reports a compile failure as a build-fail event and a
        # package fail carrying FailedBuild.
        if action == "build-fail" or ev.get("FailedBuild"):
            problems.append(f"build failure reported at line {n}: {ev.get('ImportPath') or ev.get('FailedBuild') or ev.get('Package')}")
            if action == "build-fail":
                continue
        test = ev.get("Test")
        if test is None:
            if action in ("pass", "fail", "skip"):
                package_results.append((ev.get("Package"), action))
            continue
        if action == "output":
            output.setdefault(test, []).append(ev.get("Output", ""))
        elif action in ("pass", "fail", "skip"):
            final[test] = action

    if len(package_results) != 1:
        problems.append(f"want exactly one package result, got {len(package_results)}: {package_results}")
    for pkg, action in package_results:
        if pkg != PACKAGE:
            problems.append(f"result for {pkg!r}; this path tests only {PACKAGE}")
        elif action != "pass":
            problems.append(f"{PACKAGE} ended {action!r}, want pass")

    passed = sorted(t for t, a in final.items() if a == "pass")
    failed = sorted(t for t, a in final.items() if a == "fail")
    skipped = sorted(t for t, a in final.items() if a == "skip")
    if not passed:
        problems.append("no test passed")
    for t in failed:
        problems.append(f"test failed: {t}")

    reasons = {}
    for t in skipped:
        logged = []
        for chunk in output.get(t, []):
            for piece in chunk.splitlines():
                m = LOGGED.match(piece)
                if m:
                    logged.append(m.group(1))
        message = logged[-1] if logged else None
        if message not in PERMITTED:
            problems.append(f"test skipped for a reason this path does not permit: {t}: "
                            f"{message if message is not None else '(no skip message)'}")
        else:
            reasons[message] = reasons.get(message, 0) + 1

    summary = (f"documentation path, PARTIAL validation of {PACKAGE}: {len(passed)} passed, "
               f"{len(failed)} failed, {len(skipped)} not run")
    for message, count in sorted(reasons.items()):
        summary += f"\n  not run ({count}): {message}"
    summary += "\nFull test and coverage enforcement runs on code, spec and tooling changes."
    return problems, summary


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--stream", required=True, help="go test -json output of packaging/tests")
    args = ap.parse_args()
    problems, summary = check(args.stream)
    if summary:
        print(summary)
    if problems:
        for p in problems:
            print(f"check-doc-stream: {p}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
