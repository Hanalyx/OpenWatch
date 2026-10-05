#!/usr/bin/env python3
"""Check the test result files the Go CI gates job feeds to specter ingest.

`specter ingest` refuses a missing file and a malformed JUnit file, but it
accepts an empty or malformed `go test -json` file and silently ingests
nothing from it (measured on specter 0.15.1). Run this before ingest so a
lost or broken result file fails the required check instead.

Checks:
  - every file exists and is not empty;
  - every line of each go test stream is a JSON object;
  - the package list is non-empty, and the two go test streams together
    report every listed package exactly once: each package appears in
    exactly one stream, with a package-level pass, fail or skip;
  - the server stream reports internal/server and nothing else;
  - the JUnit file parses as XML and holds at least one testcase.

Standard library only.

Usage: check-test-streams.py --packages FILE --others FILE --server FILE --junit FILE
"""

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

SERVER = "github.com/Hanalyx/openwatch/internal/server"


def read_nonempty(path, what):
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"{what} {path} is missing")
    data = p.read_text(encoding="utf-8")
    if not data.strip():
        raise ValueError(f"{what} {path} is empty")
    return data


def packages_in(path, what):
    """Packages with a package-level pass, fail or skip in a go test -json stream."""
    seen = set()
    for n, line in enumerate(read_nonempty(path, what).splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as err:
            raise ValueError(f"{what} {path} line {n} is not JSON: {err}") from None
        if not isinstance(event, dict):
            raise ValueError(f"{what} {path} line {n} is not a JSON object")
        if not event.get("Test") and event.get("Action") in ("pass", "fail", "skip"):
            seen.add(event.get("Package", ""))
    if not seen:
        raise ValueError(f"{what} {path} reports no package result")
    return seen


def check(packages, others, server, junit):
    listed = set(read_nonempty(packages, "package list").split())
    a = packages_in(others, "go test stream (every package but internal/server)")
    b = packages_in(server, "go test stream (internal/server)")
    problems = []
    if b != {SERVER}:
        problems.append(f"server stream reports {sorted(b)}, want only {SERVER}")
    if both := a & b:
        problems.append(f"packages reported by both streams: {sorted(both)}")
    if missing := listed - a - b:
        problems.append(f"listed packages with no result: {sorted(missing)}")
    if extra := (a | b) - listed:
        problems.append(f"results for packages not listed: {sorted(extra)}")
    try:
        root = ET.fromstring(read_nonempty(junit, "vitest junit"))
    except ET.ParseError as err:
        raise ValueError(f"vitest junit {junit} does not parse: {err}") from None
    if root.find(".//testcase") is None:
        problems.append(f"vitest junit {junit} holds no testcase")
    return problems, len(listed)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for flag in ("--packages", "--others", "--server", "--junit"):
        ap.add_argument(flag, required=True)
    args = ap.parse_args()
    try:
        problems, n = check(args.packages, args.others, args.server, args.junit)
    except ValueError as err:
        problems, n = [str(err)], 0
    if problems:
        for p in problems:
            print(f"::error::{p}")
        return 1
    print(f"test streams complete: {n} packages, each reported exactly once; junit parses")
    return 0


if __name__ == "__main__":
    sys.exit(main())
