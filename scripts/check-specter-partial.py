#!/usr/bin/env python3
"""Check Specter's results for the documentation path's partial run.

    python3 -S scripts/check-specter-partial.py \\
        --results .specter-results.json --stream /tmp/go-test-docs.json \\
        --since <epoch seconds taken after the old results were removed>

On the documentation path (release-ci-gates C-18) `specter ingest` reads
only packaging/tests, so its results cover only the criteria those tests
annotate. That is partial. `specter sync` is NOT run on it: the coverage
thresholds are global, and partial results would fail them while proving
nothing about the rest. Full ingest and threshold enforcement stay on the
full path.

The results pass only if all of these hold:

  * the file exists, parses, and is {"results": [...]} with every entry
    naming spec_id, ac_id and a status of passed, failed or skipped;
  * it was written by this run: modified at or after --since, and every
    criterion in it is one this run's stream exercised;
  * no entry failed, and at least one passed.

Standard library only.
"""

import argparse
import json
import os
import re
import sys

STATUSES = {"passed", "failed", "skipped"}

# t.Run("<spec-id>/AC-NN", ...) is how a test binds a criterion.
CRITERION = re.compile(r"(?:^|/)([a-z0-9][a-z0-9-]*)/(AC-\d+)(?:/|$)")


def stream_criteria(path):
    found = set()
    with open(path, encoding="utf-8") as f:
        for ln in f:
            if not ln.strip():
                continue
            try:
                ev = json.loads(ln)
            except json.JSONDecodeError:
                continue
            test = ev.get("Test") if isinstance(ev, dict) else None
            if test:
                for m in CRITERION.finditer(test):
                    found.add((m.group(1), m.group(2)))
    return found


def check(results, stream, since):
    """Return (problems, summary)."""
    try:
        mtime = os.stat(results).st_mtime
        with open(results, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return [f"{results} is missing; specter ingest wrote nothing"], ""
    except (OSError, json.JSONDecodeError) as e:
        return [f"{results} is malformed: {e}"], ""

    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return [f'{results} is malformed: want {{"results": [...]}}'], ""
    entries = data["results"]
    problems = []
    for i, e in enumerate(entries):
        if (not isinstance(e, dict) or not isinstance(e.get("spec_id"), str)
                or not isinstance(e.get("ac_id"), str) or e.get("status") not in STATUSES):
            problems.append(f"{results} entry {i} is malformed: {e!r}")
    if problems:
        return problems, ""

    if mtime < since:
        problems.append(f"{results} is stale: modified before this run's ingest started")
    try:
        exercised = stream_criteria(stream)
    except OSError as e:
        return [f"{stream} cannot be read: {e}"], ""
    foreign = sorted({(e["spec_id"], e["ac_id"]) for e in entries} - exercised)
    if foreign:
        problems.append(f"{results} holds {len(foreign)} criteria this run's stream did not exercise, "
                        f"so it is not this run's output: {foreign[:5]}")

    failed = sorted(f"{e['spec_id']}/{e['ac_id']}" for e in entries if e["status"] == "failed")
    passed = [e for e in entries if e["status"] == "passed"]
    skipped = [e for e in entries if e["status"] == "skipped"]
    for c in failed:
        problems.append(f"criterion failed: {c}")
    if not passed:
        problems.append("no criterion passed")

    summary = (f"specter, PARTIAL results (documentation path): {len(passed)} criteria passed, "
               f"{len(failed)} failed, {len(skipped)} not run. Coverage thresholds are not "
               f"evaluated on this path; full coverage is enforced on code, spec and tooling changes.")
    return problems, summary


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--results", required=True)
    ap.add_argument("--stream", required=True)
    ap.add_argument("--since", required=True, type=float,
                    help="epoch seconds; results modified earlier are stale")
    args = ap.parse_args()
    problems, summary = check(args.results, args.stream, args.since)
    if summary:
        print(summary)
    if problems:
        for p in problems:
            print(f"check-specter-partial: {p}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
