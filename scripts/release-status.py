#!/usr/bin/env python3
"""Render the release gates for a candidate tag and return a go/no-go verdict.

    scripts/release-status.py --tag v0.7.0-rc.3

Exit status is the verdict: 0 for GO, 1 for NO-GO, 2 for a configuration or
lookup error. That makes it usable as a gate in its own right, so CI can call
exactly what a human calls and neither can reach a different answer.

Single file, standard library only, matching scripts/check-doc-style.py. TOML
is read with the stdlib tomllib rather than PyYAML so the checker has no
install step of its own.

Evidence comes from three places and nowhere else:

  github-check   check runs on the tag's commit, via `gh api`
  release-asset  assets on the GitHub release for the tag, via `gh release`
  attestation    files under release/attestations/, scoped to an artifact
                 digest so evidence follows the bits rather than the tag

An attestation whose artifact_sha256 does not appear in the candidate's
SHA256SUMS is reported STALE, not PASS. That is the whole point: re-cutting a
candidate with a rebuilt binary silently invalidates prior install evidence,
which is the failure mode this tool exists to prevent.
"""

import argparse
import fnmatch
import json
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GATES = REPO / "release" / "gates.toml"
ATTEST_DIR = REPO / "release" / "attestations"

PASS, FAIL, MISSING, STALE, ERROR = "PASS", "FAIL", "MISSING", "STALE", "ERROR"
BAD = {FAIL, MISSING, STALE, ERROR}


def sh(*args, check=False):
    """Run a command, returning (rc, stdout). Never raises on non-zero."""
    p = subprocess.run(args, capture_output=True, text=True)
    if check and p.returncode != 0:
        die(f"{' '.join(args)}: {p.stderr.strip()}")
    return p.returncode, p.stdout.strip()


def die(msg):
    print(f"release-status: {msg}", file=sys.stderr)
    sys.exit(2)


# ------------------------------------------------------------------ evidence


def tag_commit(tag):
    rc, out = sh("git", "rev-list", "-n", "1", tag)
    if rc != 0 or not out:
        die(f"tag {tag} not found locally; fetch it first")
    return out


def check_runs(commit):
    """Map check-run name -> conclusion for a commit."""
    rc, out = sh(
        "gh", "api", "--paginate",
        f"repos/{{owner}}/{{repo}}/commits/{commit}/check-runs",
        "--jq", ".check_runs[] | [.name, .conclusion] | @tsv",
    )
    if rc != 0:
        return None
    runs = {}
    for line in out.splitlines():
        if "\t" in line:
            name, conclusion = line.split("\t", 1)
            # A name can appear more than once across re-runs; success wins,
            # because a passing re-run is what the tree is at.
            if runs.get(name) != "success":
                runs[name] = conclusion
    return runs


def release_assets(tag):
    rc, out = sh("gh", "release", "view", tag, "--json", "assets")
    if rc != 0:
        return None
    return [a["name"] for a in json.loads(out).get("assets", [])]


def release_digests(tag):
    """sha256 -> filename, from the candidate's published SHA256SUMS.

    Returns None when the list could not be read at all, which callers must
    treat as "cannot verify" rather than "nothing to check against". An
    unreachable checksum list is the one case where a stale attestation would
    otherwise sail through as PASS.
    """
    rc, out = sh("gh", "release", "download", tag, "--pattern", "SHA256SUMS",
                 "--output", "-")
    if rc != 0:
        return None
    digests = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2:
            digests[parts[0]] = parts[1]
    return digests


def tag_is_signed(tag):
    rc, _ = sh("git", "tag", "-v", tag)
    return rc == 0


def load_attestations():
    if not ATTEST_DIR.is_dir():
        return []
    out = []
    for f in sorted(ATTEST_DIR.glob("*.toml")):
        try:
            with f.open("rb") as fh:
                a = tomllib.load(fh)
        except tomllib.TOMLDecodeError as e:
            die(f"{f.name}: {e}")
        a["_file"] = f.name
        out.append(a)
    return out


# --------------------------------------------------------------- evaluation


def eval_attestation(att, digests, human_required):
    """Return (status, note) for one matched attestation."""
    if human_required and att.get("performed_by", "").endswith("-agent"):
        return FAIL, (f"{att['_file']}: performed_by is an agent; this gate "
                      "requires a human observer")
    sha = att.get("artifact_sha256")
    if not sha:
        return FAIL, f"{att['_file']}: no artifact_sha256"
    if digests is None:
        # Fail closed. If the candidate's SHA256SUMS cannot be read, the
        # attestation cannot be tied to these bits, and an unverifiable claim
        # is not evidence.
        return ERROR, (f"{att['_file']}: cannot read SHA256SUMS for this "
                       "candidate, so the attested artifact is unverifiable")
    if sha not in digests:
        return STALE, (f"{att['_file']}: artifact {sha[:12]} is not in this "
                       "candidate's SHA256SUMS")
    who = att.get("performed_by", "?")
    when = att.get("performed_at", "?")
    return PASS, f"{att['_file']} ({who}, {when})"


def evaluate(gates, tag, commit):
    """Yield (gate_id, label, status, note) rows."""
    runs = check_runs(commit)
    assets = release_assets(tag)
    digests = release_digests(tag)
    atts = load_attestations()
    platforms = gates.get("platform", [])

    for g in gates.get("gate", []):
        gid, kind = g["id"], g.get("evidence")

        if kind == "github-check":
            name = g["check"]
            if runs is None:
                yield gid, g["title"], ERROR, "could not read check runs (gh auth?)"
            elif name not in runs:
                yield gid, g["title"], MISSING, f"no check run named {name!r}"
            elif runs[name] == "success":
                yield gid, g["title"], PASS, f"{name} on {commit[:8]}"
            else:
                yield gid, g["title"], FAIL, f"{name}: {runs[name]}"

        elif kind == "github-check-all":
            # One gate, many named check runs. Every one must pass, and a
            # name that produced no run at all is a miss rather than a pass:
            # a matrix leg that silently stopped running is exactly the kind
            # of erosion this catches.
            if runs is None:
                yield gid, g["title"], ERROR, "could not read check runs (gh auth?)"
                continue
            absent = [c for c in g["checks"] if c not in runs]
            failed = [c for c in g["checks"]
                      if c in runs and runs[c] != "success"]
            if absent:
                yield gid, g["title"], MISSING, "no run for: " + ", ".join(absent)
            elif failed:
                yield gid, g["title"], FAIL, "failed: " + ", ".join(failed)
            else:
                yield (gid, g["title"], PASS,
                       f"{len(g['checks'])}/{len(g['checks'])} legs on {commit[:8]}")

        elif kind == "release-asset":
            if assets is None:
                yield gid, g["title"], MISSING, f"no published release for {tag}"
                continue
            absent = [p for p in g["assets"]
                      if not any(fnmatch.fnmatch(a, p) for a in assets)]
            if absent:
                yield gid, g["title"], FAIL, "missing: " + ", ".join(absent)
            else:
                yield gid, g["title"], PASS, f"{len(g['assets'])} patterns matched"

        elif kind == "signed-tag":
            if tag_is_signed(tag):
                yield gid, g["title"], PASS, "good signature"
            else:
                yield gid, g["title"], FAIL, "tag is unsigned or unverifiable"

        elif kind == "per-platform":
            for p in platforms:
                label = f"{g['title']} [{p['id']}]"
                # A CI job that proves this platform outranks an attestation:
                # it re-runs on every candidate, so it cannot go stale the way
                # a hand-recorded observation can. Only gates that need a human
                # observer refuse it.
                if p.get("check") and not g.get("human_required"):
                    if runs is None:
                        yield gid, label, ERROR, "could not read check runs (gh auth?)"
                    elif p["check"] not in runs:
                        yield (gid, label, MISSING,
                               f"no run for {p['check']!r} on this commit")
                    elif runs[p["check"]] == "success":
                        yield gid, label, PASS, f"{p['check']} on {commit[:8]}"
                    else:
                        yield gid, label, FAIL, f"{p['check']}: {runs[p['check']]}"
                    continue
                match = [a for a in atts
                         if a.get("kind") == g["kind"]
                         and a.get("platform") == p["id"]]
                if not match:
                    yield (gid, label, MISSING,
                           f"no {g['kind']} attestation for {p['id']} "
                           f"({p['method']})")
                    continue
                status, note = eval_attestation(
                    match[-1], digests, g.get("human_required", False))
                yield gid, label, status, note

        elif kind == "attestation":
            match = [a for a in atts if a.get("kind") == g["kind"]]
            if not match:
                yield gid, g["title"], MISSING, f"no {g['kind']} attestation"
                continue
            status, note = eval_attestation(
                match[-1], digests, g.get("human_required", False))
            yield gid, label_of(g), status, note

        else:
            yield gid, g["title"], ERROR, f"unknown evidence kind {kind!r}"


def label_of(g):
    return g["title"]


# ------------------------------------------------------------------- output


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", help="candidate tag (default: most recent tag)")
    ap.add_argument("--verbose", action="store_true",
                    help="print what each gate proves")
    args = ap.parse_args()

    if not GATES.is_file():
        die(f"{GATES} not found")
    with GATES.open("rb") as fh:
        gates = tomllib.load(fh)

    tag = args.tag
    if not tag:
        _, tag = sh("git", "describe", "--tags", "--abbrev=0")
        if not tag:
            die("no tag given and none found")
    commit = tag_commit(tag)

    rows = list(evaluate(gates, tag, commit))
    width = max(len(r[1]) for r in rows) + 2

    print(f"\nRelease readiness: {tag} ({commit[:8]})\n")
    print(f"{'':4} {'GATE'.ljust(width)} {'STATUS':8} EVIDENCE")
    print("-" * (width + 60))
    for gid, label, status, note in rows:
        print(f"{gid:4} {label.ljust(width)} {status:8} {note}")

    blocking = [r for r in rows if r[2] in BAD]
    print()
    if blocking:
        print(f"VERDICT: NO-GO ({len(blocking)} blocking "
              f"{'gate' if len(blocking) == 1 else 'gates'} unmet)")
        for gid, label, status, _ in blocking:
            print(f"  {status:8} {gid}  {label}")
        return 1

    print("VERDICT: GO")
    return 0


if __name__ == "__main__":
    sys.exit(main())
