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
import datetime
import hashlib
import subprocess
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GATES = REPO / "release" / "gates.toml"
ATTEST_DIR = REPO / "release" / "attestations"

PASS, FAIL, MISSING, STALE, ERROR = "PASS", "FAIL", "MISSING", "STALE", "ERROR"
# A run that has not finished is not a failure. Reporting one as FAIL says a
# candidate is broken when it is merely early, which is the same class of error
# as calling an empty field a fact about the host.
PENDING = "PENDING"
# N/A is not a pass and not a failure: the claim cannot apply to this platform,
# and the manifest has to carry the reason so nobody re-opens it as a gap.
NA = "N/A"
BAD = {FAIL, MISSING, STALE, ERROR, PENDING}


def sh(*args, check=False):
    """Run a command, returning (rc, stdout). Never raises on non-zero."""
    p = subprocess.run(args, capture_output=True, text=True)
    if check and p.returncode != 0:
        die(f"{' '.join(args)}: {p.stderr.strip()}")
    return p.returncode, p.stdout.strip()


def sh_bytes(*args):
    """Run a command, returning (rc, raw stdout). Paths are bytes in git and
    stay bytes here: decoding them early is how a path that is legal on disk
    and illegal in UTF-8 turns into a silently different path."""
    p = subprocess.run(args, capture_output=True)
    return p.returncode, p.stdout


def die(msg):
    print(f"release-status: {msg}", file=sys.stderr)
    sys.exit(2)


# ------------------------------------------- documentation review evidence

# The scope is every tracked blob whose path ends in ".md", read from the
# CANDIDATE COMMIT. Not the working tree, not the index, and no directory
# exclusions: .github, .claude and scripts/README.md are documentation a
# reader can reach, so they are in scope like any other.
#
# No corpus count appears anywhere in this file. A count has to be edited on
# every addition and fails nothing when it is not, so the only counts here are
# derived at runtime from the tree in hand and reported alongside the result.

DOC_SUFFIX = b".md"


class PathNotEncodable(Exception):
    """A tracked path that TOML cannot carry faithfully."""

    def __init__(self, raw):
        super().__init__(raw)
        self.raw = raw


def candidate_docs(commit):
    """[(path_bytes, blob_hex)] for the candidate commit, sorted by raw path.

    Raises PathNotEncodable when a path is not valid UTF-8: a TOML string is
    UTF-8, so such a path cannot be written into an attestation and read back
    as itself. Failing loudly beats reviewing a path that is not the one on
    disk.
    """
    rc, raw = sh_bytes("git", "ls-tree", "-r", "-z", commit)
    if rc != 0:
        return None
    out = []
    for rec in raw.split(b"\0"):
        if not rec:
            continue
        meta, _, path = rec.partition(b"\t")
        if not path:
            continue
        parts = meta.split(b" ")
        if len(parts) < 3 or parts[1] != b"blob":
            continue
        if not path.endswith(DOC_SUFFIX):
            continue
        try:
            path.decode("utf-8")
        except UnicodeDecodeError:
            raise PathNotEncodable(path) from None
        out.append((path, parts[2].decode("ascii")))
    out.sort(key=lambda e: e[0])
    return out


def docs_manifest_digest(entries):
    """sha256 over `path NUL blob NUL verdict NUL` records, ordered by raw
    path bytes. NUL-delimited because a newline is a legal character in a git
    path, and a newline-delimited manifest cannot tell one path containing a
    newline from two paths."""
    h = hashlib.sha256()
    for path, blob, verdict in sorted(entries, key=lambda e: e[0]):
        h.update(path)
        h.update(b"\0")
        h.update(blob.encode("ascii"))
        h.update(b"\0")
        h.update(verdict.encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()


def _reviewed_entries(att):
    """[(path_bytes, blob, verdict)] or a diagnostic string."""
    rows = att.get("reviewed")
    if not isinstance(rows, list) or not rows:
        return "carries no reviewed entries"
    out = []
    for i, r in enumerate(rows):
        if not isinstance(r, dict) or set(r) != {"path", "blob", "verdict"}:
            return (f"reviewed[{i}] must carry exactly path, blob and verdict; "
                    f"got {sorted(r) if isinstance(r, dict) else type(r).__name__}")
        if not all(isinstance(r[k], str) for k in ("path", "blob", "verdict")):
            return f"reviewed[{i}] has a non-string field"
        out.append((r["path"].encode("utf-8"), r["blob"], r["verdict"]))
    return out


def diff_docs(candidate, reviewed):
    """(added, removed, edited, renamed) between the candidate tree and the
    reviewed set.

    A rename is claimed ONLY for an unambiguous one-to-one identical-blob
    move: the blob appears exactly once on each side. Anything else stays an
    add plus a remove, because a blob appearing twice cannot say which path
    became which."""
    cand = dict(candidate)
    rev = {p: b for p, b, _ in reviewed}
    added = sorted(p for p in cand if p not in rev)
    removed = sorted(p for p in rev if p not in cand)
    edited = sorted(p for p in cand if p in rev and cand[p] != rev[p])

    by_blob_added = {}
    by_blob_removed = {}
    for p in added:
        by_blob_added.setdefault(cand[p], []).append(p)
    for p in removed:
        by_blob_removed.setdefault(rev[p], []).append(p)
    renamed = []
    for blob, news in by_blob_added.items():
        olds = by_blob_removed.get(blob, [])
        if len(news) == 1 and len(olds) == 1:
            renamed.append((olds[0], news[0]))
    for old, new in renamed:
        added.remove(new)
        removed.remove(old)
    return added, removed, edited, sorted(renamed)


def _show(paths, limit=6):
    names = [p.decode("utf-8", "backslashreplace") for p in paths]
    if len(names) > limit:
        return ", ".join(names[:limit]) + f" (+{len(names) - limit} more)"
    return ", ".join(names)


def artifact_pair_matches(att, digests):
    """Does (artifact, artifact_sha256) name one real file in the candidate?

    The two fields are ONE fact, not two strings that happen to sit together.
    A digest that is present under a different filename says the reviewer held
    a different artifact than the one they named, and checking the digest
    alone would accept it."""
    sha = att.get("artifact_sha256")
    name = att.get("artifact")
    if not sha or not name or digests is None:
        return False
    return digests.get(sha) == name


def _bad_performed_at(value):
    """A diagnostic if performed_at is not a usable calendar date, else None."""
    try:
        when = datetime.date.fromisoformat(value)
    except ValueError:
        return f"performed_at {value!r} is not an ISO calendar date (YYYY-MM-DD)"
    today = datetime.date.today()
    if when > today:
        return (f"performed_at {value} is in the future (today is {today}); "
                "a review cannot have happened yet")
    return None


def eval_doc_review(att, candidate, tag, commit, digests):
    """(status, note) for one documentation-review attestation."""
    if att.get("performed_by", "").endswith("-agent"):
        return FAIL, (f"{att['_file']}: performed_by is an agent; a documentation "
                      "review is a human observation")
    for field in ("tag", "commit", "artifact", "artifact_sha256", "docs_sha256",
                  "performed_by", "performed_at"):
        if not att.get(field):
            return FAIL, f"{att['_file']}: no {field}"
    if bad := _bad_performed_at(att["performed_at"]):
        return FAIL, f"{att['_file']}: {bad}"
    if att["tag"] != tag:
        return STALE, f"{att['_file']}: attests tag {att['tag']}, candidate is {tag}"
    if att["commit"] != commit:
        return STALE, (f"{att['_file']}: attests commit {att['commit'][:12]}, "
                       f"candidate is {commit[:12]}")
    if digests is None:
        return ERROR, (f"{att['_file']}: cannot read SHA256SUMS for this candidate, "
                       "so the attested artifact is unverifiable")
    if att["artifact_sha256"] not in digests:
        return STALE, (f"{att['_file']}: artifact {att['artifact_sha256'][:12]} is not "
                       "in this candidate's SHA256SUMS")
    if not artifact_pair_matches(att, digests):
        return STALE, (f"{att['_file']}: digest {att['artifact_sha256'][:12]} belongs to "
                       f"{digests[att['artifact_sha256']]!r} in this candidate, but the "
                       f"attestation names {att['artifact']!r}")
    if candidate is None:
        return ERROR, (f"{att['_file']}: the candidate tree could not be read at "
                       f"{commit[:12]}")

    reviewed = _reviewed_entries(att)
    if isinstance(reviewed, str):
        return FAIL, f"{att['_file']}: {reviewed}"

    seen = {}
    for path, _, _ in reviewed:
        seen[path] = seen.get(path, 0) + 1
    dupes = sorted(p for p, n in seen.items() if n > 1)
    if dupes:
        return FAIL, f"{att['_file']}: duplicate reviewed path: {_show(dupes)}"

    bad = sorted(p for p, _, v in reviewed if v != "accurate")
    if bad:
        return FAIL, (f"{att['_file']}: every verdict must be 'accurate'; "
                      f"not accurate: {_show(bad)}")

    added, removed, edited, renamed = diff_docs(candidate, reviewed)
    if added or removed or edited or renamed:
        bits = []
        if added:
            bits.append(f"added {_show(added)}")
        if removed:
            bits.append(f"removed {_show(removed)}")
        if edited:
            bits.append(f"edited {_show(edited)}")
        for old, new in renamed:
            bits.append(f"renamed {old.decode('utf-8', 'backslashreplace')} -> "
                        f"{new.decode('utf-8', 'backslashreplace')}")
        return STALE, f"{att['_file']}: the review does not describe this tree: " + "; ".join(bits)

    want = docs_manifest_digest([(p, b, v) for p, b, v in reviewed])
    if want != att["docs_sha256"]:
        return FAIL, (f"{att['_file']}: docs_sha256 is {att['docs_sha256'][:12]}, "
                      f"the reviewed entries hash to {want[:12]}")
    return PASS, (f"{att['_file']} ({att.get('performed_by', '?')}, "
                  f"{att['performed_at']}, {len(reviewed)} documents)")


def select_attestation(atts, kind, digests, platform=None):
    """Pick the attestation of `kind` that binds to THIS candidate.

    Selection used to be match[-1]: whichever file sorted last. Two clean-install
    attestations for the same platform ship today, one per release candidate, so
    the rule that decided which one spoke for a candidate was its filename. A
    stale attestation whose name sorts later hid a matching one, and the
    checker reported the stale one's verdict as the gate's.

    The binding is the artifact PAIR, name and digest together, against the
    candidate's published SHA256SUMS. Two attestations binding to the same gate,
    platform and candidate are an ambiguity to report, not a tie to break."""
    where = f" for {platform}" if platform else ""
    same = [a for a in atts if a.get("kind") == kind
            and (platform is None or a.get("platform") == platform)]
    if not same:
        return None, (MISSING, f"no {kind} attestation{where}")
    if digests is None:
        return None, (ERROR, (f"cannot read SHA256SUMS for this candidate, so no "
                              f"{kind} attestation{where} can be tied to these bits"))
    bound = [a for a in same if artifact_pair_matches(a, digests)]
    if len(bound) > 1:
        names = ", ".join(sorted(a["_file"] for a in bound))
        return None, (ERROR, f"{len(bound)} {kind} attestations{where} bind to this "
                             f"candidate: {names}")
    if len(bound) == 1:
        return bound[0], None
    names = ", ".join(sorted(a["_file"] for a in same))
    return None, (STALE, (f"no {kind} attestation{where} names an artifact in this "
                          f"candidate's SHA256SUMS; have {names}"))


def select_doc_review(atts, kind, tag, commit, digests):
    """Pick the attestation that binds to THIS candidate.

    Never by filename order. A stale attestation whose name sorts later must
    not hide a valid one, and two attestations that both bind to the same
    candidate are an ambiguity to report rather than a tie to break."""
    same_kind = [a for a in atts if a.get("kind") == kind]
    if not same_kind:
        return None, (MISSING, f"no {kind} attestation")
    if digests is None:
        # Fail closed, and as ERROR. Reporting STALE here would say the
        # evidence describes another candidate, when the truth is that nothing
        # could be compared at all.
        return None, (ERROR, (f"cannot read SHA256SUMS for this candidate, so no "
                              f"{kind} attestation can be tied to these bits"))
    bound = [a for a in same_kind
             if a.get("tag") == tag and a.get("commit") == commit
             and artifact_pair_matches(a, digests)]
    if len(bound) > 1:
        names = ", ".join(sorted(a["_file"] for a in bound))
        return None, (ERROR, f"{len(bound)} {kind} attestations bind to this candidate: {names}")
    if len(bound) == 1:
        return bound[0], None
    # None binds. Report against every candidate so the reason is the real
    # one, not whichever file happened to sort last.
    notes = []
    for a in sorted(same_kind, key=lambda x: x["_file"]):
        status, note = eval_doc_review(a, None, tag, commit, digests)
        notes.append(note)
    return None, (STALE, "; ".join(notes))


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
        if "\t" not in line:
            continue
        name, conclusion = line.split("\t", 1)
        # GitHub leaves conclusion empty while a run is in progress. Treat that
        # as pending rather than as a non-success, or a candidate tagged before
        # its main-branch build finishes reads as broken.
        if conclusion == "":
            conclusion = PENDING
        # A name can appear more than once across re-runs; success wins,
        # because a passing re-run is what the tree is at. A finished result
        # also outranks a pending one.
        prev = runs.get(name)
        if prev == "success":
            continue
        if prev is not None and prev != PENDING and conclusion == PENDING:
            continue
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
            elif runs[name] == PENDING:
                yield gid, g["title"], PENDING, f"{name} is still running"
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
            pending = [c for c in g["checks"] if runs.get(c) == PENDING]
            failed = [c for c in g["checks"]
                      if c in runs and runs[c] not in ("success", PENDING)]
            if absent:
                yield gid, g["title"], MISSING, "no run for: " + ", ".join(absent)
            elif failed:
                yield gid, g["title"], FAIL, "failed: " + ", ".join(failed)
            elif pending:
                yield gid, g["title"], PENDING, "still running: " + ", ".join(pending)
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
                # A claim that cannot apply here. Recorded with its reason
                # rather than left MISSING, which would read as unfinished
                # work forever, or marked PASS, which would be a lie.
                na = p.get("not_applicable", {}).get(g["kind"])
                if na:
                    yield gid, label, NA, na
                    continue
                # Scoped per gate kind: a job proves the claims it actually
                # asserts and no others. A job that installs cleanly says
                # nothing about upgrading from the previous GA.
                pcheck = p.get("checks", {}).get(g["kind"])
                if pcheck and not g.get("human_required"):
                    if runs is None:
                        yield gid, label, ERROR, "could not read check runs (gh auth?)"
                    elif pcheck not in runs:
                        yield (gid, label, MISSING,
                               f"no run for {pcheck!r} on this commit")
                    elif runs[pcheck] == "success":
                        yield gid, label, PASS, f"{pcheck} on {commit[:8]}"
                    elif runs[pcheck] == PENDING:
                        yield gid, label, PENDING, f"{pcheck} is still running"
                    else:
                        yield gid, label, FAIL, f"{pcheck}: {runs[pcheck]}"
                    continue
                att, problem = select_attestation(atts, g["kind"], digests, p["id"])
                if problem:
                    status, note = problem
                    if status == MISSING:
                        note = (f"no {g['kind']} attestation for {p['id']} "
                                f"({p['method']})")
                    yield gid, label, status, note
                    continue
                status, note = eval_attestation(
                    att, digests, g.get("human_required", False))
                yield gid, label, status, note

        elif kind == "doc-review":
            try:
                cand = candidate_docs(commit)
            except PathNotEncodable as e:
                raw = e.raw.decode("utf-8", "backslashreplace")
                yield (gid, g["title"], ERROR,
                       f"tracked path {raw!r} is not valid UTF-8, so TOML cannot "
                       "carry it faithfully and it cannot be attested")
                continue
            if cand is None:
                yield (gid, g["title"], ERROR,
                       f"cannot read the tree at {commit[:12]}")
                continue
            att, problem = select_doc_review(atts, g["kind"], tag, commit, digests)
            if problem:
                yield gid, g["title"], problem[0], problem[1]
                continue
            status, note = eval_doc_review(att, cand, tag, commit, digests)
            yield gid, label_of(g), status, note

        elif kind == "attestation":
            att, problem = select_attestation(atts, g["kind"], digests)
            if problem:
                yield gid, g["title"], problem[0], problem[1]
                continue
            status, note = eval_attestation(
                att, digests, g.get("human_required", False))
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
