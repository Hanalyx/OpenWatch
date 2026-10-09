#!/usr/bin/env python3
"""Generate an UNSIGNED documentation-review skeleton for a candidate commit.

    python3 -S scripts/doc-review-skeleton.py --commit <sha> [--tag vX.Y.Z]
        [--inherit-from <last published release's documentation review>]

What it does: enumerates every tracked blob whose path ends in ".md" at that
commit, in raw-path-byte order, and writes a TOML skeleton with one reviewed
entry per document.

What it deliberately does NOT do:

  * It leaves every verdict as "pending". Only a human who has read the
    document may write "accurate", and the release checker fails anything that
    is not "accurate".
  * It leaves performed_by and performed_at empty. This tool must not create a
    human attestation on anyone's behalf, and the checker refuses a
    performed_by ending in "-agent" anyway.
  * It does not compute docs_sha256 over the pending verdicts and present it as
    final. The digest covers the verdicts too, so it is only meaningful once
    they are filled in. The MANIFEST digest it prints is over the same records
    with every verdict set to "accurate", which is what the finished review
    will hash to if nothing in the tree changes and every verdict is accurate.

With --inherit-from (release-ci-gates C-21), it splits the documents in two:

  * [[inherited]]: same path and same blob as in the prior review, AND no
    mention of any non-document file that changed since the prior release.
    These carry the prior verdict; they get no verdict or date of their own.
  * [[reviewed]]: everything else, verdict "pending". A document whose bytes
    are unchanged but which names a changed file (a workflow, go.mod, a
    script) is put here with a comment saying why: matching bytes do not prove
    the behavior it describes is unchanged. The reviewer may move it to
    [[inherited]] after judging it unaffected, and should move any other
    document whose subject changed even if this text scan missed it.

It writes the [inherits] table from the prior file, except changes_reviewed,
which the reviewer fills in to state that the listed changes were checked.

Standard library only, no network.
"""

import argparse
import hashlib
import subprocess
import sys
import tomllib

DOC_SUFFIX = b".md"


def candidate_docs(commit):
    """[(path_bytes, blob_hex)] sorted by raw path bytes."""
    p = subprocess.run(["git", "ls-tree", "-r", "-z", commit], capture_output=True)
    if p.returncode != 0:
        sys.exit(f"doc-review-skeleton: cannot read the tree at {commit}: "
                 f"{p.stderr.decode('utf-8', 'replace').strip()}")
    out = []
    for rec in p.stdout.split(b"\0"):
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
            sys.exit(f"doc-review-skeleton: tracked path {path!r} is not valid "
                     "UTF-8, so TOML cannot carry it faithfully. Rename it or "
                     "the candidate cannot be attested.")
        out.append((path, parts[2].decode("ascii")))
    out.sort(key=lambda e: e[0])
    return out


def manifest_digest(entries, verdict):
    """sha256 over `path NUL blob NUL verdict NUL`, ordered by raw path."""
    return manifest_digest_of([(p, b, verdict) for p, b in entries])


def manifest_digest_of(records):
    """The same digest over (path, blob, verdict) records with mixed verdicts."""
    h = hashlib.sha256()
    for path, blob, verdict in sorted(records, key=lambda r: r[0]):
        h.update(path)
        h.update(b"\0")
        h.update(blob.encode("ascii"))
        h.update(b"\0")
        h.update(verdict.encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()


def changed_non_docs(prior_commit, commit):
    """Paths of non-document files changed between the two commits."""
    p = subprocess.run(["git", "diff", "--name-only", "-z", f"{prior_commit}..{commit}"],
                       capture_output=True)
    if p.returncode != 0:
        sys.exit(f"doc-review-skeleton: cannot diff {prior_commit[:12]}..{commit[:12]}: "
                 f"{p.stderr.decode('utf-8', 'replace').strip()}")
    return sorted(x.decode("utf-8", "replace") for x in p.stdout.split(b"\0")
                  if x and not x.endswith(DOC_SUFFIX))


def mentions(blob, changed):
    """Changed paths, or their file names, that the document's text names."""
    text = subprocess.run(["git", "cat-file", "blob", blob],
                          capture_output=True).stdout.decode("utf-8", "replace")
    hits = []
    for path in changed:
        name = path.rsplit("/", 1)[-1]
        if path in text or (len(name) >= 6 and name in text):
            hits.append(path)
    return hits


# TOML basic strings forbid every control character except tab, and require an
# escape for backslash and quote. Git permits any byte except NUL and "/" in a
# path component, so a filename can legally carry a backspace, a form feed or a
# DEL, and emitting one raw produces a file tomllib refuses to parse. Anything
# without a short escape goes out as \uXXXX.
_SHORT = {
    0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r",
    0x22: '\\"', 0x5C: "\\\\",
}


def toml_escape(s):
    out = []
    for ch in s:
        cp = ord(ch)
        if cp in _SHORT:
            out.append(_SHORT[cp])
        elif cp < 0x20 or cp == 0x7F:
            out.append(f"\\u{cp:04X}")
        else:
            out.append(ch)
    return "".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--commit", required=True)
    ap.add_argument("--tag", default="")
    ap.add_argument("--inherit-from", default="",
                    help="the last published release's documentation review (C-21)")
    args = ap.parse_args()

    rc = subprocess.run(["git", "rev-parse", "--verify", f"{args.commit}^{{commit}}"],
                        capture_output=True, text=True)
    if rc.returncode != 0:
        sys.exit(f"doc-review-skeleton: {args.commit} is not a commit in this repository")
    commit = rc.stdout.strip()

    docs = candidate_docs(commit)
    if not docs:
        sys.exit(f"doc-review-skeleton: no tracked .md blobs at {commit[:12]}; "
                 "refusing to write an empty review")
    if args.inherit_from:
        inheriting(args, commit, docs)
        return

    print("# UNSIGNED SKELETON. Not evidence until a human fills it in.")
    print("#")
    print("# Set every verdict to \"accurate\" ONLY for a document you have read")
    print("# against this commit and found accurate. Any other value is a NO-GO,")
    print("# and there is no general waiver. The only exception is C-22: for v0.8.4,")
    print("# the two documents registered in release/doc-review-exceptions.toml may be")
    print("# \"accepted-defect\", never \"accurate\", with the release captain's internal")
    print("# [[defect_acceptance]] entries. Then set performed_by to your own")
    print("# name and performed_at to the date you finished, fill in the artifact")
    print("# identity and digest from the candidate's SHA256SUMS, and recompute")
    print("# docs_sha256 once the verdicts are final.")
    print("#")
    print("# This file is internal evidence. Keep it untracked; after publication")
    print("# archive it outside the repository with a verified checksum manifest.")
    print("# Never commit it and never upload it.")
    print("#")
    print(f"# If every verdict ends up \"accurate\" and the tree does not move,")
    print(f"# docs_sha256 will be:")
    print(f"#   {manifest_digest(docs, 'accurate')}")
    print()
    print('kind = "documentation-review"')
    print(f'tag = "{toml_escape(args.tag)}"')
    print(f'commit = "{commit}"')
    print('artifact = ""')
    print('artifact_sha256 = ""')
    print('performed_by = ""')
    print('performed_at = ""')
    print('docs_sha256 = ""')
    print()
    print(f"# {len(docs)} documents, ordered by raw path bytes. The count is a")
    print("# reading of this commit, not a target.")
    for path, blob in docs:
        print()
        print("[[reviewed]]")
        print(f'path = "{toml_escape(path.decode("utf-8"))}"')
        print(f'blob = "{blob}"')
        print('verdict = "pending"')


def inheriting(args, commit, docs):
    raw = open(args.inherit_from, "rb").read()
    prior = tomllib.loads(raw.decode("utf-8"))
    for field in ("tag", "commit", "docs_sha256"):
        if not isinstance(prior.get(field), str) or not prior[field]:
            sys.exit(f"doc-review-skeleton: {args.inherit_from} has no {field}")
    prior_docs = {}
    for key in ("reviewed", "inherited"):
        for r in prior.get(key, []) or []:
            prior_docs[r["path"].encode("utf-8")] = r["blob"]
    changed = changed_non_docs(prior["commit"], commit)

    reviewed, inherited = [], []
    for path, blob in docs:
        old = prior_docs.get(path)
        if old is None:
            reviewed.append((path, blob, f"new since {prior['tag']}"))
        elif old != blob:
            reviewed.append((path, blob, f"changed since {prior['tag']}"))
        elif hits := mentions(blob, changed):
            reviewed.append((path, blob,
                             f"unchanged since {prior['tag']}, but names changed "
                             f"{', '.join(hits)}; move to [[inherited]] only if unaffected"))
        else:
            inherited.append((path, blob))

    records = [(p, b, "accurate") for p, b, _ in reviewed] + \
              [(p, b, "inherited") for p, b in inherited]
    print("# UNSIGNED SKELETON. Not evidence until a human fills it in.")
    print("#")
    print(f"# Inherits from the {prior['tag']} documentation review (release-ci-gates C-21).")
    print("#")
    print("# PROVISIONAL SPLIT. A document that names a changed file is flagged for fresh")
    print("# review; that is a text scan, not a dependency analysis. Decide for every")
    print("# inherited document whether a behavior change since the prior release makes")
    print("# it inaccurate, and move it to [[reviewed]] if so.")
    print("# [[reviewed]] documents need a fresh read against this commit: set each")
    print("# verdict to \"accurate\" only after reading it. There is no general waiver;")
    print("# C-22 covers only the two v0.8.4 documents registered in")
    print("# release/doc-review-exceptions.toml. [[inherited]] documents")
    print(f"# carry the {prior['tag']} verdict; they have no verdict or date here, and")
    print("# performed_by and performed_at describe only the fresh reviews.")
    print("#")
    print(f"# Non-document files changed since {prior['tag']} ({len(changed)}). Check each for")
    print("# effects on the inherited documents, move any affected one to [[reviewed]],")
    print("# then set inherits.changes_reviewed to the range below:")
    for path in changed:
        print(f"#   {toml_escape(path)}")
    print("#")
    print("# This file is internal evidence. Keep it untracked; after publication")
    print("# archive it outside the repository with a verified checksum manifest.")
    print("# Never commit it and never upload it.")
    print("#")
    print("# If every reviewed verdict ends up \"accurate\" and no document moves,")
    print("# docs_sha256 will be:")
    print(f"#   {manifest_digest_of(records)}")
    print()
    print('kind = "documentation-review"')
    print(f'tag = "{toml_escape(args.tag)}"')
    print(f'commit = "{commit}"')
    print('artifact = ""')
    print('artifact_sha256 = ""')
    print('performed_by = ""')
    print('performed_at = ""')
    print('docs_sha256 = ""')
    print()
    print("[inherits]")
    print(f'tag = "{toml_escape(prior["tag"])}"')
    print(f'commit = "{prior["commit"]}"')
    print(f'attestation_sha256 = "{hashlib.sha256(raw).hexdigest()}"')
    print(f'docs_sha256 = "{prior["docs_sha256"]}"')
    print(f'# set to "{prior["commit"]}..{commit}" once the changes above are checked')
    print('changes_reviewed = ""')
    print()
    print(f"# {len(reviewed)} documents to review for this candidate.")
    for path, blob, why in reviewed:
        print()
        print(f"# {toml_escape(why)}")
        print("[[reviewed]]")
        print(f'path = "{toml_escape(path.decode("utf-8"))}"')
        print(f'blob = "{blob}"')
        print('verdict = "pending"')
    print()
    print(f"# {len(inherited)} documents inherited from {prior['tag']}: same path, same blob.")
    for path, blob in inherited:
        print()
        print("[[inherited]]")
        print(f'path = "{toml_escape(path.decode("utf-8"))}"')
        print(f'blob = "{blob}"')


if __name__ == "__main__":
    main()
