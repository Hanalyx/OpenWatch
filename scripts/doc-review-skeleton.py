#!/usr/bin/env python3
"""Generate an UNSIGNED documentation-review skeleton for a candidate commit.

    python3 -S scripts/doc-review-skeleton.py --commit <sha> [--tag vX.Y.Z]

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

Standard library only, no network.
"""

import argparse
import hashlib
import subprocess
import sys

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
    h = hashlib.sha256()
    for path, blob in entries:
        h.update(path)
        h.update(b"\0")
        h.update(blob.encode("ascii"))
        h.update(b"\0")
        h.update(verdict.encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()


def toml_escape(s):
    out = s.replace("\\", "\\\\").replace('"', '\\"')
    return out.replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--commit", required=True)
    ap.add_argument("--tag", default="")
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

    print("# UNSIGNED SKELETON. Not evidence until a human fills it in.")
    print("#")
    print("# Set every verdict to \"accurate\" ONLY for a document you have read")
    print("# against this commit and found accurate. Any other value is a NO-GO,")
    print("# and there is no waiver mechanism. Then set performed_by to your own")
    print("# name and performed_at to the date you finished, fill in the artifact")
    print("# identity and digest from the candidate's SHA256SUMS, and recompute")
    print("# docs_sha256 once the verdicts are final.")
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


if __name__ == "__main__":
    main()
