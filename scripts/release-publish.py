#!/usr/bin/env python3
"""Publish a verified GA draft without touching its assets.

    python3 -S scripts/release-publish.py --tag v0.8.0            (dry run)
    python3 -S scripts/release-publish.py --tag v0.8.0 --yes      (publish)

A GA candidate's assets are built once into a DRAFT release, and every piece
of evidence (the checker's own digest and signature verification, D1, F1 to
F3, H1) binds to the digests of that one build. Publication is the act of
making that exact draft visible. This script:

  1. refuses unless the release for the tag exists and is a draft;
  2. runs the full readiness evaluation and refuses on anything but GO;
  3. records every asset's id, name and size, the SHA256SUMS content, and
     the commit the tag names on origin;
  4. re-reads the release and refuses if anything in (3) changed meanwhile;
  5. flips the single `draft` flag through the GitHub API;
  6. re-reads the release and reports, loudly, if what is now published is
     not byte-for-byte what was verified.

It never uploads, deletes, renames or rebuilds an asset. It never creates a
tag. It cannot be run by an agent to any effect a human did not authorize:
the --yes flag is the human's, and GO is a precondition, not a substitute.

Spec: release-ci-gates C-14 / AC-20.
"""

import argparse
import importlib.util
import sys
import tempfile
import tomllib
from pathlib import Path

_here = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("release_status", _here / "release-status.py")
rs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rs)

REFUSED, CHANGED = 2, 3


class Refuse(Exception):
    """A precondition failed; nothing was changed."""


class Changed(Exception):
    """The release changed under us. If raised after the flip, the release
    is published and does not match what was verified: say so."""


def snapshot(tag, info, sums_text):
    """Everything publication exposes: which release, which assets, what the
    manifest says, and which commit the tag names on origin. A change to any
    of these between the verdict and the flip is a different candidate."""
    return {
        "id": info["id"],
        "assets": sorted((a["id"], a["name"], a["size"]) for a in info["assets"]),
        "sums": sums_text,
        "commit": rs.remote_tag_commit(tag),
    }


def read_sums(info):
    sums = rs._asset_by_name(info, "SHA256SUMS")
    if sums is None:
        return None
    rc, raw = rs.sh_bytes(
        "gh", "api", "-H", "Accept: application/octet-stream",
        f"repos/{{owner}}/{{repo}}/releases/assets/{sums['id']}",
    )
    return raw.decode("utf-8", "replace") if rc == 0 else None


def require_draft(tag):
    info = rs.release_info(tag)
    if info is None:
        raise Refuse(f"could not read releases for {tag} (gh auth?)")
    if not info.get("exists"):
        raise Refuse(f"no release exists for {tag}; there is nothing to publish")
    if info.get("ambiguous"):
        raise Refuse(f"{info['ambiguous']} releases name {tag}; resolve that first")
    if not info["draft"]:
        raise Refuse(f"the release for {tag} is already published; nothing to do "
                     "and nothing may be rebuilt")
    if not info["assets"]:
        raise Refuse(f"the draft for {tag} carries no assets")
    return info


def verdict(gates, tag, commit, workdir):
    rows = list(rs.evaluate(gates, tag, commit, workdir))
    blocking = [r for r in rows if r[2] in rs.BAD]
    return rows, blocking


def flip(release_id):
    rc, out = rs.sh("gh", "api", "-X", "PATCH",
                    f"repos/{{owner}}/{{repo}}/releases/{release_id}",
                    "-F", "draft=false")
    if rc != 0:
        raise Refuse(f"publish request failed: {out[:200]}")


def publish(tag, gates, confirm, workdir, out=print):
    """Returns 0 on success, REFUSED when a precondition failed and nothing
    was changed, CHANGED when the published release does not match what was
    verified."""
    try:
        info = require_draft(tag)
        commit = rs.tag_commit(tag)
        rows, blocking = verdict(gates, tag, commit, workdir)
        width = max(len(r[1]) for r in rows) + 2
        for gid, label, status, note in rows:
            out(f"{gid:4} {label.ljust(width)} {status:8} {note}")
        if blocking:
            names = ", ".join(f"{r[0]} {r[2]}" for r in blocking)
            raise Refuse(f"verdict is NO-GO ({names}); a draft is published only on GO")
        sums = read_sums(info)
        if sums is None:
            raise Refuse("could not read SHA256SUMS from the draft")
        before = snapshot(tag, info, sums)
        if before["commit"] is None:
            raise Refuse(f"cannot resolve {tag} on origin; a tag that cannot be read "
                         "cannot be published")
        if before["commit"] != commit:
            raise Refuse(f"{tag} names {before['commit'][:12]} on origin but the verdict "
                         f"was for {commit[:12]}; the tag moved or the local tag is stale")
        out(f"\nDraft release {before['id']} for {tag} ({commit[:8]}): "
            f"{len(before['assets'])} assets, verdict GO.")
        for _, name, size in before["assets"]:
            out(f"  {size:>12}  {name}")
        if not confirm:
            out("\nDry run. Re-run with --yes to publish exactly these assets.")
            return 0

        # The window between GO and the flip is where a re-run of release.yml
        # would substitute bytes. Re-read and compare before acting.
        again = require_draft(tag)
        if snapshot(tag, again, read_sums(again)) != before:
            raise Refuse("the draft, its manifest or the tag changed since it was "
                         "verified; nothing published")
        flip(before["id"])
    except Refuse as e:
        out(f"\nrelease-publish: REFUSED: {e}")
        return REFUSED

    after = rs.release_info(tag)
    if after is None or not after.get("exists") or after.get("ambiguous") or after["draft"]:
        out(f"\nrelease-publish: the flip did not take; release state is "
            f"{rs.release_state(tag, after)}")
        return CHANGED
    now = snapshot(tag, after, read_sums(after))
    if now != before:
        out(f"\nrelease-publish: PUBLISHED BUT CHANGED: what is now public for {tag} "
            "is not what was verified. Treat every attestation for this tag as "
            "stale and investigate before announcing.")
        return CHANGED
    out(f"\nrelease-publish: published {tag}; {len(now['assets'])} assets, "
        "unchanged from the verified draft.")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True, help="the GA tag whose draft to publish")
    ap.add_argument("--yes", action="store_true",
                    help="publish; without it, evaluate and report only")
    args = ap.parse_args()
    if not rs.GATES.is_file():
        rs.die(f"{rs.GATES} not found")
    with rs.GATES.open("rb") as fh:
        gates = tomllib.load(fh)
    workdir = Path(tempfile.mkdtemp(prefix="release-publish-"))
    return publish(args.tag, gates, args.yes, workdir)


if __name__ == "__main__":
    sys.exit(main())
