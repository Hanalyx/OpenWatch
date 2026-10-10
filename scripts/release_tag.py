#!/usr/bin/env python3
"""Cut a release tag on an explicit candidate commit (CP bugs/OW-118).

    python3 -S scripts/release_tag.py --commit <40-hex> --key <40-hex fingerprint>
        # dry run: every check, then stop before signing
    python3 -S scripts/release_tag.py --commit <40-hex> --key <fpr> --sign
        # sign that commit, then verify the tag object and its signature
    python3 -S scripts/release_tag.py --commit <40-hex> --key <fpr> --push
        # re-verify the local tag, push refs/tags/<tag> only, check origin

The candidate is the full commit SHA recorded for the release, typed once. It
is never derived from a branch: the block this replaces tagged whatever main
was at, so a merge after the candidate was chosen would have been tagged
under the candidate's name with no check failing.

The tag name is derived from packaging/version.env AT THE CANDIDATE COMMIT,
never typed. The signing key is named by its full fingerprint and must be a
key in security/KEYS at that commit. Signing uses that key explicitly, not the
repository's user.signingkey.

Checks, all before anything is signed:
  - the commit exists, is a commit, and is an ancestor of origin/main after a
    fetch;
  - VERSION in version.env, the README phrase and the newest CHANGELOG heading
    agree at the commit, and packaging/check-tag-version.sh from that commit
    accepts the derived tag;
  - the tag does not exist locally, on origin, or on any GitHub release,
    drafts included;
  - the key is in security/KEYS at the commit and its secret key is present.

After signing: the tag is an annotated tag object, it names exactly the
candidate commit, and `git verify-tag --raw` reports VALIDSIG from the release
key. After pushing: origin's tag object and its peeled commit match.

Nothing here moves or deletes a tag. A failure after signing leaves the local
tag in place and says so; what to do about it is the release captain's call.
Signing needs the release key unlocked in the captain's own terminal (see
RELEASING.md, "Signing model"); this script is not run from automation.

Spec: release-tagging.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

REPO_SLUG = "Hanalyx/OpenWatch"
_SHA = re.compile(r"^[0-9a-f]{40}$")
_FPR = re.compile(r"^[0-9A-F]{40}$")
_TAG = re.compile(r"^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")


class TagError(Exception):
    """A check refused the candidate, or a step did not verify."""


class Repo(object):
    """git, gpg and gh, run in one working tree. Every call is printed."""

    def __init__(self, path, remote="origin", gh="gh", repo_slug=REPO_SLUG, out=sys.stdout):
        self.path = path
        self.remote = remote
        self.gh = gh
        self.repo_slug = repo_slug
        self.out = out

    def run(self, argv, check=True, input_bytes=None):
        r = subprocess.run(argv, cwd=self.path, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           input=input_bytes)
        if check and r.returncode != 0:
            raise TagError("`%s` exited %d: %s" % (" ".join(argv), r.returncode,
                                                   r.stderr.decode("utf-8", "replace").strip()))
        return r

    def git(self, *args, **kw):
        return self.run(["git"] + list(args), **kw)

    def show(self, commit, path):
        r = self.git("show", "%s:%s" % (commit, path), check=False)
        if r.returncode != 0:
            raise TagError("%s does not exist at %s" % (path, commit))
        return r.stdout.decode("utf-8", "replace")


def say(repo, ok, what):
    repo.out.write("%-5s %s\n" % ("ok" if ok else "FAIL", what))
    repo.out.flush()


def _version_env(text):
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("VERSION="):
            return line[len("VERSION="):].strip("\"'")
    return None


def _readme_version(text):
    flat = " ".join(text.replace("\n>", " ").split())
    m = re.search(r"current version is `([^`]+)`", flat)
    return m.group(1) if m else None


def _changelog_version(text):
    for line in text.splitlines():
        m = re.match(r"^## \[([^\]]+)\]", line)
        if m and m.group(1) != "Unreleased":
            return m.group(1)
    return None


def check_candidate(repo, commit, key, signed=False):
    """Run every pre-signing check. Returns the derived tag name.

    With signed=True (before a push) the local tag is expected to exist; it is
    verified separately. Every other check runs again."""
    if not _SHA.match(commit or ""):
        raise TagError("--commit must be a full 40-character lowercase SHA, not %r. Copy it "
                       "from the release record; never pass a branch or a short SHA" % commit)
    if not _FPR.match(key or ""):
        raise TagError("--key must be the release key's full 40-character fingerprint")
    if repo.git("cat-file", "-t", commit, check=False).stdout.decode().strip() != "commit":
        raise TagError("%s is not a commit in this repository; fetch it first" % commit)
    say(repo, True, "candidate %s is a commit" % commit)

    # Only main is fetched. Tags on origin are checked with ls-remote below,
    # without bringing them into this repository.
    repo.git("fetch", "--quiet", repo.remote, "main")
    main = repo.git("rev-parse", "%s/main" % repo.remote).stdout.decode().strip()
    if repo.git("merge-base", "--is-ancestor", commit, main, check=False).returncode != 0:
        raise TagError("%s is not an ancestor of %s/main (%s)" % (commit, repo.remote, main))
    say(repo, True, "candidate is an ancestor of %s/main (%s)%s" % (
        repo.remote, main, "" if main == commit else "; main has moved on, which is fine"))

    version = _version_env(repo.show(commit, "packaging/version.env"))
    if not version:
        raise TagError("packaging/version.env at %s declares no VERSION" % commit)
    tag = "v" + version
    if not _TAG.match(tag):
        raise TagError("VERSION=%r at %s does not make a release tag" % (version, commit))
    readme = _readme_version(repo.show(commit, "README.md"))
    changelog = _changelog_version(repo.show(commit, "CHANGELOG.md"))
    if readme != version or changelog != version:
        raise TagError("versions disagree at %s: version.env %r, README %r, newest CHANGELOG "
                       "heading %r" % (commit, version, readme, changelog))
    say(repo, True, "VERSION, README and CHANGELOG agree at the candidate: %s" % version)

    # Run the commit's own check-tag-version.sh against the commit's own files.
    work = tempfile.mkdtemp(prefix="release-tag-")
    try:
        arch = repo.git("archive", "--format=tar", commit, "packaging/check-tag-version.sh",
                        "packaging/version.env").stdout
        path = os.path.join(work, "a.tar")
        with open(path, "wb") as f:
            f.write(arch)
        with tarfile.open(path) as tf:
            for m in tf.getmembers():
                if m.isdir() and m.name.rstrip("/") == "packaging":
                    continue
                if not m.isreg() or m.name not in ("packaging/check-tag-version.sh",
                                                   "packaging/version.env"):
                    raise TagError("unexpected archive member %r" % m.name)
            if hasattr(tarfile, "data_filter"):
                tf.extractall(work, filter="data")
            else:
                tf.extractall(work)
        env = dict(os.environ, RELEASE_REF=tag)
        r = subprocess.run(["bash", os.path.join(work, "packaging", "check-tag-version.sh")],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        if r.returncode != 0:
            raise TagError("check-tag-version.sh at %s refused %s: %s" % (
                commit, tag, r.stderr.decode("utf-8", "replace").strip()))
    finally:
        shutil.rmtree(work, True)
    say(repo, True, "check-tag-version.sh at the candidate accepts %s" % tag)

    if not signed and repo.git("rev-parse", "-q", "--verify", "refs/tags/" + tag,
                               check=False).returncode == 0:
        raise TagError("tag %s already exists locally. Tags are never moved or reused; a "
                       "refused candidate takes the next version" % tag)
    remote_refs = repo.git("ls-remote", "--tags", repo.remote, "refs/tags/" + tag).stdout.strip()
    if remote_refs:
        raise TagError("tag %s already exists on %s" % (tag, repo.remote))
    rel = repo.run([repo.gh, "api", "--paginate", "repos/%s/releases" % repo.repo_slug,
                    "--jq", ".[].tag_name"])
    if tag in rel.stdout.decode().split():
        raise TagError("a GitHub release (possibly a draft) already uses %s" % tag)
    say(repo, True, "%s exists %s: not on %s, not on any release or draft" % (
        tag, "only as the local signed tag" if signed else "nowhere: not locally",
        repo.remote))

    keys = repo.git("show", "%s:security/KEYS" % commit, check=False)
    if keys.returncode != 0:
        raise TagError("security/KEYS does not exist at %s" % commit)
    listed = repo.run(["gpg", "--batch", "--with-colons", "--import-options", "show-only",
                       "--import"], input_bytes=keys.stdout).stdout.decode()
    primaries = _primary_fingerprints(listed)
    if key not in primaries:
        raise TagError("key %s is not a primary key in security/KEYS at %s" % (key, commit))
    secret = repo.run(["gpg", "--batch", "--with-colons", "--list-secret-keys", key],
                      check=False)
    if secret.returncode != 0 or key not in _primary_fingerprints(secret.stdout.decode()):
        raise TagError("the secret key for %s is not available to gpg here" % key)
    say(repo, True, "release key %s is in security/KEYS at the candidate, secret key present"
        % key)
    return tag


def _primary_fingerprints(colons):
    out = []
    want = False
    for line in colons.splitlines():
        f = line.split(":")
        if f[0] in ("pub", "sec"):
            want = True
        elif f[0] == "fpr" and want:
            out.append(f[9])
            want = False
        elif f[0] in ("sub", "ssb"):
            want = False
    return out


def verify_tag(repo, tag, commit, key):
    """The local tag is a signed tag object naming the commit, signed by key."""
    if repo.git("cat-file", "-t", "refs/tags/" + tag, check=False).stdout.decode().strip() != "tag":
        raise TagError("refs/tags/%s is not an annotated tag object" % tag)
    body = repo.git("cat-file", "-p", "refs/tags/" + tag).stdout.decode("utf-8", "replace")
    head = dict(l.split(" ", 1) for l in body.split("\n\n", 1)[0].splitlines() if " " in l)
    if head.get("object") != commit or head.get("type") != "commit" or head.get("tag") != tag:
        raise TagError("tag %s names %s %s as %r, not commit %s" % (
            tag, head.get("type"), head.get("object"), head.get("tag"), commit))
    r = repo.git("verify-tag", "--raw", tag, check=False)
    status = r.stderr.decode("utf-8", "replace")
    valid = [l.split() for l in status.splitlines() if l.startswith("[GNUPG:] VALIDSIG ")]
    # VALIDSIG <signing key fpr> ... [<primary key fpr>]: the last field is the
    # primary key whenever a subkey signed.
    if r.returncode != 0 or not valid or key not in (valid[0][2], valid[0][-1]):
        raise TagError("tag %s does not carry a valid signature from %s" % (tag, key))
    tag_object = repo.git("rev-parse", "refs/tags/" + tag).stdout.decode().strip()
    say(repo, True, "tag %s (object %s) names commit %s, signed by %s"
        % (tag, tag_object, commit, key))
    return tag_object


def sign(repo, tag, commit, key):
    r = repo.git("tag", "-s", "-u", key, "-m", tag, tag, commit, check=False)
    if r.returncode != 0:
        raise TagError("signing failed, no tag was pushed: %s"
                       % r.stderr.decode("utf-8", "replace").strip())
    try:
        return verify_tag(repo, tag, commit, key)
    except TagError as e:
        raise TagError("%s. The local tag %s was created and is NOT pushed. It is not moved "
                       "or deleted here; decide with the release captain" % (e, tag))


def push(repo, tag, commit, key):
    tag_object = verify_tag(repo, tag, commit, key)
    if repo.git("ls-remote", "--tags", repo.remote, "refs/tags/" + tag).stdout.strip():
        raise TagError("tag %s appeared on %s before the push; nothing was pushed"
                       % (tag, repo.remote))
    repo.git("push", repo.remote, "refs/tags/%s:refs/tags/%s" % (tag, tag))
    refs = {}
    for line in repo.git("ls-remote", "--tags", repo.remote, "refs/tags/" + tag,
                         "refs/tags/%s^{}" % tag).stdout.decode().splitlines():
        sha, ref = line.split("\t")
        refs[ref] = sha
    if refs.get("refs/tags/" + tag) != tag_object or refs.get("refs/tags/%s^{}" % tag) != commit:
        raise TagError("after the push, %s on %s is %r; expected tag object %s naming %s"
                       % (tag, repo.remote, refs, tag_object, commit))
    say(repo, True, "%s on %s: tag object %s, commit %s" % (tag, repo.remote, tag_object, commit))


def main(argv=None, out=sys.stdout):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--commit", required=True, help="the candidate's full commit SHA")
    p.add_argument("--key", required=True, help="the release key's full fingerprint")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--sign", action="store_true", help="sign the tag after every check")
    mode.add_argument("--push", action="store_true", help="push an already signed tag")
    p.add_argument("--repo", default=".", help=argparse.SUPPRESS)
    p.add_argument("--remote", default="origin", help=argparse.SUPPRESS)
    p.add_argument("--gh", default="gh", help=argparse.SUPPRESS)  # tests: a fake gh
    a = p.parse_args(argv)
    repo = Repo(a.repo, remote=a.remote, gh=a.gh, out=out)
    try:
        if a.push:
            tag = check_candidate(repo, a.commit, a.key, signed=True)
            push(repo, tag, a.commit, a.key)
            out.write("PUSHED %s -> %s\n" % (tag, a.commit))
            return 0
        tag = check_candidate(repo, a.commit, a.key)
        if not a.sign:
            out.write("DRY RUN: every check passed for %s -> %s. Nothing was signed or pushed. "
                      "Run again with --sign in your own terminal.\n" % (tag, a.commit))
            return 0
        sign(repo, tag, a.commit, a.key)
        out.write("SIGNED %s -> %s locally. Nothing was pushed. Run again with --push.\n"
                  % (tag, a.commit))
        return 0
    except TagError as e:
        out.write("REFUSED: %s\n" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
