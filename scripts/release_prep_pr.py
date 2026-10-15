#!/usr/bin/env python3
"""Prepare a release-prep pull request from recorded evidence, offline.

    python3 -S scripts/release_prep_pr.py draft --version X.Y.Z[-rc.N] --date YYYY-MM-DD \\
        --since vPREVIOUS --evidence DIR
    #   review the diff, commit it, run scripts/ci-strict.py --commit on that commit
    python3 -S scripts/release_prep_pr.py body --evidence DIR [--ci-result RESULT.json]

draft runs in a checkout with no tracked changes. It records, through
scripts/evidence_capture.py, what changed since the previous release (commits,
migrations, the API contract, go.mod, specs), then makes the mechanical edits
of Stage 1 in docs/runbooks/RELEASING.md:

  - VERSION in packaging/version.env (CODENAME is kept);
  - the README phrase "current version is `X`";
  - every "Applies to:** OpenWatch v<previous> (<codename>)" banner;
  - CHANGELOG.md: the [Unreleased] section becomes "[X] <codename> (<date>)",
    under a fresh, empty [Unreleased].

The release notes themselves are human prose: draft refuses an empty
[Unreleased] rather than invent them. It never commits, pushes or tags.

body runs on the committed prep commit. It re-checks that the three version
sources agree and runs the commit's own packaging/check-tag-version.sh, then
writes PR-BODY.md from the recorded captures. A ci-strict result counts only
when `ci-strict.py --commit` produced it for this exact commit, testing the
commit's files alone; its outcome and every gate or test that did
not run are copied, never summarized away. The release gates are listed as not
yet evaluated, because no tag exists at prep time. Every human field (the
date, the notes review, each Stage 1 refresh the evidence calls for) is blank.

Spec: release-prep-pr.
"""

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

_here = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("evidence_capture", _here / "evidence_capture.py")
ec = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ec)

READ_TIMEOUT = 120

_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-rc\.\d+)?$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
README_PHRASE = re.compile(r"(current version is `)([^`]+)(`)")
# One reading per question a release-prep review asks. Each is a git command
# over the range since the previous release, captured raw.
READINGS = [
    ("commits", ["log", "--no-merges", "--format=%H%x09%s"], None),
    ("migrations", ["diff", "--name-status"], "internal/db/migrations"),
    ("api-contract", ["diff", "--stat"], "api/openapi.yaml"),
    ("go-mod", ["diff"], "go.mod"),
    ("specs", ["diff", "--name-status"], "specs"),
    ("install-docs", ["diff", "--name-status"], "docs/guides/INSTALLATION.md"),
]


class PrepPRError(Exception):
    pass


def check_timeouts():
    if not isinstance(READ_TIMEOUT, (int, float)) or not READ_TIMEOUT > 0:
        raise PrepPRError("READ_TIMEOUT is not an explicit positive timeout")


def git(repo, *args):
    p = subprocess.run(["git", "-C", repo] + list(args), capture_output=True, text=True)
    if p.returncode != 0:
        raise PrepPRError("git %s failed: %s" % (" ".join(args), p.stderr.strip()))
    return p.stdout


def read(repo, rel):
    with open(os.path.join(repo, rel), encoding="utf-8") as f:
        return f.read()


def write(repo, rel, text):
    with open(os.path.join(repo, rel), "w", encoding="utf-8") as f:
        f.write(text)


def env_value(text, key):
    found = re.findall(r'(?m)^%s="([^"]*)"$' % key, text)
    if len(found) != 1:
        raise PrepPRError("packaging/version.env sets %s %d times, not once" % (key, len(found)))
    return found[0]


def readme_version(text):
    flat = " ".join(text.replace("\n>", " ").split())
    found = README_PHRASE.findall(flat)
    if len(found) != 1:
        raise PrepPRError("README.md has %d \"current version is `X`\" phrases, not one" %
                          len(found))
    return found[0][1]


def changelog_latest(text):
    for m in re.finditer(r"(?m)^## \[([^\]]+)\]", text):
        if m.group(1) != "Unreleased":
            return m.group(1)
    return None


def agreement(repo, texts=None):
    """The three sources the hygiene test and release_tag.py require to agree.

    texts maps a path to proposed contents; a path not in it is read from disk."""
    texts = texts or {}

    def get(rel):
        return texts[rel] if rel in texts else read(repo, rel)
    return {"version.env": env_value(get("packaging/version.env"), "VERSION"),
            "README.md": readme_version(get("README.md")),
            "CHANGELOG.md": changelog_latest(get("CHANGELOG.md"))}


def stamp_changelog(text, version, codename, date):
    """Rename [Unreleased] to the release; open a fresh empty [Unreleased] above it."""
    heads = list(re.finditer(r"(?m)^## \[([^\]]+)\][^\n]*\n", text))
    unrel = [h for h in heads if h.group(1) == "Unreleased"]
    if len(unrel) != 1:
        raise PrepPRError("CHANGELOG.md has %d [Unreleased] headings, not one" % len(unrel))
    start = unrel[0].end()
    later = [h for h in heads if h.start() > unrel[0].start()]
    end = later[0].start() if later else len(text)
    if any(h.group(1) == version for h in heads):
        raise PrepPRError("CHANGELOG.md already has a [%s] section" % version)
    notes = text[start:end].strip("\n")
    if not notes.strip():
        raise PrepPRError("CHANGELOG.md's [Unreleased] section is empty. The release notes are "
                          "written by a person; write them under [Unreleased] first")
    return (text[:unrel[0].start()] + "## [Unreleased]\n\n" +
            "## [%s] %s (%s)\n\n%s\n\n" % (version, codename, date, notes) + text[end:])


def tracked_md(repo):
    return [p for p in git(repo, "ls-files", "-z", "--", "*.md").split("\0") if p]


def draft(a):
    repo = os.path.abspath(a.repo)
    if not _VERSION.match(a.version or ""):
        raise PrepPRError("--version must be X.Y.Z or X.Y.Z-rc.N, without a leading v")
    if not _DATE.match(a.date or ""):
        raise PrepPRError("--date must be an ISO date, YYYY-MM-DD")
    try:
        datetime.date.fromisoformat(a.date)
    except ValueError:
        raise PrepPRError("--date %s is not a calendar date" % a.date)
    if git(repo, "status", "--porcelain", "--untracked-files=no").strip():
        raise PrepPRError("the checkout has tracked changes; draft needs a clean commit")
    base = git(repo, "rev-parse", "HEAD").strip()
    tag = "v" + a.version
    ec.check_candidate(tag, base)
    if not re.match(r"^v\d+\.\d+\.\d+(?:-rc\.\d+)?$", a.since or ""):
        raise PrepPRError("--since must name the previous release tag, such as v0.8.4")
    since = git(repo, "rev-parse", "--verify", "-q", a.since + "^{commit}").strip()
    if subprocess.run(["git", "-C", repo, "merge-base", "--is-ancestor", since, base]).returncode:
        raise PrepPRError("%s is not an ancestor of HEAD" % a.since)
    before = agreement(repo)
    previous = before["version.env"]
    if len(set(before.values())) != 1:
        raise PrepPRError("the version sources disagree before any edit: %s" % before)
    if previous == a.version:
        raise PrepPRError("packaging/version.env already says %s" % a.version)
    codename = env_value(read(repo, "packaging/version.env"), "CODENAME")
    out = os.path.join(os.path.abspath(a.evidence), "prep-pr")
    if os.path.lexists(os.path.join(out, "draft.json")):
        raise PrepPRError("%s already holds a draft; a draft is never overwritten" % out)
    os.makedirs(out, mode=0o700, exist_ok=True)
    # Compute every edit before writing any, so a refusal changes nothing.
    edits = {}
    # The assignment line itself, never a comment or another line that quotes it.
    env, n = re.subn(r'(?m)^VERSION="%s"$' % re.escape(previous), 'VERSION="%s"' % a.version,
                     read(repo, "packaging/version.env"))
    if n != 1:
        raise PrepPRError("packaging/version.env's VERSION assignment could not be updated")
    edits["packaging/version.env"] = env
    readme = read(repo, "README.md")
    # The phrase wraps inside a blockquote, at any of its word gaps.
    gap = r"(?:\s|>)+"
    new_readme, n = re.subn(r"(current%sversion%sis%s`)%s(`)" % (gap, gap, gap,
                                                                re.escape(previous)),
                            r"\g<1>%s\g<2>" % a.version, readme)
    if n != 1:
        raise PrepPRError("README.md's version phrase could not be updated in place")
    edits["README.md"] = new_readme
    edits["CHANGELOG.md"] = stamp_changelog(read(repo, "CHANGELOG.md"), a.version, codename,
                                            a.date)
    banner_old = "Applies to:** OpenWatch v%s (%s)" % (previous, codename)
    banner_new = "Applies to:** OpenWatch v%s (%s)" % (a.version, codename)
    banners = []
    for rel in tracked_md(repo):
        if rel in edits:
            continue
        text = read(repo, rel)
        if banner_old in text:
            edits[rel] = text.replace(banner_old, banner_new)
            banners.append(rel)
    # Every proposed content is checked before any file or capture is written.
    proposed = agreement(repo, edits)
    if set(proposed.values()) != {a.version}:
        raise PrepPRError("the proposed edits would leave the sources saying %s; nothing was "
                          "edited" % proposed)
    # Readings first: they describe the base commit, before any edit.
    caps = []
    for name, args, path in READINGS:
        argv = ["git", "-C", repo] + args + ["%s..%s" % (since, base)]
        if path:
            argv += ["--", path]
        rec = ec.capture(argv, out, "reading-" + name, tag, base, timeout=READ_TIMEOUT,
                         purpose="release-prep reading %s since %s" % (name, a.since))
        if rec["exit"]["code"] != 0:
            raise PrepPRError("the %s reading failed (%s); its raw output is in %s. Nothing "
                              "was edited." % (name, ec._exit_text(rec["exit"]).strip(),
                                               rec["path"]))
        caps.append(name)
    record = {"version": a.version, "tag": tag, "codename": codename, "date": a.date,
              "previous": previous, "since": a.since, "since_commit": since, "base": base,
              "readings": caps, "banners": sorted(banners),
              "edited": {rel: hashlib.sha256(text.encode()).hexdigest()
                         for rel, text in sorted(edits.items())}}
    apply_edits(repo, edits, a.version, os.path.join(out, "draft.json"),
                (json.dumps(record, indent=1, sort_keys=True) + "\n").encode())
    return ("Drafted %s (%s) over %s. Edited %d files: version.env, README, CHANGELOG and %d "
            "banners. Nothing is committed.\nReview `git diff`, commit it, run "
            "scripts/ci-strict.py --commit on that commit, then:\n    python3 -S scripts/"
            "release_prep_pr.py body --evidence %s --ci-result <run>/result.json" % (
                tag, codename, a.since, len(edits), len(banners), a.evidence))


def apply_edits(repo, edits, version, record_path, record):
    """Write every edit and the draft record as one transaction.

    The record is written to a .partial file and renamed into place, so it only
    ever appears complete. On any failure every edited file gets its original
    bytes back, and the record paths this transaction created are removed; a
    file that existed before is never touched, because its presence refuses the
    transaction before anything is written."""
    tmp = record_path + ".partial"
    for p in (record_path, tmp):
        if os.path.lexists(p):
            raise PrepPRError("%s already exists; move it aside, then draft again" % p)
    originals = {}
    for rel in edits:
        with open(os.path.join(repo, rel), "rb") as f:
            originals[rel] = f.read()
    try:
        for rel, text in sorted(edits.items()):
            write(repo, rel, text)
        after = agreement(repo)
        if set(after.values()) != {version}:
            raise PrepPRError("after the edits the sources say %s" % after)
        ec._write_new(tmp, record)
        os.rename(tmp, record_path)
    except BaseException:
        for rel, raw in originals.items():
            with open(os.path.join(repo, rel), "wb") as f:
                f.write(raw)
        for p in (tmp, record_path):
            if os.path.lexists(p):
                os.unlink(p)
        raise


def _stdout(out, name):
    with open(os.path.join(out, "reading-" + name, "stdout"), encoding="utf-8",
              errors="replace") as f:
        return f.read()


_ci_spec = importlib.util.spec_from_file_location("ci_strict", _here / "ci-strict.py")
ci_strict = importlib.util.module_from_spec(_ci_spec)
_ci_spec.loader.exec_module(ci_strict)


def _when(v):
    try:
        return bool(v) and datetime.datetime.fromisoformat(v) is not None
    except (TypeError, ValueError):
        return False


def check_ci_result(r):
    """The problems with a ci-strict result.json's structure, or [] when well formed."""
    p = []
    if not isinstance(r, dict):
        return ["it is not a JSON object"]
    if not isinstance(r.get("id"), str) or not r["id"]:
        p.append("no invocation id")
    if not re.match(r"^[0-9a-f]{40}$", str(r.get("commit"))):
        p.append("commit is not a 40-character commit id")
    if r.get("mode", "development") == "commit":
        if not re.match(r"^[0-9a-f]{40}$", str(r.get("tree"))):
            p.append("tree is not a 40-character git tree id")
    elif not re.match(r"^[0-9a-f]{64}$", str(r.get("tree"))):
        p.append("tree is not a 64-character digest")
    if not _when(r.get("started")):
        p.append("started is not a timestamp")
    if not _when(r.get("finished")):
        p.append("finished is empty or not a timestamp: the run did not finish")
    if type(r.get("exit")) is not int or ci_strict.VERDICTS.get(r["exit"]) != r.get("verdict"):
        p.append("verdict %r does not match exit %r" % (r.get("verdict"), r.get("exit")))
    t = r.get("tests")
    if not isinstance(t, dict) or type(t.get("passed")) is not int or \
            type(t.get("failed")) is not int:
        p.append("tests lacks passed and failed counts")
    else:
        for k in ("not_run", "unexpected_not_run"):
            v = t.get(k, {})
            if not isinstance(v, dict) or not all(type(n) is int for n in v.values()):
                p.append("tests.%s is not a map of counts" % k)
    g = r.get("gates")
    if not isinstance(g, list) or not all(isinstance(x, dict) and isinstance(x.get("gate"), str)
                                          and isinstance(x.get("outcome"), str) for x in g):
        p.append("gates is not a list of named outcomes")
    if not isinstance(r.get("accepted_gaps", []), list):
        p.append("accepted_gaps is not a list")
    return p


def ci_section(path, repo, head):
    """Lines for the local CI result: counted only for a commit-mode result for
    this exact commit, which tested its committed files alone (bugs/OW-124).
    A development-mode result tested working-tree changes as well, so it is
    not evidence about the commit and is not counted."""
    if not path:
        return ["- **No local CI result was supplied.** Hosted checks on this head are the only "
                "test evidence."], "not supplied"
    with open(path, "rb") as f:
        raw = f.read()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        r = json.loads(raw)
    except ValueError as e:
        raise PrepPRError("--ci-result %s is not JSON: %s" % (path, e))
    problems = check_ci_result(r)
    if problems:
        raise PrepPRError("--ci-result %s is not a finished, well-formed ci-strict result: %s" % (
            path, "; ".join(problems)))
    if r["commit"] != head:
        return ["- **A local CI result for another commit was supplied and is not counted:** "
                "`%s` (sha256 `%s`) ran on `%s`, not this head `%s`." % (
                    path, digest, r["commit"][:12], head[:12])], "another commit"
    if r.get("mode", "development") != "commit":
        return ["- **A development-mode local CI result was supplied and is not counted:** "
                "`%s` (sha256 `%s`) tested this head plus working-tree changes, not the commit "
                "alone. Run `scripts/ci-strict.py --commit` on this head." % (path, digest)
                ], "development result"
    rc = subprocess.run(["git", "-C", repo, "rev-parse", head + "^{tree}"],
                        capture_output=True, text=True)
    tree = rc.stdout.strip()
    if rc.returncode != 0 or r["tree"] != tree:
        return ["- **A local CI result for this commit but another tree was supplied and is not "
                "counted:** `%s` (sha256 `%s`) records tree `%s`; this commit's is `%s`." % (
                    path, digest, r["tree"][:12], tree[:12])], "another tree"
    t = r.get("tests") or {}
    lines = ["- Local `scripts/ci-strict.py --commit` on this head (its committed files only): "
             "verdict **%s**, exit %s, finished %s (`%s`, sha256 `%s`)." % (
                 r["verdict"], r["exit"], r["finished"], path, digest),
             "  - Tests: %s passed, %s failed." % (t.get("passed"), t.get("failed"))]
    for reason, n in sorted((t.get("not_run") or {}).items()):
        lines.append("  - Not run (%d): %s" % (n, reason))
    for reason, n in sorted((t.get("unexpected_not_run") or {}).items()):
        lines.append("  - **Not run, unexpected** (%d): %s" % (n, reason))
    for g in r.get("gates") or []:
        if g.get("outcome") != "passed":
            lines.append("  - Gate `%s`: **%s**%s" % (g.get("gate"), g.get("outcome"),
                                                      " (%s)" % g["reason"] if g.get("reason")
                                                      else ""))
    for gap in r.get("accepted_gaps") or []:
        lines.append("  - Accepted gap: %s" % gap)
    return lines, r.get("verdict")


def body(a):
    repo = os.path.abspath(a.repo)
    out = os.path.join(os.path.abspath(a.evidence), "prep-pr")
    try:
        with open(os.path.join(out, "draft.json")) as f:
            d = json.load(f)
    except OSError:
        raise PrepPRError("no draft in %s; run draft first" % out)
    if git(repo, "status", "--porcelain", "--untracked-files=no").strip():
        raise PrepPRError("the checkout has tracked changes; commit the prep first")
    head = git(repo, "rev-parse", "HEAD").strip()
    if head == d["base"] or subprocess.run(
            ["git", "-C", repo, "merge-base", "--is-ancestor", d["base"], head]).returncode:
        raise PrepPRError("HEAD must be the committed prep, a descendant of the draft's base %s"
                          % d["base"][:12])
    caps = {}
    for name in d["readings"]:
        caps[name] = ec.verify_capture(os.path.join(out, "reading-" + name), tag=d["tag"],
                                       commit=d["base"])
    # The supplied CI result is judged before any capture is written.
    ci_lines, ci_state = ci_section(a.ci_result, repo, head)
    now = agreement(repo)
    if set(now.values()) != {d["version"]}:
        raise PrepPRError("at HEAD the version sources say %s, not %s" % (now, d["version"]))
    check = ec.capture(["env", "RELEASE_REF=" + d["tag"], "bash",
                        os.path.join(repo, "packaging", "check-tag-version.sh")],
                       out, "check-tag-version-%s" % head[:12], d["tag"], head,
                       timeout=READ_TIMEOUT, purpose="the commit's own tag-version check")
    if check["exit"]["code"] != 0:
        raise PrepPRError("the commit's check-tag-version.sh refuses %s; see %s" % (
            d["tag"], check["path"]))
    commits = [l.split("\t", 1) for l in _stdout(out, "commits").splitlines() if l.strip()]
    migrations = [l.split("\t")[-1] for l in _stdout(out, "migrations").splitlines()
                  if l.startswith("A\t")]
    api = _stdout(out, "api-contract").strip()
    gomod = [l for l in _stdout(out, "go-mod").splitlines()
             if re.match(r"^[-+](go |toolchain |\s*github\.com/Hanalyx/kensa )", l)]
    specs = [l for l in _stdout(out, "specs").splitlines() if l.strip()]
    install = _stdout(out, "install-docs").strip()
    with open(os.path.join(repo, "release", "gates.toml"), "rb") as f:
        gates = [g for g in tomllib.load(f).get("gate", [])]
    # What the person changed after the draft: drafted files that no longer
    # hold the drafted bytes, and files the draft never touched.
    later = []
    for rel, digest in sorted(d["edited"].items()):
        p = subprocess.run(["git", "-C", repo, "show", "%s:%s" % (head, rel)], capture_output=True)
        if p.returncode != 0 or hashlib.sha256(p.stdout).hexdigest() != digest:
            later.append("`%s` (drafted, then edited)" % rel)
    for rel in sorted(set(git(repo, "diff", "--name-only", d["base"], head).split()) -
                      set(d["edited"])):
        later.append("`%s` (not part of the draft)" % rel)

    def cite(name):
        return "`reading-%s` (stdout sha256 `%s`)" % (
            name, caps[name]["streams"]["stdout"]["sha256"][:16])

    doc = ["## Summary", "",
           "Release prep for **%s %s**, proposed for **%s**. The date is a proposal, not "
           "authorization to tag. Nothing is tagged or published by this PR." % (
               d["tag"], d["codename"], d["date"]), "",
           "This PR changes only:",
           "- `packaging/version.env`: `VERSION=\"%s\"` (was %s); `CODENAME` unchanged." % (
               d["version"], d["previous"]),
           "- The README version phrase, and the \"Applies to\" banner in %d tracked documents. "
           "\"Last updated\" dates are left alone." % len(d["banners"]),
           "- `CHANGELOG.md`: the [Unreleased] notes become `[%s] %s (%s)`, under a fresh empty "
           "[Unreleased]." % (d["version"], d["codename"], d["date"]), "",
           "Prepared by `scripts/release_prep_pr.py` from the captures below. It records no "
           "verdict.", "",
           "## What changed since %s (recorded)" % d["since"], "",
           "Base `%s`, range `%s..%s`. The raw captures are authoritative." % (
               d["base"][:12], d["since_commit"][:12], d["base"][:12]), "",
           "| Reading | Finding | Evidence |", "|---|---|---|",
           "| Commits | %d | %s |" % (len(commits), cite("commits")),
           "| Migrations added | %s | %s |" % (", ".join("`%s`" % os.path.basename(m)
                                                      for m in migrations) or "none",
                                            cite("migrations")),
           "| API contract | %s | %s |" % ("changed" if api else "unchanged",
                                          cite("api-contract")),
           "| go.mod: Go, toolchain, Kensa | %s | %s |" % (
               "; ".join("`%s`" % l for l in gomod) or "unchanged", cite("go-mod")),
           "| Specs | %d changed | %s |" % (len(specs), cite("specs")),
           "| Installation guide | %s | %s |" % ("changed" if install else "unchanged",
                                                cite("install-docs")), ""]
    doc += ["Commits since %s, from the capture:" % d["since"], ""]
    doc += ["- `%s` %s" % (c[0][:8], c[1] if len(c) > 1 else "") for c in commits] or ["- none"]
    doc += ["", "## Changes after the draft", ""]
    doc += (["The draft's own edits are mechanical. These were changed by hand after it, and "
             "need a reviewer's eye:", ""] + ["- %s" % l for l in later]) if later else \
        ["None: every changed file holds exactly what the draft wrote."]
    doc += ["", "## Validation", ""] + ci_lines + [
        "- The commit's own `packaging/check-tag-version.sh` accepts `%s` (capture `%s`)." % (
            d["tag"], os.path.basename(check["path"])),
        "- Hosted checks: see the latest run on this head.", "",
        "**Not yet evaluated.** No tag exists at prep time, so no release gate can be evaluated. "
        "`release/gates.toml` declares %d:" % len(gates), ""]
    doc += ["- %s, %s%s" % (g.get("id"), g.get("title"),
                            " (human)" if g.get("human_required") else "") for g in gates]
    doc += ["", "## For the release captain", "",
            "Left blank on purpose. Only a person fills these.", "",
            "- Release notes read and accurate: ______",
            "- Proposed date %s accepted: ______" % d["date"]]
    if migrations:
        doc.append("- Migration notes written for %s: ______" % ", ".join(
            os.path.basename(m) for m in migrations))
    if api:
        doc.append("- API documentation refreshed for the contract change: ______")
    if install:
        doc.append("- Installation guide change checked: ______")
    if gomod:
        doc.append("- Toolchain or Kensa change described in the notes: ______")
    doc += ["- Reviewed by: ______", ""]
    path = os.path.join(out, "PR-BODY-%s.md" % head[:12])
    if os.path.lexists(path):
        raise PrepPRError("%s already exists; a body is never overwritten" % path)
    ec._write_new(path, "\n".join(doc).encode())
    return "PR body written: %s (local CI: %s)" % (path, ci_state)


def main(argv=None, out=sys.stdout):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="step")
    s = sub.add_parser("draft")
    s.add_argument("--version", required=True)
    s.add_argument("--date", required=True, help="the proposed publication date")
    s.add_argument("--since", required=True, help="the previous release tag")
    s.add_argument("--evidence", required=True)
    s.add_argument("--repo", default=".", help=argparse.SUPPRESS)
    s = sub.add_parser("body")
    s.add_argument("--evidence", required=True)
    s.add_argument("--ci-result", help="scripts/ci-strict.py's result.json for this commit")
    s.add_argument("--repo", default=".", help=argparse.SUPPRESS)
    a = p.parse_args(argv)
    if a.step is None:
        p.print_help(sys.stderr)
        return 2
    try:
        check_timeouts()
        out.write((draft(a) if a.step == "draft" else body(a)) + "\n")
        return 0
    except (PrepPRError, ec.CaptureError) as e:
        out.write("release_prep_pr: %s\n" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
