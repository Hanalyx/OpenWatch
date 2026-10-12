#!/usr/bin/env python3
"""Tests for the release-prep PR tool.

    python3 -S scripts/test_release_prep_pr.py

Each test builds a throwaway git repository in the repository's real formats:
packaging/version.env, a README whose version phrase wraps inside a
blockquote, a CHANGELOG with [Unreleased] notes, "Applies to" banners, and a
v0.8.4 tag followed by commits that add a migration and change the API
contract, go.mod, a spec and the installation guide. The repository's own
packaging/check-tag-version.sh and release/gates.toml are copied in, so the
version check and the gate list are the real ones. No network.

One class per criterion of spec release-prep-pr.
"""

import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_here = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("release_prep_pr", _here / "release_prep_pr.py")
pr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pr)
ec = pr.ec

GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}

README = """# OpenWatch

> **Project status.** The Go tree lives at the repo root. The current
> version is `0.8.4`, on the general-availability line that opened with `0.2.0`.
"""
CHANGELOG = """# Changelog

---

## [Unreleased]

### Added

- Release preparation scripts capture raw evidence for every step.

## [0.8.4] Eyrie (2026-10-10)

A security release.
"""
NOTES_LINE = "- Release preparation scripts capture raw evidence for every step."


def read_text(path):
    with open(path) as f:
        return f.read()


class Case(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="relprpr-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.repo = os.path.join(self.dir, "repo")
        self.evidence = os.path.join(self.dir, "evidence")
        self.out = os.path.join(self.evidence, "prep-pr")
        os.makedirs(self.repo)
        old_env = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(old_env)))
        os.environ.update(GIT_ENV)
        files = {
            "packaging/version.env": '# version\nVERSION="0.8.4"\nCODENAME="Eyrie"\n',
            "README.md": README,
            "CHANGELOG.md": CHANGELOG,
            "docs/guides/QUICKSTART.md": "# Quickstart\n\n**Last updated:** 2026-07-30 · "
                                         "**Applies to:** OpenWatch v0.8.4 (Eyrie)\n",
            "docs/runbooks/BACKUP.md": "# Backup\n\n**Applies to:** OpenWatch v0.8.4 (Eyrie)\n",
            "docs/guides/OLD.md": "# Old\n\n**Applies to:** OpenWatch v0.8.3 (Eyrie)\n",
            "internal/db/migrations/0001_initial.sql": "-- one\n",
            "api/openapi.yaml": "openapi: 3.0.0\n",
            "go.mod": "module x\n\ngo 1.26.5\n",
            "specs/a.spec.yaml": "spec: {id: a}\n",
            "docs/guides/INSTALLATION.md": "# Install\n",
        }
        for rel, text in files.items():
            self.put(rel, text)
        os.makedirs(os.path.join(self.repo, "release"))
        shutil.copy(_here.parent / "release" / "gates.toml", os.path.join(self.repo, "release"))
        shutil.copy(_here.parent / "packaging" / "check-tag-version.sh",
                    os.path.join(self.repo, "packaging"))
        self.git("init", "-q", "-b", "main")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "release 0.8.4")
        self.git("tag", "v0.8.4")
        self.put("internal/db/migrations/0002_more.sql", "-- two\n")
        self.put("api/openapi.yaml", "openapi: 3.0.0\npaths: {}\n")
        self.put("go.mod", "module x\n\ngo 1.26.9\n")
        self.put("specs/b.spec.yaml", "spec: {id: b}\n")
        self.put("docs/guides/INSTALLATION.md", "# Install\n\nRocky 10.\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "feat: work after 0.8.4 (#950)")
        self.base = self.git("rev-parse", "HEAD").strip()

    def put(self, rel, text):
        p = os.path.join(self.repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)

    def git(self, *args):
        return subprocess.run(["git", "-C", self.repo] + list(args), check=True,
                              capture_output=True, text=True).stdout

    def run_tool(self, *argv):
        out = io.StringIO()
        code = pr.main(list(argv) + ["--repo", self.repo], out=out)
        return code, out.getvalue()

    def draft(self, version="0.8.5", date="2026-10-20", since="v0.8.4"):
        return self.run_tool("draft", "--version", version, "--date", date, "--since", since,
                             "--evidence", self.evidence)

    def commit_prep(self):
        self.git("commit", "-q", "-am", "chore(release): prepare v0.8.5")
        return self.git("rev-parse", "HEAD").strip()

    def body(self, *extra):
        return self.run_tool("body", "--evidence", self.evidence, *extra)

    def the_body(self):
        names = [n for n in os.listdir(self.out) if n.startswith("PR-BODY-")]
        self.assertEqual(len(names), 1, names)
        return read_text(os.path.join(self.out, names[0]))

    def tree(self):
        """This checkout's tree identity, computed by ci-strict itself."""
        return pr.ci_strict.tree_identity(pr.ci_strict.Probe(repo=self.repo))[1]

    def ci_result(self, commit, **over):
        r = {"id": "0" * 32, "commit": commit, "tree": self.tree(),
             "started": "2026-10-11T15:17:20.375446+00:00",
             "finished": "2026-10-11T15:40:14.449628+00:00",
             "verdict": "incomplete", "exit": 3, "accepted_gaps": [],
             "tests": {"passed": 3801, "failed": 0,
                       "not_run": {"set OPENWATCH_LIVE_HOSTS to run live-host SSH tests": 1},
                       "unexpected_not_run": {}},
             "gates": [{"gate": "vet", "outcome": "passed"},
                       {"gate": "lint", "outcome": "not run", "reason": "golangci-lint missing"}]}
        r.update(over)
        p = os.path.join(self.dir, "result.json")
        with open(p, "w") as f:
            json.dump(r, f)
        return p

    def assert_untouched(self):
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=no"), "")
        self.assertEqual(self.git("rev-parse", "HEAD").strip(), self.base)


class DraftEdits(Case):
    """AC-01: draft makes exactly the Stage 1 edits, derived, and commits nothing."""

    def test_the_four_edits_and_nothing_else(self):
        code, out = self.draft()
        self.assertEqual(code, 0, out)
        changed = sorted(self.git("diff", "--name-only").split())
        self.assertEqual(changed, ["CHANGELOG.md", "README.md", "docs/guides/QUICKSTART.md",
                                   "docs/runbooks/BACKUP.md", "packaging/version.env"])
        env = read_text(os.path.join(self.repo, "packaging/version.env"))
        self.assertIn('VERSION="0.8.5"', env)
        self.assertIn('CODENAME="Eyrie"', env)
        self.assertIn("> version is `0.8.5`, on the general-availability line",
                      read_text(os.path.join(self.repo, "README.md")))
        for rel in ("docs/guides/QUICKSTART.md", "docs/runbooks/BACKUP.md"):
            self.assertIn("Applies to:** OpenWatch v0.8.5 (Eyrie)",
                          read_text(os.path.join(self.repo, rel)))
        self.assertIn("v0.8.3 (Eyrie)", read_text(os.path.join(self.repo, "docs/guides/OLD.md")))
        self.assertEqual(self.git("rev-parse", "HEAD").strip(), self.base, "draft committed")

    def test_the_changelog_section_holds_the_notes_under_a_fresh_unreleased(self):
        self.assertEqual(self.draft()[0], 0)
        log = read_text(os.path.join(self.repo, "CHANGELOG.md"))
        self.assertIn("## [Unreleased]\n\n## [0.8.5] Eyrie (2026-10-20)\n\n### Added\n\n" +
                      NOTES_LINE + "\n\n## [0.8.4] Eyrie (2026-10-10)", log)
        self.assertEqual(log.count("## [Unreleased]"), 1)
        self.assertEqual(set(pr.agreement(self.repo).values()), {"0.8.5"})

    def test_the_readings_are_captured_bound_and_the_draft_is_recorded(self):
        self.assertEqual(self.draft()[0], 0)
        d = json.loads(read_text(os.path.join(self.out, "draft.json")))
        self.assertEqual((d["tag"], d["base"], d["previous"], d["since"]),
                         ("v0.8.5", self.base, "0.8.4", "v0.8.4"))
        self.assertEqual(d["banners"], ["docs/guides/QUICKSTART.md", "docs/runbooks/BACKUP.md"])
        for rel, digest in d["edited"].items():
            with open(os.path.join(self.repo, rel), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest, rel)
        for name, _args, _path in pr.READINGS:
            rec = ec.verify_capture(os.path.join(self.out, "reading-" + name), tag="v0.8.5",
                                    commit=self.base)
            self.assertEqual(rec["invocation"]["timeout_seconds"], pr.READ_TIMEOUT)
            self.assertEqual(rec["exit"]["code"], 0, name)
        self.assertIn("A\tinternal/db/migrations/0002_more.sql",
                      read_text(os.path.join(self.out, "reading-migrations", "stdout")))

    def test_only_the_version_assignment_changes_not_a_comment_quoting_it(self):
        # The reproduction: a comment quoting the assignment, before it.
        self.put("packaging/version.env",
                 '# Bump with, for example: VERSION="0.8.4"\nVERSION="0.8.4"\nCODENAME="Eyrie"\n')
        self.git("commit", "-q", "-am", "comment quoting the assignment")
        self.base = self.git("rev-parse", "HEAD").strip()
        code, out = self.draft()
        self.assertEqual(code, 0, out)
        self.assertEqual(read_text(os.path.join(self.repo, "packaging/version.env")),
                         '# Bump with, for example: VERSION="0.8.4"\nVERSION="0.8.5"\n'
                         'CODENAME="Eyrie"\n')

    def test_a_release_candidate_suffix_is_carried_everywhere(self):
        code, out = self.draft(version="0.9.0-rc.1")
        self.assertEqual(code, 0, out)
        self.assertEqual(set(pr.agreement(self.repo).values()), {"0.9.0-rc.1"})
        self.assertIn("## [0.9.0-rc.1] Eyrie (2026-10-20)",
                      read_text(os.path.join(self.repo, "CHANGELOG.md")))


class DraftRefusals(Case):
    """AC-02: draft refuses, changing nothing, rather than guess."""

    def assert_refused(self, why, **kw):
        code, out = self.draft(**kw)
        self.assertEqual(code, 1, out)
        self.assertIn(why, out)
        self.assert_untouched()
        self.assertFalse(os.path.exists(os.path.join(self.out, "draft.json")))

    def test_an_empty_unreleased_section_is_refused(self):
        self.put("CHANGELOG.md", CHANGELOG.replace("### Added\n\n" + NOTES_LINE + "\n", ""))
        self.git("commit", "-q", "-am", "no notes")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.assert_refused("The release notes are written by a person")

    def test_malformed_inputs_are_refused(self):
        for kw, why in (({"version": "v0.8.5"}, "--version must be"),
                        ({"version": "0.8"}, "--version must be"),
                        ({"date": "20261020"}, "--date must be an ISO date"),
                        ({"date": "2026-02-30"}, "is not a calendar date"),
                        ({"since": "main"}, "--since must name the previous release tag"),
                        ({"since": "v9.9.9"}, "git rev-parse"),
                        ({"version": "0.8.4"}, "already says 0.8.4")):
            with self.subTest(kw=kw):
                self.assert_refused(why, **kw)

    def test_a_since_tag_that_is_not_an_ancestor_is_refused(self):
        self.git("checkout", "-q", "-b", "side", "v0.8.4^0")
        self.put("side.txt", "x\n")
        self.git("add", "side.txt")
        self.git("commit", "-q", "-m", "side")
        self.git("tag", "v0.8.9")
        self.git("checkout", "-q", "main")
        self.assert_refused("is not an ancestor of HEAD", since="v0.8.9")

    def test_a_proposal_that_would_disagree_is_refused_before_anything_is_written(self):
        real = pr.stamp_changelog
        pr.stamp_changelog = lambda text, *a: text  # a defect in one proposed edit
        self.addCleanup(setattr, pr, "stamp_changelog", real)
        code, out = self.draft()
        self.assertEqual(code, 1, out)
        self.assertIn("the proposed edits would leave the sources saying", out)
        self.assert_untouched()
        self.assertFalse([n for n in os.listdir(self.out) if n.startswith("reading-")],
                         "a reading was captured for a refused proposal")

    def originals(self):
        out = {}
        for rel in ("packaging/version.env", "README.md", "CHANGELOG.md",
                    "docs/guides/QUICKSTART.md", "docs/runbooks/BACKUP.md"):
            with open(os.path.join(self.repo, rel), "rb") as f:
                out[rel] = f.read()
        return out

    def assert_restored(self, originals):
        for rel, raw in originals.items():
            with open(os.path.join(self.repo, rel), "rb") as f:
                self.assertEqual(f.read(), raw, rel)
        self.assert_untouched()
        for n in ("draft.json", "draft.json.partial"):
            self.assertFalse(os.path.lexists(os.path.join(self.out, n)), n)

    def test_a_failure_while_writing_an_edit_restores_every_original_byte(self):
        originals = self.originals()
        calls = []
        real = pr.write

        def failing(repo, rel, text):
            calls.append(rel)
            if len(calls) == 3:
                raise OSError("disk full")
            real(repo, rel, text)
        pr.write = failing
        try:
            with self.assertRaises(OSError):
                self.draft()
        finally:
            pr.write = real
        self.assertEqual(len(calls), 3)
        self.assert_restored(originals)

    def test_a_record_failing_after_its_bytes_are_written_leaves_no_record(self):
        # The review's reproduction: the failure strikes the draft record only,
        # after part of it is on disk, not the captures written before it.
        originals = self.originals()
        real = pr.ec._write_new
        hit = []

        def half_then_fail(path, data):
            if os.path.basename(path).startswith("draft.json"):
                hit.append(path)
                real(path, data[:len(data) // 2])
                raise OSError("disk full")
            real(path, data)
        pr.ec._write_new = half_then_fail
        try:
            with self.assertRaises(OSError):
                self.draft()
        finally:
            pr.ec._write_new = real
        self.assertEqual(len(hit), 1, "the record write was never reached")
        self.assertTrue(os.path.isdir(os.path.join(self.out, "reading-commits")),
                        "the captures before it were written")
        self.assert_restored(originals)
        # A retry is not blocked by a leftover record. The readings are moved
        # aside first: a capture is never taken twice under one name.
        for n in os.listdir(self.out):
            os.rename(os.path.join(self.out, n), os.path.join(self.out, n + ".failed"))
        code, out = self.draft()
        self.assertEqual(code, 0, out)

    def test_a_failure_renaming_the_record_into_place_leaves_no_record(self):
        originals = self.originals()
        real = pr.os.rename

        def failing(src, dst):
            if os.path.basename(dst) == "draft.json":
                raise OSError("rename failed")
            real(src, dst)
        pr.os.rename = failing
        try:
            with self.assertRaises(OSError):
                self.draft()
        finally:
            pr.os.rename = real
        self.assert_restored(originals)

    def test_a_record_that_existed_before_is_never_removed(self):
        os.makedirs(self.out)
        for name in ("draft.json", "draft.json.partial"):
            with self.subTest(name=name):
                path = os.path.join(self.out, name)
                with open(path, "w") as f:
                    f.write("someone else's\n")
                with self.assertRaises(pr.PrepPRError):
                    pr.apply_edits(self.repo, {"README.md": "changed\n"}, "0.8.5",
                                   os.path.join(self.out, "draft.json"), b"{}")
                self.assertEqual(read_text(path), "someone else's\n")
                self.assertEqual(read_text(os.path.join(self.repo, "README.md")), README)
                os.unlink(path)

    def test_a_dirty_checkout_is_refused(self):
        self.put("README.md", README + "\nedited\n")
        code, out = self.draft()
        self.assertEqual(code, 1, out)
        self.assertIn("tracked changes", out)
        self.assertFalse(os.path.exists(self.evidence))

    def test_sources_that_already_disagree_are_refused(self):
        self.put("README.md", README.replace("`0.8.4`", "`0.8.3`"))
        self.git("commit", "-q", "-am", "drift")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.assert_refused("disagree before any edit")

    def test_an_existing_section_or_a_doubled_phrase_is_refused(self):
        for rel, text, why in (
                # Below the newest heading, so the sources still agree and the
                # section guard itself must refuse.
                ("CHANGELOG.md", CHANGELOG + "\n## [0.8.5] Eyrie (2026-10-01)\n\nx\n",
                 "already has a [0.8.5] section"),
                ("README.md", README + "\nThe current version is `0.8.4` too.\n",
                 "phrases, not one")):
            with self.subTest(rel=rel):
                self.git("reset", "-q", "--hard", "HEAD")
                self.put(rel, text)
                self.git("commit", "-q", "-am", "set up " + rel)
                self.base = self.git("rev-parse", "HEAD").strip()
                self.assert_refused(why)

    def test_a_second_draft_is_refused(self):
        self.assertEqual(self.draft()[0], 0)
        self.git("checkout", "-q", "--", ".")
        code, out = self.draft()
        self.assertEqual(code, 1, out)
        # The draft's own guard, not the capture library's refusal of a name.
        self.assertIn("already holds a draft; a draft is never overwritten", out)
        self.assert_untouched()


class BodyFromEvidence(Case):
    """AC-03: body is written from the recorded captures, with every human field blank."""

    def test_the_body_reports_the_recorded_findings(self):
        self.assertEqual(self.draft()[0], 0)
        head = self.commit_prep()
        code, out = self.body()
        self.assertEqual(code, 0, out)
        b = self.the_body()
        self.assertIn("Release prep for **v0.8.5 Eyrie**, proposed for **2026-10-20**", b)
        self.assertIn("not authorization to tag", b)
        self.assertIn("| Migrations added | `0002_more.sql` |", b)
        self.assertIn("| API contract | changed |", b)
        self.assertIn("`-go 1.26.5`; `+go 1.26.9`", b)
        self.assertIn("| Specs | 1 changed |", b)
        self.assertIn("| Installation guide | changed |", b)
        self.assertIn("feat: work after 0.8.4 (#950)", b)
        rec = ec.verify_capture(os.path.join(self.out, "reading-commits"), tag="v0.8.5",
                                commit=self.base)
        self.assertIn(rec["streams"]["stdout"]["sha256"][:16], b)
        check = os.path.join(self.out, "check-tag-version-" + head[:12])
        self.assertEqual(ec.verify_capture(check, tag="v0.8.5", commit=head)["exit"]["code"], 0)
        self.assertIn("matches VERSION=0.8.5", read_text(os.path.join(check, "stdout")))

    def test_every_human_field_is_blank_and_follows_the_evidence(self):
        self.assertEqual(self.draft()[0], 0)
        self.commit_prep()
        self.assertEqual(self.body()[0], 0)
        b = self.the_body()
        for line in ("- Release notes read and accurate: ______",
                     "- Proposed date 2026-10-20 accepted: ______",
                     "- Migration notes written for 0002_more.sql: ______",
                     "- API documentation refreshed for the contract change: ______",
                     "- Installation guide change checked: ______",
                     "- Toolchain or Kensa change described in the notes: ______",
                     "- Reviewed by: ______"):
            self.assertIn(line, b)
        self.assertIn("It records no verdict.", b)

    def test_every_gate_is_listed_as_not_yet_evaluated(self):
        import tomllib
        self.assertEqual(self.draft()[0], 0)
        self.commit_prep()
        self.assertEqual(self.body()[0], 0)
        b = self.the_body()
        with open(_here.parent / "release" / "gates.toml", "rb") as f:
            gates = tomllib.load(f)["gate"]
        self.assertIn("No tag exists at prep time, so no release gate can be evaluated. "
                      "`release/gates.toml` declares %d:" % len(gates), b)
        for g in gates:
            self.assertIn("- %s, %s" % (g["id"], g["title"]), b)
        self.assertIn("- D1, Tracked documentation reviewed against this candidate (human)", b)

    def test_changes_after_the_draft_are_named(self):
        self.assertEqual(self.draft()[0], 0)
        self.commit_prep()
        self.assertEqual(self.body()[0], 0)
        self.assertIn("None: every changed file holds exactly what the draft wrote.",
                      self.the_body())
        shutil.rmtree(self.out)
        self.git("reset", "-q", "--hard", self.base)
        self.assertEqual(self.draft()[0], 0)
        log = read_text(os.path.join(self.repo, "CHANGELOG.md"))
        self.put("CHANGELOG.md", log.replace(NOTES_LINE, NOTES_LINE + " Edited by hand."))
        self.put("docs/guides/EXTRA.md", "# Extra\n")
        self.git("add", "docs/guides/EXTRA.md")
        self.commit_prep()
        self.assertEqual(self.body()[0], 0)
        b = self.the_body()
        self.assertIn("- `CHANGELOG.md` (drafted, then edited)", b)
        self.assertIn("- `docs/guides/EXTRA.md` (not part of the draft)", b)


class LocalCIResult(Case):
    """AC-04: a local CI result counts only for this commit, and its gaps are copied."""

    def prepared(self):
        self.assertEqual(self.draft()[0], 0)
        return self.commit_prep()

    def test_a_result_for_this_commit_is_copied_with_every_gap(self):
        head = self.prepared()
        p = self.ci_result(head)
        code, out = self.body("--ci-result", p)
        self.assertEqual(code, 0, out)
        self.assertIn("local CI: incomplete", out)
        b = self.the_body()
        with open(p, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        self.assertIn("on this head and tree: verdict **incomplete**, exit 3, finished "
                      "2026-10-11T15:40:14.449628+00:00", b)
        self.assertIn(digest, b)
        self.assertIn("Tests: 3801 passed, 0 failed.", b)
        self.assertIn("Not run (1): set OPENWATCH_LIVE_HOSTS to run live-host SSH tests", b)
        self.assertIn("Gate `lint`: **not run** (golangci-lint missing)", b)
        self.assertNotIn("Gate `vet`", b)

    def test_unexpected_not_run_tests_and_accepted_gaps_are_kept(self):
        head = self.prepared()
        p = self.ci_result(head, accepted_gaps=["lint: no local binary"], tests={
            "passed": 1, "failed": 2, "not_run": {}, "unexpected_not_run": {"TestX skipped": 1}})
        self.assertEqual(self.body("--ci-result", p)[0], 0)
        b = self.the_body()
        self.assertIn("Tests: 1 passed, 2 failed.", b)
        self.assertIn("**Not run, unexpected** (1): TestX skipped", b)
        self.assertIn("Accepted gap: lint: no local binary", b)

    def test_a_result_for_another_commit_is_not_counted(self):
        self.prepared()
        p = self.ci_result(self.base, verdict="complete", exit=0)
        code, out = self.body("--ci-result", p)
        self.assertEqual(code, 0, out)
        b = self.the_body()
        self.assertIn("A local CI result for another commit was supplied and is not counted", b)
        self.assertNotIn("verdict **complete**", b)

    def test_no_result_is_stated(self):
        self.prepared()
        self.assertEqual(self.body()[0], 0)
        self.assertIn("**No local CI result was supplied.**", self.the_body())

    def test_the_reviewers_result_another_tree_and_unfinished_is_refused(self):
        # The reproduction: this commit, a different tree, an empty finished.
        head = self.prepared()
        p = self.ci_result(head, tree="f" * 64, finished="", verdict="complete", exit=0)
        code, out = self.body("--ci-result", p)
        self.assertEqual(code, 1, out)
        self.assertIn("is not a finished, well-formed ci-strict result", out)
        self.assertIn("the run did not finish", out)
        self.assertFalse([n for n in os.listdir(self.out) if n.startswith("PR-BODY-")])

    def test_a_finished_result_for_another_tree_is_not_counted(self):
        head = self.prepared()
        p = self.ci_result(head, tree="f" * 64, verdict="complete", exit=0)
        code, out = self.body("--ci-result", p)
        self.assertEqual(code, 0, out)
        self.assertIn("local CI: another tree", out)
        b = self.the_body()
        self.assertIn("for this commit but another tree was supplied and is not counted", b)
        self.assertNotIn("verdict **complete**", b)

    def test_untracked_files_since_the_run_change_the_tree(self):
        head = self.prepared()
        p = self.ci_result(head)
        self.put("scratch.txt", "appeared after the run\n")
        self.assertEqual(self.body("--ci-result", p)[0], 0)
        self.assertIn("another tree", self.the_body())

    def test_a_malformed_result_is_refused(self):
        head = self.prepared()
        for over, why in (({"verdict": "complete"}, "does not match exit 3"),
                          ({"commit": head[:12]}, "40-character commit"),
                          ({"tree": "abc"}, "64-character digest"),
                          ({"started": "yesterday"}, "started is not a timestamp"),
                          ({"id": ""}, "no invocation id"),
                          ({"tests": {"passed": "3801", "failed": 0}}, "passed and failed"),
                          ({"tests": {"passed": 1, "failed": 0, "not_run": {"x": "1"}}},
                           "tests.not_run is not a map of counts"),
                          ({"gates": [{"outcome": "passed"}]}, "list of named outcomes"),
                          ({"accepted_gaps": "none"}, "accepted_gaps is not a list")):
            with self.subTest(over=over):
                over = dict(over)
                code, out = self.body("--ci-result",
                                      self.ci_result(over.pop("commit", head), **over))
                self.assertEqual(code, 1, out)
                self.assertIn(why, out)
        self.assertFalse([n for n in os.listdir(self.out) if n.startswith("PR-BODY-")])

    def test_a_result_that_is_not_json_is_refused(self):
        self.prepared()
        p = os.path.join(self.dir, "result.json")
        with open(p, "w") as f:
            f.write("not json")
        code, out = self.body("--ci-result", p)
        self.assertEqual(code, 1, out)
        self.assertIn("is not JSON", out)
        self.assertFalse([n for n in os.listdir(self.out) if n.startswith("PR-BODY-")])


class BodyRefusals(Case):
    """AC-05: body refuses an unverified or inconsistent state, and never overwrites."""

    def assert_refused(self, why):
        code, out = self.body()
        self.assertEqual(code, 1, out)
        self.assertIn(why, out)
        if os.path.isdir(self.out):
            self.assertFalse([n for n in os.listdir(self.out) if n.startswith("PR-BODY-")])

    def test_without_a_draft(self):
        self.assert_refused("no draft")

    def test_before_the_prep_is_committed(self):
        self.assertEqual(self.draft()[0], 0)
        self.assert_refused("tracked changes")
        self.git("stash", "-q")
        self.assert_refused("must be the committed prep")

    def test_an_altered_reading(self):
        self.assertEqual(self.draft()[0], 0)
        self.commit_prep()
        p = os.path.join(self.out, "reading-migrations", "stdout")
        os.chmod(p, 0o600)
        with open(p, "w") as f:
            f.write("")
        code, out = self.body()
        self.assertEqual(code, 1, out)
        self.assertFalse([n for n in os.listdir(self.out) if n.startswith("PR-BODY-")])

    def test_a_version_changed_after_the_draft(self):
        self.assertEqual(self.draft()[0], 0)
        self.put("packaging/version.env", '# version\nVERSION="0.8.6"\nCODENAME="Eyrie"\n')
        self.commit_prep()
        self.assert_refused("not 0.8.5")

    def test_a_commit_whose_own_tag_check_refuses(self):
        self.assertEqual(self.draft()[0], 0)
        self.put("packaging/check-tag-version.sh", "#!/usr/bin/env bash\necho refused >&2\n"
                                                   "exit 1\n")
        self.commit_prep()
        self.assert_refused("check-tag-version.sh refuses v0.8.5")

    def test_a_body_is_never_overwritten(self):
        self.assertEqual(self.draft()[0], 0)
        self.commit_prep()
        self.assertEqual(self.body()[0], 0)
        before = self.the_body()
        code, out = self.body()
        self.assertEqual(code, 1, out)
        # The capture library refuses the second check-tag-version capture of
        # this head first; PR-BODY's own guard stays behind it as a backstop.
        self.assertIn("check-tag-version-", out)
        self.assertEqual(self.the_body(), before)


class PrepBoundaries(Case):
    """AC-06: an explicit timeout, and the tool never commits, pushes or tags."""

    def test_a_missing_timeout_is_refused_before_anything_runs(self):
        old = pr.READ_TIMEOUT
        pr.READ_TIMEOUT = 0
        try:
            code, out = self.draft()
        finally:
            pr.READ_TIMEOUT = old
        self.assertEqual(code, 1, out)
        self.assertIn("not an explicit positive timeout", out)
        self.assert_untouched()
        self.assertFalse(os.path.exists(self.evidence))

    def test_the_tool_never_commits_pushes_or_tags(self):
        import re
        src = read_text(_here / "release_prep_pr.py")
        calls = re.findall(r'git\(repo, ([^)]*)\)', src) + re.findall(r'\["git", "-C", repo\] \+ '
                                                                       r'([^\n]*)', src)
        self.assertTrue(calls)
        for c in calls:
            for verb in ('"commit"', '"push"', '"tag"', '"add"', '"reset"', '"checkout"',
                         '"stash"'):
                self.assertNotIn(verb, c, c)
        for name, args, _path in pr.READINGS:
            self.assertIn(args[0], ("log", "diff"), name)

    def test_a_full_flow_leaves_no_tag_and_no_new_commit(self):
        tags = self.git("tag")
        self.assertEqual(self.draft()[0], 0)
        self.assertEqual(self.git("tag"), tags)
        self.assertEqual(self.git("rev-parse", "HEAD").strip(), self.base)
        self.assertEqual(self.git("stash", "list"), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
