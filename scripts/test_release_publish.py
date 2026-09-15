#!/usr/bin/env python3
"""Tests for the draft-to-publication step.

    python3 -S scripts/test_release_publish.py

The publish script does one thing to GitHub, flip `draft` to false, and only
after every precondition holds. These tests drive it with the evaluator's
GitHub access replaced by an in-memory release, and check what it refused,
what it flipped, and what it reported when the release changed under it.
No network. Spec: release-ci-gates C-14 / AC-20.
"""

import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path

_here = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("release_publish", _here / "release-publish.py")
rp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rp)
rs = rp.rs

_tspec = importlib.util.spec_from_file_location("test_release_status", _here / "test_release_status.py")
ts = importlib.util.module_from_spec(_tspec)
_tspec.loader.exec_module(ts)

GATES = {"gate": [{"id": "X1", "title": "a gate", "evidence": "fake"}]}


class Scenario:
    """One publish attempt with a scripted release and a scripted verdict."""

    def __init__(self, draft=True, verdict_ok=True, mutate_before_flip=None,
                 mutate_after_flip=None):
        self.release, self.blobs = ts.draft_fixture(draft=draft)
        self.gh = ts.FakeGH([self.release], self.blobs)
        self.reads = 0
        self.mutate_before_flip = mutate_before_flip
        self.mutate_after_flip = mutate_after_flip
        self.verdict_ok = verdict_ok
        self.out = io.StringIO()

    def __enter__(self):
        self._saved = (rs.sh, rs.sh_bytes, rs.evaluate, rs.tag_commit, rs.release_info)
        rs.sh, rs.sh_bytes = self.gh.sh, self.gh.sh_bytes
        rs.tag_commit = lambda tag: "d" * 40
        status = rs.PASS if self.verdict_ok else rs.STALE
        rs.evaluate = lambda gates, tag, commit, workdir=None: iter(
            [("X1", "a gate", status, "scripted")])
        real_info = self._saved[4]

        def counted_info(tag):
            self.reads += 1
            # The second read is the pre-flip re-check; the third is post-flip.
            if self.reads == 2 and self.mutate_before_flip:
                self.mutate_before_flip(self.release, self.blobs)
            if self.reads == 3 and self.mutate_after_flip:
                self.mutate_after_flip(self.release, self.blobs)
            return real_info(tag)
        rs.release_info = counted_info
        return self

    def __exit__(self, *exc):
        rs.sh, rs.sh_bytes, rs.evaluate, rs.tag_commit, rs.release_info = self._saved

    def run(self, confirm):
        return rp.publish("v0.8.0", GATES, confirm, Path(tempfile.mkdtemp()),
                          out=lambda line="": self.out.write(str(line) + "\n"))

    @property
    def patched(self):
        return [c for c in self.gh.calls if "PATCH" in c]


class PublicationPreconditions(unittest.TestCase):
    def test_no_release_is_refused(self):
        with Scenario() as sc:
            sc.gh.releases.clear()
            self.assertEqual(sc.run(True), rp.REFUSED)
            self.assertEqual(sc.patched, [])
            self.assertIn("no release exists", sc.out.getvalue())

    def test_an_already_published_release_is_refused(self):
        with Scenario(draft=False) as sc:
            self.assertEqual(sc.run(True), rp.REFUSED)
            self.assertEqual(sc.patched, [])
            self.assertIn("already published", sc.out.getvalue())

    def test_no_go_is_refused_even_with_yes(self):
        with Scenario(verdict_ok=False) as sc:
            self.assertEqual(sc.run(True), rp.REFUSED)
            self.assertEqual(sc.patched, [])
            self.assertIn("NO-GO", sc.out.getvalue())

    def test_a_dry_run_flips_nothing(self):
        with Scenario() as sc:
            self.assertEqual(sc.run(False), 0)
            self.assertEqual(sc.patched, [])
            self.assertTrue(sc.release["draft"])
            self.assertIn("Dry run", sc.out.getvalue())


class PublicationFlipsOnlyTheDraftFlag(unittest.TestCase):
    def test_go_plus_yes_publishes_the_same_assets(self):
        with Scenario() as sc:
            ids_before = sorted(a["id"] for a in sc.release["assets"])
            self.assertEqual(sc.run(True), 0)
            self.assertEqual(len(sc.patched), 1)
            self.assertFalse(sc.release["draft"])
            self.assertEqual(sorted(a["id"] for a in sc.release["assets"]), ids_before)
            self.assertIn("unchanged from the verified draft", sc.out.getvalue())

    def test_the_request_carries_only_the_draft_flag(self):
        with Scenario() as sc:
            sc.run(True)
            (call,) = sc.patched
            fields = [call[i + 1] for i, a in enumerate(call) if a == "-F"]
            self.assertEqual(fields, ["draft=false"])
            for forbidden in ("upload", "delete", "assets", "tag_name", "target_commitish"):
                self.assertNotIn(forbidden, " ".join(call))

    def test_nothing_is_ever_uploaded_deleted_or_rebuilt(self):
        with Scenario() as sc:
            sc.run(True)
            for call in sc.gh.calls:
                joined = " ".join(str(a) for a in call)
                self.assertNotIn("DELETE", joined)
                self.assertNotIn("POST", joined)
                self.assertNotIn("workflow", joined)


class PublicationRefusesAChangedDraft(unittest.TestCase):
    def test_an_asset_replaced_between_go_and_the_flip_is_refused(self):
        def rebuild(release, blobs):
            a = next(x for x in release["assets"] if x["name"].endswith(".deb"))
            a["id"] = 555
            blobs[555] = b"deb-bytes-rebuilt"
        with Scenario(mutate_before_flip=rebuild) as sc:
            self.assertEqual(sc.run(True), rp.REFUSED)
            self.assertEqual(sc.patched, [])
            self.assertTrue(sc.release["draft"])
            self.assertIn("changed since it was verified", sc.out.getvalue())

    def test_a_manifest_changed_between_go_and_the_flip_is_refused(self):
        def reissue(release, blobs):
            sums = next(x for x in release["assets"] if x["name"] == "SHA256SUMS")
            blobs[sums["id"]] = b"0" * 64 + b"  openwatch-0.8.0-1.x86_64.rpm\n"
        with Scenario(mutate_before_flip=reissue) as sc:
            self.assertEqual(sc.run(True), rp.REFUSED)
            self.assertEqual(sc.patched, [])

    def test_a_change_after_the_flip_is_reported_as_changed_not_success(self):
        def rebuild(release, blobs):
            a = next(x for x in release["assets"] if x["name"].endswith(".rpm"))
            a["size"] += 1
        with Scenario(mutate_after_flip=rebuild) as sc:
            self.assertEqual(sc.run(True), rp.CHANGED)
            self.assertIn("PUBLISHED BUT CHANGED", sc.out.getvalue())
            self.assertIn("stale", sc.out.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2, argv=[sys.argv[0]])
