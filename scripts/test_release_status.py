#!/usr/bin/env python3
"""Tests for the release readiness checker.

    python3 scripts/test_release_status.py     (or: make release-status-test)

These cover the two behaviours the verdict actually rests on, because a guard
that has never been observed to fail is not known to work:

  staleness       evidence is tied to an artifact digest, so a candidate that
                  does not contain that artifact must not inherit it
  human_required  an agent can record that a container install succeeded; it
                  must not be able to sign off that something rendered
                  correctly on a screen

Standard library only, and no network: the checker's evidence gathering is
already separated from its judgement, so eval_attestation can be driven
directly with the inputs those functions would have returned.
"""

import importlib.util
import sys
import unittest
from pathlib import Path

# The script has a hyphen in its name, so it cannot be imported by name.
_path = Path(__file__).resolve().parent / "release-status.py"
_spec = importlib.util.spec_from_file_location("release_status", _path)
rs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rs)

GOOD_SHA = "a" * 64
OTHER_SHA = "b" * 64
DIGESTS = {GOOD_SHA: "openwatch-0.7.0-1.x86_64.rpm"}


def att(**kw):
    """An otherwise-valid attestation, overridden per test."""
    base = {
        "_file": "test.toml",
        "kind": "clean-install",
        "platform": "rhel9",
        "artifact_sha256": GOOD_SHA,
        "performed_by": "a.human",
        "performed_at": "2026-07-31",
    }
    base.update(kw)
    return base


class Staleness(unittest.TestCase):
    def test_matching_digest_passes(self):
        status, note = rs.eval_attestation(att(), DIGESTS, False)
        self.assertEqual(status, rs.PASS, note)

    def test_digest_absent_from_candidate_is_stale(self):
        """The core property: rebuilt bits do not inherit old evidence."""
        status, note = rs.eval_attestation(
            att(artifact_sha256=OTHER_SHA), DIGESTS, False)
        self.assertEqual(status, rs.STALE, note)
        self.assertIn("not in this candidate", note)

    def test_unreadable_checksums_fail_closed(self):
        """digests=None means the list could not be read.

        This must not pass. Treating "nothing to compare against" as "nothing
        wrong" would let every stale attestation through whenever the release
        lookup broke, which is exactly when nobody is looking.
        """
        status, note = rs.eval_attestation(att(), None, False)
        self.assertEqual(status, rs.ERROR, note)
        self.assertIn("unverifiable", note)

    def test_missing_digest_field_fails(self):
        a = att()
        del a["artifact_sha256"]
        status, _ = rs.eval_attestation(a, DIGESTS, False)
        self.assertEqual(status, rs.FAIL)


class HumanRequired(unittest.TestCase):
    def test_agent_cannot_satisfy_a_human_gate(self):
        status, note = rs.eval_attestation(
            att(performed_by="openwatch-agent"), DIGESTS, True)
        self.assertEqual(status, rs.FAIL, note)
        self.assertIn("requires a human observer", note)

    def test_any_agent_suffix_is_refused(self):
        """The rule is the -agent suffix, not one hardcoded name."""
        for who in ("kensa-agent", "some-other-agent"):
            with self.subTest(who=who):
                status, _ = rs.eval_attestation(
                    att(performed_by=who), DIGESTS, True)
                self.assertEqual(status, rs.FAIL)

    def test_human_satisfies_a_human_gate(self):
        status, note = rs.eval_attestation(att(), DIGESTS, True)
        self.assertEqual(status, rs.PASS, note)

    def test_agent_may_satisfy_a_non_human_gate(self):
        """A container job is equally non-human; install gates accept both."""
        status, note = rs.eval_attestation(
            att(performed_by="openwatch-agent"), DIGESTS, False)
        self.assertEqual(status, rs.PASS, note)

    def test_staleness_is_checked_even_for_a_human(self):
        """A human signature does not excuse evidence for the wrong bits."""
        status, _ = rs.eval_attestation(
            att(artifact_sha256=OTHER_SHA), DIGESTS, True)
        self.assertEqual(status, rs.STALE)


class ManifestIsLoadable(unittest.TestCase):
    """The shipped manifest must parse and reference only known evidence
    kinds, so a typo in gates.toml surfaces here rather than as a gate that
    silently never applies."""

    KINDS = {"github-check", "github-check-all", "release-asset",
             "signed-tag", "per-platform", "attestation"}

    def setUp(self):
        import tomllib
        with rs.GATES.open("rb") as fh:
            self.gates = tomllib.load(fh)

    def test_every_gate_has_a_known_evidence_kind(self):
        for g in self.gates["gate"]:
            with self.subTest(gate=g["id"]):
                self.assertIn(g.get("evidence"), self.KINDS)

    def test_gate_ids_are_unique(self):
        ids = [g["id"] for g in self.gates["gate"]]
        self.assertEqual(len(ids), len(set(ids)), "duplicate gate id")

    def test_per_platform_gates_declare_a_kind(self):
        for g in self.gates["gate"]:
            if g.get("evidence") in ("per-platform", "attestation"):
                with self.subTest(gate=g["id"]):
                    self.assertIn("kind", g)

    def test_shipped_attestations_parse(self):
        for a in rs.load_attestations():
            with self.subTest(f=a["_file"]):
                self.assertIn("kind", a)
                self.assertIn("artifact_sha256", a)


if __name__ == "__main__":
    unittest.main(verbosity=2, argv=[sys.argv[0]])
