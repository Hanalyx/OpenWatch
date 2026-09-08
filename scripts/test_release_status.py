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
import os
import re
import subprocess
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


class PendingIsNotFailure(unittest.TestCase):
    """A run that has not finished must not be reported as a failure.

    Found on the v0.7.1 tag: the release build was tagged while the main-branch
    Quality gate was still running, and the checker read the empty conclusion
    GitHub returns for an in-progress run as a non-success. It printed FAIL,
    which says the candidate is broken when it is merely early. That is the
    same class of error as rendering an unpopulated field as a fact.
    """

    def test_pending_is_its_own_status_and_still_blocks(self):
        # It must block, so nobody ships on an unfinished build, but it must
        # not accuse. Those are different claims.
        self.assertIn(rs.PENDING, rs.BAD)
        self.assertNotEqual(rs.PENDING, rs.FAIL)

    def test_a_finished_result_outranks_a_pending_one(self):
        # Re-runs produce several entries for one name. A completed success or
        # failure is what the tree is at; a stale queued entry is not.
        for finished in ("success", "failure"):
            with self.subTest(finished=finished):
                self.assertNotEqual(finished, rs.PENDING)


class PlatformCheckWiring(unittest.TestCase):
    """A platform proven by a CI job names a check run, and that name has to
    match a job the workflow actually produces. A typo here reads as MISSING
    forever, which looks like unfinished work rather than a broken manifest."""

    def setUp(self):
        import re
        import tomllib
        with rs.GATES.open("rb") as fh:
            self.gates = tomllib.load(fh)
        wf = (rs.REPO / ".github" / "workflows" / "package-smoke.yml").read_text()
        # The job's `name:` is a template over the matrix, so collect the
        # matrix values it expands to rather than parsing YAML semantics.
        self.distros = set(re.findall(r"distro:\s*'([^']+)'", wf))

    def test_a_check_never_covers_a_kind_the_job_does_not_assert(self):
        """The setup-install job installs and re-runs. It never touches the
        previous GA, so it must not be wired to the upgrade gate: that would
        report PASS for something nobody ran."""
        kinds = {g["kind"] for g in self.gates["gate"] if "kind" in g}
        for p in self.gates["platform"]:
            for kind, check in p.get("checks", {}).items():
                with self.subTest(platform=p["id"], kind=kind):
                    self.assertIn(kind, kinds, f"{kind!r} is not a gate kind")
                    if check.startswith("setup "):
                        self.assertIn(
                            kind, {"clean-install", "idempotence"},
                            f"the setup-install job cannot prove {kind!r}")
                    if check.startswith("upgrade-from-ga "):
                        self.assertEqual(
                            kind, "upgrade-from-ga",
                            f"the upgrade job cannot prove {kind!r}")

    def test_not_applicable_carries_a_reason(self):
        """N/A suppresses a blocking gate, so it has to say why in enough
        detail that a reader can challenge it."""
        for p in self.gates["platform"]:
            for kind, reason in p.get("not_applicable", {}).items():
                with self.subTest(platform=p["id"], kind=kind):
                    self.assertGreater(
                        len(reason), 60,
                        "an N/A reason must explain itself, not assert itself")
                    self.assertNotIn(kind, p.get("checks", {}),
                                     "a kind cannot be both N/A and proven")

    def test_platform_check_names_match_a_real_matrix_leg(self):
        for p in self.gates["platform"]:
            for check in p.get("checks", {}).values():
                with self.subTest(platform=p["id"], check=check):
                    # Names are "setup <distro>" from the setup-install job.
                    self.assertRegex(
                        check, r"^(setup|upgrade-from-ga) ",
                        f"{check!r} does not look like a matrix job name")
                    self.assertIn(
                        check.split(" ", 1)[1], self.distros,
                        f"{check!r} names a distro the matrix does not run")


# --------------------------------------------------------------- spec reader
#
# The specs are YAML, and this checker has no dependencies by design: see the
# header of release-status.py, which reads TOML with the stdlib tomllib rather
# than pulling in PyYAML. CI installs no Python packages, so an import of a
# third-party module here fails the Quality gates job on a machine that has it
# and passes on a developer's laptop that does not.
#
# Only two facts are needed, and the spec files have one controlled shape, so a
# structural reader is enough. It is deliberately NOT a YAML parser: it tracks
# indentation and the current top-level section instead of matching `id:`
# wherever it appears, because fixture cases inside a criterion carry their own
# ids and a regex over the whole file would collect those too.
#
#   spec:                     column 0, the ONE root mapping that counts
#     id: <spec id>           column 2, the ROOT id, exactly one per file
#     acceptance_criteria:    column 2, a section name
#       - id: AC-NN           column 4 dash item, only inside that section
#         inputs:
#           cases:
#             - id: whatever  column 10, a fixture case, NOT a criterion
#   metadata:                 column 0, a DIFFERENT root; everything under it
#     id: counterfeit         is outside spec: and must be ignored entirely
#
# The column-zero parent is tracked, not assumed. Keying on "a column-two id"
# alone accepted a document whose only such id sat under another root mapping,
# which is a spec id taken from a place that does not define one.

SPEC_ROOT_MAP = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):")
SPEC_ROOT_ID = re.compile(r"^  id:\s*(\S+)\s*$")
SPEC_SECTION = re.compile(r"^  ([A-Za-z_][A-Za-z0-9_]*):")
SPEC_LIST_ID = re.compile(r"^    - id:\s*(\S+)\s*$")


def _unquote(v):
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        return v[1:-1]
    return v


def read_one_spec(path):
    """Return (spec_id, [ac ids]) for one spec file, or raise ValueError."""
    spec_id, section, acs = None, None, []
    in_spec, spec_roots = False, 0
    for n, line in enumerate(path.read_text().split("\n"), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = SPEC_ROOT_MAP.match(line)
        if m:
            # A new column-zero mapping ends whatever came before it.
            in_spec = m.group(1) == "spec"
            section = None
            if in_spec:
                spec_roots += 1
            continue
        if not in_spec:
            continue
        m = SPEC_ROOT_ID.match(line)
        if m:
            if spec_id is not None:
                raise ValueError(f"{path}:{n}: a second root id")
            spec_id = _unquote(m.group(1))
            continue
        m = SPEC_SECTION.match(line)
        if m:
            section = m.group(1)
            continue
        m = SPEC_LIST_ID.match(line)
        if m and section == "acceptance_criteria":
            ac = _unquote(m.group(1))
            if ac in acs:
                raise ValueError(f"{path}:{n}: duplicate criterion {ac}")
            acs.append(ac)
    if spec_roots != 1:
        raise ValueError(f"{path}: expected exactly one spec: root, found {spec_roots}")
    if spec_id is None:
        raise ValueError(f"{path}: no readable spec.id")
    return spec_id, acs


def read_spec_registry(root=None):
    """Map every tracked spec id to the set of its criterion ids."""
    root = root or (rs.REPO / "specs")
    out = {}
    for f in sorted(root.rglob("*.spec.yaml")):
        spec_id, acs = read_one_spec(f)
        if spec_id in out:
            raise ValueError(f"duplicate spec id {spec_id!r} at {f}")
        out[spec_id] = set(acs)
    return out


TEST_SPEC_ANNOTATION = re.compile(r"^// @spec (\S+)", re.M)
TEST_AC_ANNOTATION = re.compile(r"^\s*// @ac (AC-\d+)", re.M)


def read_test_annotations():
    """Map each annotated spec id to the criterion ids some test claims."""
    out = {}
    for root in (rs.REPO / "frontend" / "tests", rs.REPO / "internal"):
        for f in root.rglob("*"):
            if f.suffix not in (".ts", ".tsx", ".go") or not f.is_file():
                continue
            text = f.read_text(errors="ignore")
            m = TEST_SPEC_ANNOTATION.search(text)
            if not m:
                continue
            out.setdefault(m.group(1), set()).update(TEST_AC_ANNOTATION.findall(text))
    return out


class SpecReaderIsStructural(unittest.TestCase):
    """The reader must key on structure, not on the word `id` appearing."""

    def _read(self, body):
        import tempfile, pathlib
        d = pathlib.Path(tempfile.mkdtemp())
        f = d / "x.spec.yaml"
        f.write_text(body)
        return f

    def test_a_fixture_case_id_is_not_a_criterion(self):
        f = self._read(
            "spec:\n  id: demo\n  acceptance_criteria:\n    - id: AC-01\n"
            "      inputs:\n        cases:\n          - id: not_a_criterion\n"
        )
        self.assertEqual(read_one_spec(f), ("demo", ["AC-01"]))

    def test_a_list_id_outside_the_criteria_section_is_ignored(self):
        f = self._read(
            "spec:\n  id: demo\n  constraints:\n    - id: C-01\n"
            "  acceptance_criteria:\n    - id: AC-01\n"
        )
        self.assertEqual(read_one_spec(f), ("demo", ["AC-01"]))

    def test_an_id_under_another_root_mapping_is_not_the_spec_id(self):
        """The counterfeit this reader used to accept.

        Every field is at the documented column, but none of it is under
        `spec:`. Keying on "a column-two id" alone took `counterfeit` as the
        spec id and AC-99 as its criterion.
        """
        f = self._read(
            "metadata:\n  id: counterfeit\n  acceptance_criteria:\n    - id: AC-99\n"
        )
        with self.assertRaisesRegex(ValueError, "exactly one spec: root"):
            read_one_spec(f)

    def test_content_after_another_root_mapping_leaves_the_spec(self):
        f = self._read(
            "spec:\n  id: real\n  acceptance_criteria:\n    - id: AC-01\n"
            "metadata:\n  acceptance_criteria:\n    - id: AC-99\n"
        )
        self.assertEqual(read_one_spec(f), ("real", ["AC-01"]))

    def test_two_spec_roots_each_with_an_id_are_an_error(self):
        f = self._read("spec:\n  id: a\nspec:\n  id: b\n")
        with self.assertRaisesRegex(ValueError, "a second root id"):
            read_one_spec(f)

    def test_two_spec_roots_are_an_error_even_with_one_id(self):
        f = self._read("spec:\n  id: a\nspec:\n  title: second\n")
        with self.assertRaisesRegex(ValueError, "exactly one spec: root"):
            read_one_spec(f)

    def test_a_spec_with_no_root_id_is_an_error(self):
        f = self._read("spec:\n  title: nothing\n")
        with self.assertRaises(ValueError):
            read_one_spec(f)

    def test_a_duplicate_criterion_id_is_an_error(self):
        f = self._read(
            "spec:\n  id: demo\n  acceptance_criteria:\n    - id: AC-01\n    - id: AC-01\n"
        )
        with self.assertRaisesRegex(ValueError, "duplicate criterion AC-01"):
            read_one_spec(f)

    def test_a_duplicate_spec_id_is_an_error(self):
        import tempfile, pathlib
        d = pathlib.Path(tempfile.mkdtemp())
        for name in ("a", "b"):
            (d / f"{name}.spec.yaml").write_text(
                "spec:\n  id: same\n  acceptance_criteria:\n    - id: AC-01\n")
        with self.assertRaisesRegex(ValueError, "duplicate spec id"):
            read_spec_registry(d)

    def test_the_registry_reads_the_shipped_specs(self):
        specs = read_spec_registry()
        self.assertGreater(len(specs), 100, "the shipped spec tree should be large")
        self.assertIn("AC-31", specs["system-compliance-scoring"])


class CheckerRunsWithoutSitePackages(unittest.TestCase):
    """This suite must run with site packages disabled.

    CI installs no Python dependencies and release-status.py says so in its
    own header. An import of a third-party module passes on a laptop that has
    it and fails the Quality gates job, which is the worst way to find out.
    Running the shipped file under `python3 -S` makes the boundary executable
    rather than a comment.
    """

    def test_the_suite_passes_under_dash_S(self):
        if os.environ.get("OW_RELEASE_STATUS_NO_SITE") == "1":
            self.skipTest("already the -S child; do not recurse")
        env = dict(os.environ, OW_RELEASE_STATUS_NO_SITE="1")
        r = subprocess.run([sys.executable, "-S", __file__],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0,
                         f"the suite fails without site packages:\n{r.stderr[-3000:]}")


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

    def test_gate_spec_citations_resolve(self):
        """A gate citing a spec and AC must cite one that exists.

        Without this the citation is prose. A criterion renamed or renumbered
        would leave the gate reading like evidence while pointing at nothing,
        which is the same failure mode the gates file exists to prevent.
        """
        specs = read_spec_registry()
        cited = [g for g in self.gates["gate"] if "spec" in g or "ac" in g]
        self.assertTrue(cited, "no gate cites a spec; this test would prove nothing")
        for g in cited:
            with self.subTest(gate=g["id"]):
                self.assertIn("spec", g, "a gate citing an ac must name its spec")
                self.assertIn("ac", g, "a gate citing a spec must name its ac")
                self.assertIn(g["spec"], specs, f"{g['spec']!r} is not a tracked spec")
                self.assertIn(g["ac"], specs[g["spec"]],
                              f"{g['spec']} has no {g['ac']}")

    def test_gate_spec_citations_are_annotated_by_a_test(self):
        """The cited criterion must be annotated by a test that CI runs.

        A spec can carry a criterion nothing exercises. Resolving the id is not
        enough: the gate claims the check run proves the behavior, so a test
        has to claim the criterion.
        """
        annotated = read_test_annotations()
        for g in self.gates["gate"]:
            if "spec" not in g:
                continue
            with self.subTest(gate=g["id"]):
                self.assertIn(g["spec"], annotated,
                              f"no test file annotates {g['spec']!r}")
                self.assertIn(g["ac"], annotated[g["spec"]],
                              f"no test annotates {g['spec']}/{g['ac']}")

    def test_shipped_attestations_parse(self):
        for a in rs.load_attestations():
            with self.subTest(f=a["_file"]):
                self.assertIn("kind", a)
                self.assertIn("artifact_sha256", a)


if __name__ == "__main__":
    unittest.main(verbosity=2, argv=[sys.argv[0]])
