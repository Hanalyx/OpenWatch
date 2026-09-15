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
    for root in (rs.REPO / "frontend" / "tests", rs.REPO / "internal",
                 rs.REPO / "packaging" / "tests", rs.REPO / "cmd"):
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
             "signed-tag", "per-platform", "attestation", "doc-review",
             "asset-digests", "checksums-signature", "tag-identity"}

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


# ------------------------------------------------- documentation review gate
#
# The candidate set is read from a real git commit, so these build throwaway
# repositories rather than asserting against a list someone typed. Expected
# digests are recomputed here from the record shape, never copied from the
# implementation: a constant shared between the code and its test proves the
# two agree, which is not the same as either being right.

import hashlib
import shutil
import tempfile
import tomllib


def _git(repo, *args):
    p = subprocess.run(("git", "-C", str(repo)) + args, capture_output=True)
    if p.returncode != 0:
        raise AssertionError(f"git {' '.join(args)}: {p.stderr.decode()}")
    return p.stdout


def _expected_digest(entries):
    """Independent implementation of the canonical manifest digest."""
    h = hashlib.sha256()
    for path, blob, verdict in sorted(entries, key=lambda e: e[0]):
        h.update(path + b"\0" + blob.encode() + b"\0" + verdict.encode() + b"\0")
    return h.hexdigest()


class DocRepo:
    """A throwaway repository whose tree is known exactly."""

    FILES = {
        "README.md": "root doc",
        "docs/guides/NESTED.md": "nested doc",
        "docs/runbooks/examples/deep/DEEP.md": "deeply nested doc",
        ".github/PULL_REQUEST_TEMPLATE.md": "a form, still in scope",
        ".claude/skills/write-doc.md": "agent scaffolding, still in scope",
        "scripts/README.md": "script notes, still in scope",
        "notes.txt": "not markdown",
        "docs/prose.markdown": "not the .md suffix",
        "docs/archive.md.bak": "not the .md suffix either",
        "build/generated.md": "ignored by .gitignore",
    }

    def __enter__(self):
        self.dir = Path(tempfile.mkdtemp(prefix="ow-docgate-"))
        _git(self.dir, "init", "-q")
        _git(self.dir, "config", "user.email", "t@example.com")
        _git(self.dir, "config", "user.name", "T")
        (self.dir / ".gitignore").write_text("build/\n", encoding="utf-8")
        for rel, body in self.FILES.items():
            p = self.dir / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body + "\n", encoding="utf-8")
        _git(self.dir, "add", "-A")
        _git(self.dir, "commit", "-qm", "seed")
        # Untracked, and written AFTER the commit so `add -A` cannot pick it
        # up. Writing it first is how it ended up tracked on the first run.
        (self.dir / "UNTRACKED.md").write_text("untracked\n", encoding="utf-8")
        self.commit = _git(self.dir, "rev-parse", "HEAD").decode().strip()
        return self

    def __exit__(self, *exc):
        shutil.rmtree(self.dir, ignore_errors=True)

    def docs(self):
        cwd = os.getcwd()
        os.chdir(self.dir)
        try:
            return rs.candidate_docs(self.commit)
        finally:
            os.chdir(cwd)

    def edit(self, rel, body):
        (self.dir / rel).write_text(body, encoding="utf-8")
        _git(self.dir, "add", "-A")
        _git(self.dir, "commit", "-qm", "edit")
        self.commit = _git(self.dir, "rev-parse", "HEAD").decode().strip()


class CandidateEnumeration(unittest.TestCase):
    EXPECTED = {
        b"README.md",
        b"docs/guides/NESTED.md",
        b"docs/runbooks/examples/deep/DEEP.md",
        b".github/PULL_REQUEST_TEMPLATE.md",
        b".claude/skills/write-doc.md",
        b"scripts/README.md",
    }

    def test_root_and_nested_markdown_are_included(self):
        with DocRepo() as repo:
            got = {p for p, _ in repo.docs()}
            self.assertIn(b"README.md", got)
            self.assertIn(b"docs/guides/NESTED.md", got)
            self.assertIn(b"docs/runbooks/examples/deep/DEEP.md", got)

    def test_there_are_no_path_exclusions(self):
        with DocRepo() as repo:
            got = {p for p, _ in repo.docs()}
        for path in (b".github/PULL_REQUEST_TEMPLATE.md",
                     b".claude/skills/write-doc.md",
                     b"scripts/README.md"):
            self.assertIn(path, got, f"{path!r} was excluded; the scope rule is a "
                                     "path suffix, not a judgment about which "
                                     "documents matter")

    def test_non_markdown_ignored_and_untracked_are_excluded(self):
        with DocRepo() as repo:
            got = {p for p, _ in repo.docs()}
        self.assertEqual(got, self.EXPECTED)
        for path in (b"notes.txt", b"docs/prose.markdown", b"docs/archive.md.bak",
                     b"build/generated.md", b"UNTRACKED.md"):
            self.assertNotIn(path, got)

    def test_entries_are_sorted_by_raw_path_bytes(self):
        with DocRepo() as repo:
            paths = [p for p, _ in repo.docs()]
        self.assertEqual(paths, sorted(paths))

    def test_a_non_utf8_path_is_rejected_rather_than_mangled(self):
        # A git path is bytes; a TOML string is UTF-8. A path that cannot
        # round-trip must stop the gate, because reviewing a path that is not
        # the one on disk is worse than not reviewing it.
        with DocRepo() as repo:
            bad = os.path.join(os.fsdecode(repo.dir), os.fsdecode(b"bro\xffken.md"))
            with open(os.fsencode(bad), "wb") as fh:
                fh.write(b"undecodable name\n")
            _git(repo.dir, "add", "-A")
            _git(repo.dir, "commit", "-qm", "bad name")
            repo.commit = _git(repo.dir, "rev-parse", "HEAD").decode().strip()
            cwd = os.getcwd()
            os.chdir(repo.dir)
            try:
                with self.assertRaises(rs.PathNotEncodable) as caught:
                    rs.candidate_docs(repo.commit)
            finally:
                os.chdir(cwd)
        self.assertIn(b"\xff", caught.exception.raw)

    def test_the_tree_is_read_from_the_commit_not_the_working_tree(self):
        with DocRepo() as repo:
            before = dict(repo.docs())
            (repo.dir / "docs/guides/NESTED.md").write_text("dirtied\n", encoding="utf-8")
            (repo.dir / "WORKTREE_ONLY.md").write_text("never committed\n", encoding="utf-8")
            after = dict(repo.docs())
        self.assertEqual(before, after,
                         "a dirty working tree changed the candidate set; the gate "
                         "must read the commit")


def doc_att(entries, **kw):
    """A documentation-review attestation over `entries`, overridden per test."""
    reviewed = [{"path": p.decode(), "blob": b, "verdict": v} for p, b, v in entries]
    base = {
        "_file": "doc-review-v0.8.0-rc.1.toml",
        "kind": "documentation-review",
        "tag": "v0.8.0-rc.1",
        "commit": "c" * 40,
        "artifact": DIGESTS[GOOD_SHA],
        "artifact_sha256": GOOD_SHA,
        "performed_by": "a.human",
        "performed_at": "2026-09-12",
        "reviewed": reviewed,
        "docs_sha256": _expected_digest(entries),
    }
    base.update(kw)
    return base


CAND = [(b"README.md", "1" * 40), (b"docs/guides/NESTED.md", "2" * 40)]
ACCURATE = [(p, b, "accurate") for p, b in CAND]
TAG, COMMIT = "v0.8.0-rc.1", "c" * 40


def run_doc(att, candidate=None, tag=TAG, commit=COMMIT, digests=None):
    return rs.eval_doc_review(att, CAND if candidate is None else candidate,
                              tag, commit, DIGESTS if digests is None else digests)


class DocReviewAcceptsOnlyAMatchingReview(unittest.TestCase):
    def test_clean_matching_evidence_passes(self):
        status, note = run_doc(doc_att(ACCURATE))
        self.assertEqual(status, rs.PASS, note)
        self.assertIn("2 documents", note)

    def test_a_document_added_since_the_review_is_stale(self):
        cand = CAND + [(b"docs/NEW.md", "3" * 40)]
        status, note = run_doc(doc_att(ACCURATE), candidate=cand)
        self.assertEqual(status, rs.STALE)
        self.assertIn("added docs/NEW.md", note)

    def test_a_document_removed_since_the_review_is_stale(self):
        status, note = run_doc(doc_att(ACCURATE), candidate=CAND[:1])
        self.assertEqual(status, rs.STALE)
        self.assertIn("removed docs/guides/NESTED.md", note)

    def test_an_edited_document_is_stale(self):
        cand = [(b"README.md", "1" * 40), (b"docs/guides/NESTED.md", "9" * 40)]
        status, note = run_doc(doc_att(ACCURATE), candidate=cand)
        self.assertEqual(status, rs.STALE)
        self.assertIn("edited docs/guides/NESTED.md", note)

    def test_an_unambiguous_rename_is_reported_as_a_rename(self):
        cand = [(b"README.md", "1" * 40), (b"docs/MOVED.md", "2" * 40)]
        status, note = run_doc(doc_att(ACCURATE), candidate=cand)
        self.assertEqual(status, rs.STALE)
        self.assertIn("renamed docs/guides/NESTED.md -> docs/MOVED.md", note)
        self.assertNotIn("added", note)
        self.assertNotIn("removed", note)

    def test_an_ambiguous_duplicate_blob_is_not_called_a_rename(self):
        # One blob, two new homes: nothing can say which old path became which.
        reviewed = [(b"a.md", "7" * 40, "accurate"), (b"b.md", "7" * 40, "accurate")]
        cand = [(b"x.md", "7" * 40), (b"y.md", "7" * 40)]
        status, note = run_doc(doc_att(reviewed), candidate=cand)
        self.assertEqual(status, rs.STALE)
        self.assertNotIn("renamed", note)
        self.assertIn("added", note)
        self.assertIn("removed", note)


class DocReviewRejectsUnboundOrUnsoundEvidence(unittest.TestCase):
    def test_wrong_tag_is_stale(self):
        status, note = run_doc(doc_att(ACCURATE, tag="v0.7.1"))
        self.assertEqual(status, rs.STALE)
        self.assertIn("attests tag v0.7.1", note)

    def test_wrong_commit_is_stale(self):
        status, note = run_doc(doc_att(ACCURATE, commit="d" * 40))
        self.assertEqual(status, rs.STALE)
        self.assertIn("attests commit", note)

    def test_artifact_digest_absent_from_the_candidate_is_stale(self):
        status, note = run_doc(doc_att(ACCURATE, artifact_sha256=OTHER_SHA))
        self.assertEqual(status, rs.STALE)
        self.assertIn("SHA256SUMS", note)

    def test_unreadable_checksums_fail_closed(self):
        status, _ = run_doc(doc_att(ACCURATE), digests=None if False else None)
        # digests=None means the candidate's SHA256SUMS could not be read.
        status, note = rs.eval_doc_review(doc_att(ACCURATE), CAND, TAG, COMMIT, None)
        self.assertEqual(status, rs.ERROR)
        self.assertIn("unverifiable", note)

    def test_unreadable_candidate_tree_fails_closed(self):
        status, note = rs.eval_doc_review(doc_att(ACCURATE), None, TAG, COMMIT, DIGESTS)
        self.assertEqual(status, rs.ERROR)
        self.assertIn("could not be read", note)

    def test_a_stored_blob_that_differs_from_the_tree_is_stale(self):
        reviewed = [(b"README.md", "1" * 40, "accurate"),
                    (b"docs/guides/NESTED.md", "f" * 40, "accurate")]
        status, note = run_doc(doc_att(reviewed))
        self.assertEqual(status, rs.STALE)
        self.assertIn("edited docs/guides/NESTED.md", note)

    def test_a_tampered_manifest_digest_fails(self):
        status, note = run_doc(doc_att(ACCURATE, docs_sha256="0" * 64))
        self.assertEqual(status, rs.FAIL)
        self.assertIn("docs_sha256", note)

    def test_an_agent_cannot_attest_a_documentation_review(self):
        status, note = run_doc(doc_att(ACCURATE, performed_by="openwatch-agent"))
        self.assertEqual(status, rs.FAIL)
        self.assertIn("human observation", note)

    def test_any_verdict_other_than_accurate_is_a_no_go(self):
        for verdict in ("defect", "pending", "accurate-ish", "ACCURATE", ""):
            reviewed = [(b"README.md", "1" * 40, "accurate"),
                        (b"docs/guides/NESTED.md", "2" * 40, verdict)]
            status, note = run_doc(doc_att(reviewed))
            self.assertEqual(status, rs.FAIL, f"verdict {verdict!r} was accepted")
            self.assertIn("must be 'accurate'", note)

    def test_a_missing_entry_fails(self):
        status, note = run_doc(doc_att(ACCURATE[:1]))
        self.assertEqual(status, rs.STALE)
        self.assertIn("added docs/guides/NESTED.md", note)

    def test_an_extra_entry_fails(self):
        reviewed = ACCURATE + [(b"docs/GHOST.md", "5" * 40, "accurate")]
        status, note = run_doc(doc_att(reviewed))
        self.assertEqual(status, rs.STALE)
        self.assertIn("removed docs/GHOST.md", note)

    def test_a_duplicate_entry_fails(self):
        reviewed = ACCURATE + [ACCURATE[0]]
        status, note = run_doc(doc_att(reviewed))
        self.assertEqual(status, rs.FAIL)
        self.assertIn("duplicate reviewed path", note)

    def test_a_malformed_entry_fails(self):
        att = doc_att(ACCURATE)
        att["reviewed"][1] = {"path": "docs/guides/NESTED.md", "blob": "2" * 40}
        status, note = rs.eval_doc_review(att, CAND, TAG, COMMIT, DIGESTS)
        self.assertEqual(status, rs.FAIL)
        self.assertIn("exactly path, blob and verdict", note)

    def test_an_entry_carrying_an_extra_field_fails(self):
        att = doc_att(ACCURATE)
        att["reviewed"][0]["note"] = "looked fine"
        status, note = rs.eval_doc_review(att, CAND, TAG, COMMIT, DIGESTS)
        self.assertEqual(status, rs.FAIL)
        self.assertIn("exactly path, blob and verdict", note)

    def test_no_reviewed_entries_fails(self):
        att = doc_att(ACCURATE, reviewed=[])
        status, note = rs.eval_doc_review(att, CAND, TAG, COMMIT, DIGESTS)
        self.assertEqual(status, rs.FAIL)
        self.assertIn("no reviewed entries", note)


class DocReviewRequiresANamedHumanAndARealArtifact(unittest.TestCase):
    def test_an_empty_performed_by_fails(self):
        status, note = run_doc(doc_att(ACCURATE, performed_by=""))
        self.assertEqual(status, rs.FAIL)
        self.assertIn("performed_by is empty", note)

    def test_a_whitespace_only_performed_by_fails(self):
        for blank in (" ", "\t", "   \n ", "\u00a0" if False else "  "):
            status, note = run_doc(doc_att(ACCURATE, performed_by=blank))
            self.assertEqual(status, rs.FAIL, f"{blank!r} was accepted as an identity")
            self.assertIn("performed_by is empty", note)

    def test_the_agent_test_is_applied_to_the_trimmed_identity(self):
        # Trailing whitespace must not carry an agent past the check.
        for sneaky in ("openwatch-agent ", " openwatch-agent", "openwatch-agent\t",
                       "\n openwatch-agent \n"):
            status, note = run_doc(doc_att(ACCURATE, performed_by=sneaky))
            self.assertEqual(status, rs.FAIL, f"{sneaky!r} passed as a human")
            self.assertIn("is an agent", note)

    def test_a_non_string_scalar_fails_without_a_traceback(self):
        for field, value in (("performed_by", 7), ("performed_at", 20260912),
                             ("docs_sha256", 12345), ("artifact_sha256", 99),
                             ("artifact", ["a.rpm"]), ("tag", 1.0),
                             ("commit", {"sha": "x"})):
            with self.subTest(field=field):
                status, note = run_doc(doc_att(ACCURATE, **{field: value}))
                self.assertEqual(status, rs.FAIL)
                self.assertIn(f"{field} must be a string", note)

    def test_a_non_string_scalar_does_not_crash_selection_either(self):
        broken = doc_att(ACCURATE, artifact_sha256=99)
        picked, problem = rs.select_doc_review([broken], "documentation-review",
                                               TAG, COMMIT, DIGESTS)
        self.assertIsNone(picked)
        self.assertEqual(problem[0], rs.STALE)

    def test_an_empty_artifact_fails(self):
        status, note = run_doc(doc_att(ACCURATE, artifact=""))
        self.assertEqual(status, rs.FAIL)
        self.assertIn("no artifact", note)

    def test_a_valid_digest_with_the_wrong_artifact_name_is_stale(self):
        status, note = run_doc(doc_att(ACCURATE, artifact="openwatch-9.9.9-1.x86_64.rpm"))
        self.assertEqual(status, rs.STALE)
        self.assertIn("belongs to", note)
        self.assertIn("openwatch-9.9.9-1.x86_64.rpm", note)

    def test_a_malformed_performed_at_fails(self):
        for bad in ("2026-13-01", "2026-02-30", "12/09/2026", "yesterday", "2026-9-12"):
            status, note = run_doc(doc_att(ACCURATE, performed_at=bad))
            self.assertEqual(status, rs.FAIL, f"{bad!r} was accepted")
            self.assertIn("ISO calendar date", note)

    def test_a_future_performed_at_fails(self):
        import datetime
        ahead = (datetime.date.today() + datetime.timedelta(days=1)).isoformat()
        status, note = run_doc(doc_att(ACCURATE, performed_at=ahead))
        self.assertEqual(status, rs.FAIL)
        self.assertIn("in the future", note)

    def test_today_is_accepted(self):
        import datetime
        status, note = run_doc(doc_att(ACCURATE,
                                       performed_at=datetime.date.today().isoformat()))
        self.assertEqual(status, rs.PASS, note)


class DocReviewSelectionIsCandidateBound(unittest.TestCase):
    def test_unreadable_checksums_are_an_error_through_selection(self):
        # Not STALE. Nothing could be compared, which is a different fact from
        # the evidence describing another candidate.
        picked, problem = rs.select_doc_review([doc_att(ACCURATE)], "documentation-review",
                                               TAG, COMMIT, None)
        self.assertIsNone(picked)
        self.assertEqual(problem[0], rs.ERROR)
        self.assertIn("cannot read SHA256SUMS", problem[1])

    def test_selection_uses_the_artifact_pair_not_the_digest_alone(self):
        wrong_name = doc_att(ACCURATE, _file="wrong-name.toml",
                             artifact="openwatch-9.9.9-1.x86_64.rpm")
        picked, problem = rs.select_doc_review([wrong_name], "documentation-review",
                                               TAG, COMMIT, DIGESTS)
        self.assertIsNone(picked, "an attestation naming another artifact was selected")
        self.assertEqual(problem[0], rs.STALE)


    def test_a_lexically_later_stale_file_cannot_hide_a_valid_one(self):
        valid = doc_att(ACCURATE, _file="aaa-valid.toml")
        stale = doc_att(ACCURATE, _file="zzz-stale.toml", commit="d" * 40)
        picked, problem = rs.select_doc_review([stale, valid], "documentation-review",
                                               TAG, COMMIT, DIGESTS)
        self.assertIsNone(problem, problem)
        self.assertEqual(picked["_file"], "aaa-valid.toml")
        status, _ = rs.eval_doc_review(picked, CAND, TAG, COMMIT, DIGESTS)
        self.assertEqual(status, rs.PASS)

    def test_two_attestations_binding_to_one_candidate_are_ambiguous(self):
        a = doc_att(ACCURATE, _file="one.toml")
        b = doc_att(ACCURATE, _file="two.toml")
        picked, problem = rs.select_doc_review([a, b], "documentation-review",
                                               TAG, COMMIT, DIGESTS)
        self.assertIsNone(picked)
        self.assertEqual(problem[0], rs.ERROR)
        self.assertIn("one.toml", problem[1])
        self.assertIn("two.toml", problem[1])

    def test_no_attestation_at_all_is_missing(self):
        picked, problem = rs.select_doc_review([], "documentation-review",
                                               TAG, COMMIT, DIGESTS)
        self.assertIsNone(picked)
        self.assertEqual(problem[0], rs.MISSING)

    def test_only_unbound_attestations_report_why(self):
        stale = doc_att(ACCURATE, _file="old.toml", tag="v0.7.1")
        picked, problem = rs.select_doc_review([stale], "documentation-review",
                                               TAG, COMMIT, DIGESTS)
        self.assertIsNone(picked)
        self.assertEqual(problem[0], rs.STALE)
        self.assertIn("attests tag v0.7.1", problem[1])


class SkeletonEncodesEveryLegalPath(unittest.TestCase):
    """Git permits any byte but NUL and "/" in a path component, so a tracked
    filename can carry a quote, a backslash, a newline or a control character.
    TOML forbids raw control characters in a basic string, so the generator has
    to escape them or emit a file tomllib refuses to read."""

    HARD = [
        'quote".md',
        "back\\slash.md",
        "tab\там.md".replace("\т", "\t"),
        "new\nline.md",
        "back\x08space.md",
        "form\x0cfeed.md",
        "del\x7fchar.md",
        "ctrl\x01one.md",
        "unicode-\u00e9\u4e2d.md",
    ]

    def test_every_legal_path_round_trips_through_the_skeleton(self):
        repo = Path(tempfile.mkdtemp(prefix="ow-hardpaths-"))
        try:
            _git(repo, "init", "-q")
            _git(repo, "config", "user.email", "t@example.com")
            _git(repo, "config", "user.name", "T")
            made = []
            for name in self.HARD:
                try:
                    (repo / name).write_text("x\n", encoding="utf-8")
                except (OSError, ValueError):
                    continue  # the filesystem refuses it; git never sees it
                made.append(name)
            self.assertGreaterEqual(len(made), 6,
                                    "too few difficult names survived to prove anything")
            _git(repo, "add", "-A")
            _git(repo, "commit", "-qm", "hard names")
            commit = _git(repo, "rev-parse", "HEAD").decode().strip()

            gen = rs.REPO / "scripts" / "doc-review-skeleton.py"
            r = subprocess.run([sys.executable, "-S", str(gen), "--commit", commit],
                               cwd=repo, capture_output=True)
            self.assertEqual(r.returncode, 0, r.stderr.decode())

            parsed = tomllib.loads(r.stdout.decode("utf-8"))
            recovered = {e["path"] for e in parsed["reviewed"]}
            for name in made:
                self.assertIn(name, recovered,
                              f"{name!r} did not survive the skeleton round trip")
        finally:
            shutil.rmtree(repo, ignore_errors=True)


class OrdinaryAttestationSelection(unittest.TestCase):
    """The three shipped v0.7 attestations are the reason this matters: two of
    them share kind and platform and differ only by candidate."""

    RC3 = "1" * 64
    RC4 = "2" * 64
    RPM = "openwatch-0.7.0-1.x86_64.rpm"

    def shipped(self):
        return [
            att(_file="clean-install-rhel9-zzz-rc3.toml", kind="clean-install",
                platform="rhel9", tag="v0.7.0-rc.3", artifact=self.RPM,
                artifact_sha256=self.RC3, performed_by="openwatch-agent"),
            att(_file="clean-install-rhel9-aaa-rc4.toml", kind="clean-install",
                platform="rhel9", tag="v0.7.0-rc.4", artifact=self.RPM,
                artifact_sha256=self.RC4, performed_by="openwatch-agent"),
        ]

    def test_a_lexically_later_stale_file_does_not_hide_the_matching_one(self):
        # rc.3 sorts last. The candidate is rc.4.
        picked, problem = rs.select_attestation(self.shipped(), "clean-install",
                                                {self.RC4: self.RPM}, "rhel9")
        self.assertIsNone(problem, problem)
        self.assertEqual(picked["_file"], "clean-install-rhel9-aaa-rc4.toml")

    def test_selection_is_by_the_artifact_pair_not_the_digest_alone(self):
        renamed = att(_file="renamed.toml", kind="clean-install", platform="rhel9",
                      artifact="openwatch-9.9.9-1.x86_64.rpm", artifact_sha256=self.RC4)
        picked, problem = rs.select_attestation([renamed], "clean-install",
                                                {self.RC4: self.RPM}, "rhel9")
        self.assertIsNone(picked)
        self.assertEqual(problem[0], rs.STALE)

    def test_two_binding_attestations_are_ambiguous(self):
        a = att(_file="one.toml", kind="clean-install", platform="rhel9",
                artifact=self.RPM, artifact_sha256=self.RC4)
        b = att(_file="two.toml", kind="clean-install", platform="rhel9",
                artifact=self.RPM, artifact_sha256=self.RC4)
        picked, problem = rs.select_attestation([a, b], "clean-install",
                                                {self.RC4: self.RPM}, "rhel9")
        self.assertIsNone(picked)
        self.assertEqual(problem[0], rs.ERROR)
        self.assertIn("one.toml", problem[1])
        self.assertIn("two.toml", problem[1])

    def test_a_different_platform_is_not_selected(self):
        picked, problem = rs.select_attestation(self.shipped(), "clean-install",
                                                {self.RC4: self.RPM}, "ubuntu2404")
        self.assertIsNone(picked)
        self.assertEqual(problem[0], rs.MISSING)

    def test_unreadable_checksums_fail_closed_as_error(self):
        picked, problem = rs.select_attestation(self.shipped(), "clean-install",
                                                None, "rhel9")
        self.assertIsNone(picked)
        self.assertEqual(problem[0], rs.ERROR)

    def test_nothing_binding_is_stale_and_names_what_was_considered(self):
        picked, problem = rs.select_attestation(self.shipped(), "clean-install",
                                                {"9" * 64: self.RPM}, "rhel9")
        self.assertIsNone(picked)
        self.assertEqual(problem[0], rs.STALE)
        self.assertIn("clean-install-rhel9-aaa-rc4.toml", problem[1])
        self.assertIn("clean-install-rhel9-zzz-rc3.toml", problem[1])

    def test_the_shipped_attestations_are_still_selectable(self):
        shipped = rs.load_attestations()
        by_kind = {}
        for a in shipped:
            by_kind.setdefault((a["kind"], a.get("platform")), []).append(a)
        for (kind, platform), group in by_kind.items():
            digests = {group[0]["artifact_sha256"]: group[0]["artifact"]}
            picked, problem = rs.select_attestation(shipped, kind, digests, platform)
            self.assertIsNone(problem, f"{kind}/{platform}: {problem}")
            self.assertEqual(picked["artifact_sha256"], group[0]["artifact_sha256"])


class ManifestCanonicalization(unittest.TestCase):
    def test_the_digest_matches_an_independent_computation(self):
        self.assertEqual(rs.docs_manifest_digest(ACCURATE), _expected_digest(ACCURATE))

    def test_entry_order_does_not_change_the_digest(self):
        self.assertEqual(rs.docs_manifest_digest(ACCURATE),
                         rs.docs_manifest_digest(list(reversed(ACCURATE))))

    def test_a_newline_in_a_path_cannot_forge_another_record(self):
        # NUL delimiting is why this is safe. A newline-delimited manifest
        # would hash these two sets identically.
        one = [(b"a\nb.md", "1" * 40, "accurate")]
        two = [(b"a", "1" * 40, "accurate"), (b"b.md", "1" * 40, "accurate")]
        self.assertNotEqual(rs.docs_manifest_digest(one), rs.docs_manifest_digest(two))

    def test_the_verdict_is_covered_by_the_digest(self):
        other = [(p, b, "pending") for p, b, _ in ACCURATE]
        self.assertNotEqual(rs.docs_manifest_digest(ACCURATE),
                            rs.docs_manifest_digest(other))


# ---------------------------------------------------- GA draft verification


import hashlib
import json
import shutil
import tempfile


class FakeGH:
    """Stand in for rs.sh / rs.sh_bytes: serves a releases listing and asset
    bytes by id, and records every call. No network."""

    def __init__(self, releases, assets_bytes, tag_commit="d" * 40, annotated=True):
        self.releases = releases          # list of release dicts (GitHub shape)
        self.assets_bytes = assets_bytes  # asset id -> bytes
        self.tag_commit = tag_commit      # what refs/tags/<tag> resolves to on origin
        self.annotated = annotated        # annotated tags need a second dereference
        self.tag_readable = True
        self.calls = []

    def sh(self, *args, check=False):
        self.calls.append(args)
        for a in args:
            if a.startswith("repos/{owner}/{repo}/git/ref/tags/"):
                if not self.tag_readable or self.tag_commit is None:
                    return 1, "Not Found"
                if self.annotated:
                    return 0, "tag\t" + "t" * 40
                return 0, "commit\t" + self.tag_commit
            if a.startswith("repos/{owner}/{repo}/git/tags/"):
                return 0, self.tag_commit
        if "repos/{owner}/{repo}/releases" in args and "--paginate" in args:
            jq = args[args.index("--jq") + 1]
            tag = jq.split('"')[1]
            lines = [json.dumps(r) for r in self.releases if r["tag_name"] == tag]
            return 0, "\n".join(lines)
        if "-X" in args and "PATCH" in args:
            rid = int(args[args.index("PATCH") + 1].rsplit("/", 1)[1])
            for r in self.releases:
                if r["id"] == rid:
                    r["draft"] = False
                    return 0, json.dumps(r)
            return 1, "not found"
        return 1, f"unexpected call {args}"

    def sh_bytes(self, *args):
        self.calls.append(args)
        for a in args:
            if a.startswith("repos/{owner}/{repo}/releases/assets/"):
                aid = int(a.rsplit("/", 1)[1])
                if aid in self.assets_bytes:
                    return 0, self.assets_bytes[aid]
                return 1, b""
        return 1, b""


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def draft_fixture(tag="v0.8.0", draft=True):
    """A draft release with two packages, one SBOM, a manifest over them and
    the manifest's (fake) signature, plus KEYS."""
    files = {
        "openwatch-0.8.0-1.x86_64.rpm": b"rpm-bytes",
        "openwatch_0.8.0_amd64.deb": b"deb-bytes",
        "openwatch-0.8.0-1.x86_64.rpm.cdx.json": b"{}",
    }
    sums = "".join(f"{_sha(b)}  {n}\n" for n, b in files.items()).encode()
    files["SHA256SUMS"] = sums
    files["SHA256SUMS.asc"] = b"-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----\n"
    files["KEYS"] = b"keys"
    assets, blobs = [], {}
    for i, (n, b) in enumerate(files.items(), start=100):
        assets.append({"id": i, "name": n, "size": len(b)})
        blobs[i] = b
    release = {"id": 7, "tag_name": tag, "draft": draft, "prerelease": False,
               "target_commitish": "main", "assets": assets}
    return release, blobs


class DraftReleasesAreVisible(unittest.TestCase):
    """A GA candidate lives in a draft until it is published. The evaluator
    has to see it there, and has to say which state it found."""

    def setUp(self):
        self.release, self.blobs = draft_fixture()
        self.gh = FakeGH([self.release], self.blobs)
        self._sh, self._shb = rs.sh, rs.sh_bytes
        rs.sh, rs.sh_bytes = self.gh.sh, self.gh.sh_bytes

    def tearDown(self):
        rs.sh, rs.sh_bytes = self._sh, self._shb

    def test_a_draft_is_found_through_the_listing_not_the_tag_endpoint(self):
        info = rs.release_info("v0.8.0")
        self.assertTrue(info["exists"])
        self.assertTrue(info["draft"])
        self.assertEqual(rs.release_state("v0.8.0", info), "draft")
        for call in self.gh.calls:
            self.assertNotIn("releases/tags", " ".join(call),
                             "releases/tags/<tag> never returns a draft")

    def test_assets_and_checksums_are_read_from_the_draft(self):
        info = rs.release_info("v0.8.0")
        self.assertIn("SHA256SUMS", rs.release_assets("v0.8.0", info))
        digests = rs.release_digests("v0.8.0", info)
        self.assertEqual(len(digests), 3)
        self.assertIn(_sha(b"rpm-bytes"), digests)

    def test_no_release_and_two_releases_are_distinct_facts(self):
        self.assertEqual(rs.release_state("v9.9.9", rs.release_info("v9.9.9")), "none")
        self.gh.releases.append(dict(self.release, id=8))
        info = rs.release_info("v0.8.0")
        self.assertEqual(info.get("ambiguous"), 2)
        self.assertIsNone(rs.release_digests("v0.8.0", info))
        self.assertEqual(rs.release_state("v0.8.0", info), "ambiguous")

    def test_published_state_is_reported_as_such(self):
        self.release["draft"] = False
        self.assertEqual(rs.release_state("v0.8.0"), "published")
        self.release["prerelease"] = True
        self.assertEqual(rs.release_state("v0.8.0"), "pre-release")


class AssetDigestsAreHashedNotTrusted(unittest.TestCase):
    """A1: the bytes the release serves hash to what SHA256SUMS says. The
    release page's asset list is a list of names; only a download can say
    what the names carry."""

    def setUp(self):
        self.release, self.blobs = draft_fixture()
        self.gh = FakeGH([self.release], self.blobs)
        self._sh, self._shb = rs.sh, rs.sh_bytes
        rs.sh, rs.sh_bytes = self.gh.sh, self.gh.sh_bytes
        self.work = Path(tempfile.mkdtemp())

    def tearDown(self):
        rs.sh, rs.sh_bytes = self._sh, self._shb
        shutil.rmtree(self.work, ignore_errors=True)

    def run_a1(self):
        info = rs.release_info("v0.8.0")
        return rs.verify_asset_digests(info, rs.release_digests("v0.8.0", info), self.work)

    def test_matching_bytes_pass(self):
        status, note = self.run_a1()
        self.assertEqual(status, rs.PASS, note)
        self.assertIn("3 assets hashed", note)

    def test_one_changed_byte_fails_and_names_the_asset(self):
        aid = next(a["id"] for a in self.release["assets"] if a["name"].endswith(".deb"))
        self.blobs[aid] = b"deb-bytes-rebuilt"
        status, note = self.run_a1()
        self.assertEqual(status, rs.FAIL)
        self.assertIn("openwatch_0.8.0_amd64.deb", note)
        self.assertIn("digest mismatch", note)

    def test_a_manifested_asset_missing_from_the_release_fails(self):
        self.release["assets"] = [a for a in self.release["assets"] if not a["name"].endswith(".deb")]
        status, note = self.run_a1()
        self.assertEqual(status, rs.FAIL)
        self.assertIn("not on the release", note)
        self.assertIn("openwatch_0.8.0_amd64.deb", note)

    def test_a_package_on_the_release_but_not_in_the_manifest_fails(self):
        self.release["assets"].append({"id": 999, "name": "openwatch-0.8.0-1.aarch64.rpm", "size": 3})
        self.blobs[999] = b"arm"
        status, note = self.run_a1()
        self.assertEqual(status, rs.FAIL)
        self.assertIn("not in SHA256SUMS", note)
        self.assertIn("aarch64", note)

    def test_unreadable_manifest_is_an_error_not_a_pass(self):
        info = rs.release_info("v0.8.0")
        status, _ = rs.verify_asset_digests(info, None, self.work)
        self.assertEqual(status, rs.ERROR)

    def test_no_release_is_missing(self):
        status, _ = rs.verify_asset_digests({"exists": False}, {}, self.work)
        self.assertEqual(status, rs.MISSING)


class ChecksumSignatureIsVerified(unittest.TestCase):
    """A2: SHA256SUMS.asc is a good signature by a key in security/KEYS. Only
    gpg's machine status is read."""

    def test_good_signature_passes_and_names_the_signer(self):
        status, note = rs.interpret_gpg_status(0, "[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG 4AA0538FE239E50C Hanalyx LLC (release signing) <ops@hanalyx.com>\n[GNUPG:] VALIDSIG ...\n")
        self.assertEqual(status, rs.PASS, note)
        self.assertIn("Hanalyx LLC", note)

    def test_bad_signature_fails(self):
        status, note = rs.interpret_gpg_status(1, "[GNUPG:] NEWSIG\n[GNUPG:] BADSIG 4AA0538FE239E50C x\n")
        self.assertEqual(status, rs.FAIL)
        self.assertIn("BAD signature", note)

    def test_unknown_key_fails(self):
        status, note = rs.interpret_gpg_status(2, "[GNUPG:] NEWSIG\n[GNUPG:] ERRSIG DEADBEEFDEADBEEF 1 8 00 1 9\n[GNUPG:] NO_PUBKEY DEADBEEFDEADBEEF\n")
        self.assertEqual(status, rs.FAIL)
        self.assertIn("not in security/KEYS", note)

    def test_exit_zero_without_goodsig_is_not_a_pass(self):
        status, _ = rs.interpret_gpg_status(0, "")
        self.assertEqual(status, rs.FAIL)

    def test_missing_signature_asset_fails_before_any_download(self):
        release, blobs = draft_fixture()
        release["assets"] = [a for a in release["assets"] if a["name"] != "SHA256SUMS.asc"]
        status, note = rs.verify_checksums_signature(release | {"exists": True, "draft": True}, tempfile.mkdtemp())
        self.assertEqual(status, rs.FAIL)
        self.assertIn("unsigned", note)

    @unittest.skipIf(shutil.which("gpg") is None, "gpg not installed")
    def test_a_real_signature_verifies_against_an_exported_key_and_tampering_fails(self):
        work = Path(tempfile.mkdtemp())
        try:
            signer = work / "signer"
            signer.mkdir()
            signer.chmod(0o700)
            env = {"GNUPGHOME": str(signer), "PATH": os.environ.get("PATH", "")}
            gen = subprocess.run(["gpg", "--batch", "--quiet", "--pinentry-mode", "loopback",
                                  "--passphrase", "", "--quick-gen-key",
                                  "Test Signer <test@example.invalid>", "default", "default", "0"],
                                 capture_output=True, text=True, env=env)
            self.assertEqual(gen.returncode, 0, gen.stderr)
            keys = work / "KEYS"
            subprocess.run(["gpg", "--batch", "--armor", "--export", "--output", str(keys)],
                           check=True, env=env)
            sums = work / "SHA256SUMS"
            sums.write_bytes(b"deadbeef  a.rpm\n")
            asc = work / "SHA256SUMS.asc"
            subprocess.run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                            "--armor", "--detach-sign", "--output", str(asc), str(sums)],
                           check=True, env=env)
            home = work / "verifier"
            home.mkdir()
            home.chmod(0o700)
            status, note = rs.gpg_verify(home, keys, asc, sums)
            self.assertEqual(status, rs.PASS, note)
            self.assertIn("Test Signer", note)
            sums.write_bytes(b"deadbeef  a.rpm\n# tampered\n")
            status, note = rs.gpg_verify(home, keys, asc, sums)
            self.assertEqual(status, rs.FAIL, note)
        finally:
            shutil.rmtree(work, ignore_errors=True)


class StaleEvidenceInTheGAFlow(unittest.TestCase):
    """Option C: nothing is inherited. Evidence from the RC does not describe
    the GA candidate, and evidence from a replaced GA candidate does not
    describe its replacement."""

    GA_TAG, GA_COMMIT = "v0.8.0", "d" * 40
    GA_DIGESTS = {"e" * 64: "openwatch-0.8.0-1.x86_64.rpm"}

    def test_the_rc_documentation_review_is_stale_against_the_ga_tag(self):
        # Same reviewer, same verdicts, same bytes even; the candidate is not.
        status, note = run_doc(doc_att(ACCURATE), tag=self.GA_TAG,
                               commit=self.GA_COMMIT, digests=self.GA_DIGESTS)
        self.assertEqual(status, rs.STALE, note)
        self.assertIn("attests tag v0.8.0-rc.1", note)

    def test_an_rc_fleet_attestation_is_stale_against_the_ga_digests(self):
        status, note = rs.eval_attestation(att(kind="fleet-scan", artifact_sha256=GOOD_SHA),
                                           self.GA_DIGESTS, True)
        self.assertEqual(status, rs.STALE, note)

    def test_a_ga_review_of_a_replaced_candidate_is_stale_against_the_replacement(self):
        # The candidate was replaced (a changed CHANGELOG date is enough):
        # new commit, new build, new digests. The old GA review names the old
        # commit and the old artifact.
        old = doc_att(ACCURATE, tag=self.GA_TAG, commit=self.GA_COMMIT,
                      artifact="openwatch-0.8.0-1.x86_64.rpm", artifact_sha256="e" * 64)
        new_commit, new_digests = "f" * 40, {"9" * 64: "openwatch-0.8.0-1.x86_64.rpm"}
        status, note = run_doc(old, tag=self.GA_TAG, commit=new_commit, digests=new_digests)
        self.assertEqual(status, rs.STALE, note)
        self.assertIn("attests commit", note)

    def test_a_ga_fleet_attestation_of_a_replaced_candidate_is_stale(self):
        old = att(kind="fleet-scan", artifact_sha256="e" * 64)
        status, note = rs.eval_attestation(old, {"9" * 64: "openwatch-0.8.0-1.x86_64.rpm"}, True)
        self.assertEqual(status, rs.STALE, note)

    def test_the_evaluator_has_no_promotion_or_inheritance_path(self):
        # Option D was not approved. There is no flag, field or function that
        # carries an RC verdict onto a GA candidate.
        src = (Path(__file__).resolve().parent / "release-status.py").read_text(encoding="utf-8")
        for token in ("--promotes", "promotes", "basis_docs_sha256", "carried_from"):
            self.assertNotIn(token, src, f"{token!r} would be an inheritance path")
        self.assertNotIn("promotes", rs.DOC_SCALARS)


class TagIdentityIsCheckedOnOrigin(unittest.TestCase):
    """R4: the commit the gates were evaluated against is the commit the tag
    names on origin. Evaluation resolves the tag locally, which is right only
    while the two agree."""

    def setUp(self):
        self.release, self.blobs = draft_fixture()
        self.gh = FakeGH([self.release], self.blobs)
        self._sh = rs.sh
        rs.sh = self.gh.sh

    def tearDown(self):
        rs.sh = self._sh

    def test_an_annotated_tag_is_dereferenced_to_its_commit(self):
        self.assertEqual(rs.remote_tag_commit("v0.8.0"), "d" * 40)
        self.assertTrue(any("git/tags/" in " ".join(c) for c in self.gh.calls),
                        "an annotated tag object must be dereferenced")

    def test_a_lightweight_tag_resolves_directly(self):
        self.gh.annotated = False
        self.assertEqual(rs.remote_tag_commit("v0.8.0"), "d" * 40)

    def test_matching_commits_pass(self):
        status, note = rs.verify_tag_identity("v0.8.0", "d" * 40)
        self.assertEqual(status, rs.PASS, note)

    def test_a_moved_or_stale_tag_fails_and_names_both_commits(self):
        self.gh.tag_commit = "e" * 40
        status, note = rs.verify_tag_identity("v0.8.0", "d" * 40)
        self.assertEqual(status, rs.FAIL)
        self.assertIn("e" * 12, note)
        self.assertIn("d" * 12, note)
        self.assertIn("different candidate", note)

    def test_an_unreadable_tag_is_an_error_not_a_pass(self):
        self.gh.tag_readable = False
        status, note = rs.verify_tag_identity("v0.8.0", "d" * 40)
        self.assertEqual(status, rs.ERROR)
        self.assertIn("origin", note)


if __name__ == "__main__":
    unittest.main(verbosity=2, argv=[sys.argv[0]])
