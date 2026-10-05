#!/usr/bin/env python3
"""Tests for scripts/sbom-merge.py (spec system-supply-chain C-09).

Run one class with `python3 -S scripts/test_sbom_merge.py InventoryTests`.
"""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("sbom_merge", REPO / "scripts/sbom-merge.py")
sbom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sbom)

FONT = bytes(range(256)) * 8  # 2 KiB, above the minimum match size
TINY = b"tiny shared file"
INTEGRITY = "sha512-" + "A" * 86 + "=="


def entry(version, **extra):
    return dict({"version": version, "license": "MIT", "integrity": INTEGRITY, "resolved": "https://x"}, **extra)


def lockfile():
    return {"lockfileVersion": 3, "packages": {
        "": {"name": "openwatch-frontend", "version": "0.0.0",
             "dependencies": {"react": "^19", "@fontsource/inter": "^5", "maybe": "^1"},
             "devDependencies": {"vitest": "^3"}},
        "node_modules/react": entry("19.0.0", dependencies={"scheduler": "^0.25"}),
        "node_modules/scheduler": entry("0.25.0"),
        "node_modules/@fontsource/inter": entry("5.2.8", license="OFL-1.1"),
        # A nested copy at another version, and one at the same version.
        "node_modules/react/node_modules/scheduler": entry("0.24.0"),
        "node_modules/maybe": entry("1.0.0", optional=True, license="(MIT OR Apache-2.0)",
                                    optionalDependencies={"absent-native": "^1"}),
        "node_modules/vitest": entry("3.0.0", dev=True),
    }}


class Fixture:
    """A lockfile, installed node_modules, an embedded SPA and a binary."""

    def __init__(self, tmp, binary_has_font=True, installed_inter="5.2.8"):
        self.root = Path(tmp)
        self.lock = lockfile()
        nm = self.root / "frontend/node_modules"
        for path, item in self.lock["packages"].items():
            if path:
                d = self.root / "frontend" / path
                d.mkdir(parents=True, exist_ok=True)
                version = installed_inter if path.endswith("@fontsource/inter") else item["version"]
                (d / "package.json").write_text(json.dumps({"version": version}))
                (d / "LICENSE").write_bytes(TINY)
        (nm / "@fontsource/inter/files").mkdir(parents=True)
        (nm / "@fontsource/inter/files/inter-latin-400.woff2").write_bytes(FONT)
        self.node_modules = nm
        self.spa = self.root / "spa"
        (self.spa / "assets").mkdir(parents=True)
        (self.spa / "assets/inter-latin-400-AbCd1234.woff2").write_bytes(FONT)
        (self.spa / "assets/tiny.txt").write_bytes(TINY)
        (self.spa / "assets/index.js").write_bytes(b"console.log('app')" * 64)
        self.binary = self.root / "openwatch"
        self.binary.write_bytes(b"ELF" + (FONT if binary_has_font else b"") + TINY + b"\0" * 64)
        self.artifact = self.binary

    def inventory(self):
        return sbom.frontend_inventory(self.lock, self.node_modules, self.spa, self.binary)

    def syft(self):
        digest = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                "metadata": {"component": {"bom-ref": "file-1", "type": "file", "name": "openwatch",
                                           "version": "sha256:" + digest}},
                "components": [
                    {"bom-ref": "pkg:golang/github.com/hanalyx/openwatch@v1?package-id=a", "type": "library",
                     "name": "github.com/Hanalyx/openwatch", "version": "v1",
                     "purl": "pkg:golang/github.com/Hanalyx/openwatch@v1"},
                    {"bom-ref": "pkg:golang/example.com/mod@v1.2.0?package-id=b", "type": "library",
                     "name": "example.com/mod", "version": "v1.2.0", "purl": "pkg:golang/example.com/mod@v1.2.0"},
                    {"bom-ref": "pkg:golang/stdlib@go1.26.6?package-id=c", "type": "library",
                     "name": "stdlib", "version": "go1.26.6", "purl": "pkg:golang/stdlib@go1.26.6"}],
                "dependencies": [{"ref": "pkg:golang/github.com/hanalyx/openwatch@v1?package-id=a",
                                  "dependsOn": ["pkg:golang/example.com/mod@v1.2.0?package-id=b"]}]}

    def modules(self):
        return {"example.com/mod": "v1.2.0", "stdlib": "go1.26.6"}

    def merged(self):
        components, deps = self.inventory()
        return sbom.merge(self.syft(), None, components, deps)


def by_purl(components):
    return {c["purl"]: c for c in components if c.get("purl", "").startswith("pkg:npm/")}


def evidence(component):
    return {p["name"]: p["value"] for p in component["properties"]}[sbom.EVIDENCE]


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_runtime_set_identity_and_licenses(self):
        components, _ = Fixture(self.tmp.name).inventory()
        npm = by_purl(components)
        self.assertEqual(sorted(npm), sorted([
            "pkg:npm/react@19.0.0", "pkg:npm/scheduler@0.25.0", "pkg:npm/scheduler@0.24.0",
            "pkg:npm/%40fontsource/inter@5.2.8", "pkg:npm/maybe@1.0.0"]))
        inter = npm["pkg:npm/%40fontsource/inter@5.2.8"]
        self.assertEqual((inter["group"], inter["name"], inter["version"]), ("@fontsource", "inter", "5.2.8"))
        self.assertEqual(inter["licenses"], [{"license": {"id": "OFL-1.1"}}])
        self.assertEqual(npm["pkg:npm/maybe@1.0.0"]["licenses"], [{"expression": "(MIT OR Apache-2.0)"}])
        self.assertEqual(npm["pkg:npm/maybe@1.0.0"]["scope"], "optional")
        # The integrity hash is the registry tarball's, so it sits on the
        # distribution reference and is labeled, never in the component hashes.
        self.assertNotIn("hashes", inter)
        (dist,) = inter["externalReferences"]
        self.assertEqual((dist["type"], dist["url"]), ("distribution", "https://x"))
        self.assertEqual(dist["hashes"][0]["alg"], "SHA-512")
        self.assertEqual(len(dist["hashes"][0]["content"]), 128)
        self.assertIn({"name": sbom.HASH_SOURCE, "value": "npm-registry-tarball (package-lock integrity)"},
                      inter["properties"])
        self.assertNotIn("pkg:npm/vitest@3.0.0", npm)

    def test_duplicate_purl_keeps_every_lockfile_path(self):
        lock_fixture = Fixture(self.tmp.name)
        lock_fixture.lock["packages"]["node_modules/react/node_modules/scheduler"]["version"] = "0.25.0"
        components, _ = lock_fixture.inventory()
        paths = [p["value"] for p in by_purl(components)["pkg:npm/scheduler@0.25.0"]["properties"]
                 if p["name"] == sbom.LOCKFILE_PATH]
        self.assertEqual(paths, ["node_modules/react/node_modules/scheduler", "node_modules/scheduler"])

    def test_duplicate_entries_that_disagree_fail(self):
        for field, value in (("integrity", "sha512-" + "B" * 86 + "=="), ("license", "ISC"), ("resolved", "https://y")):
            f = Fixture(tempfile.mkdtemp(dir=self.tmp.name))
            nested = f.lock["packages"]["node_modules/react/node_modules/scheduler"]
            nested.update(version="0.25.0", **{field: value})
            with self.assertRaisesRegex(ValueError, f"pkg:npm/scheduler@0.25.0 is locked at .* different {field}"):
                f.inventory()

    def test_duplicate_entries_keep_both_dependency_sets(self):
        f = Fixture(self.tmp.name)
        packages = f.lock["packages"]
        packages["node_modules/react/node_modules/scheduler"]["version"] = "0.25.0"
        packages["node_modules/react/node_modules/scheduler"]["dependencies"] = {"maybe": "^1"}
        packages["node_modules/scheduler"]["dependencies"] = {"@fontsource/inter": "^5"}
        _, deps = f.inventory()
        self.assertEqual(deps["pkg:npm/scheduler@0.25.0"], ["pkg:npm/%40fontsource/inter@5.2.8", "pkg:npm/maybe@1.0.0"])

    def test_only_a_proven_file_verifies(self):
        npm = by_purl(Fixture(self.tmp.name).inventory()[0])
        inter = npm["pkg:npm/%40fontsource/inter@5.2.8"]
        self.assertEqual(evidence(inter), "bundle-files-verified")
        self.assertEqual(inter["evidence"]["occurrences"], [{"location": "spa/assets/inter-latin-400-AbCd1234.woff2"}])
        props = [(p["name"], p["value"]) for p in inter["properties"]]
        # One of the package's three files (package.json, LICENSE, the font)
        # is proven to ship. That is a partial claim, recorded as one.
        self.assertIn(("openwatch:bundle-files-verified", "1"), props)
        self.assertIn(("openwatch:package-file-count", "3"), props)
        self.assertIn(("openwatch:verified-file",
                       "files/inter-latin-400.woff2 -> spa/assets/inter-latin-400-AbCd1234.woff2"), props)
        for ref in ("pkg:npm/react@19.0.0", "pkg:npm/scheduler@0.25.0", "pkg:npm/maybe@1.0.0"):
            self.assertEqual(evidence(npm[ref]), sbom.LOCKFILE, ref)
            self.assertNotIn("evidence", npm[ref])
            names = {p["name"] for p in npm[ref]["properties"]}
            self.assertFalse(names & {sbom.VERIFIED_COUNT, sbom.FILE_COUNT, sbom.VERIFIED_FILE}, ref)

    def test_match_absent_from_binary_stays_lockfile(self):
        npm = by_purl(Fixture(self.tmp.name, binary_has_font=False).inventory()[0])
        self.assertEqual(evidence(npm["pkg:npm/%40fontsource/inter@5.2.8"]), sbom.LOCKFILE)

    def test_installed_version_mismatch_stays_lockfile(self):
        npm = by_purl(Fixture(self.tmp.name, installed_inter="5.2.7").inventory()[0])
        self.assertEqual(evidence(npm["pkg:npm/%40fontsource/inter@5.2.8"]), sbom.LOCKFILE)

    def test_small_shared_file_does_not_verify(self):
        # Every package carries TINY as LICENSE and the SPA carries it too.
        npm = by_purl(Fixture(self.tmp.name).inventory()[0])
        self.assertEqual(evidence(npm["pkg:npm/react@19.0.0"]), sbom.LOCKFILE)

    def test_incomplete_lockfile_entry_fails(self):
        for field in ("license", "integrity", "version"):
            f = Fixture(tempfile.mkdtemp(dir=self.tmp.name))
            del f.lock["packages"]["node_modules/react"][field]
            with self.assertRaisesRegex(ValueError, f"has no {field}"):
                f.inventory()

    def test_unresolvable_required_dependency_fails(self):
        f = Fixture(self.tmp.name)
        f.lock["packages"]["node_modules/react"]["dependencies"]["ghost"] = "^1"
        with self.assertRaisesRegex(ValueError, "does not resolve"):
            f.inventory()

    def test_nested_resolution(self):
        _, deps = Fixture(self.tmp.name).inventory()
        self.assertEqual(deps["pkg:npm/react@19.0.0"], ["pkg:npm/scheduler@0.24.0"])
        self.assertEqual(deps[sbom.FRONTEND_REF], sorted([
            "pkg:npm/%40fontsource/inter@5.2.8", "pkg:npm/maybe@1.0.0", "pkg:npm/react@19.0.0"]))


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.f = Fixture(self.tmp.name)

    def test_syft_components_and_edges_preserved(self):
        original = self.f.syft()
        merged = self.f.merged()
        refs = {c["bom-ref"]: c for c in merged["components"]}
        for component in original["components"]:
            self.assertEqual(refs[component["bom-ref"]], component)
        edges = {d["ref"]: d["dependsOn"] for d in merged["dependencies"]}
        for entry_ in original["dependencies"]:
            self.assertTrue(set(entry_["dependsOn"]) <= set(edges[entry_["ref"]]))
        self.assertEqual(sorted(edges["file-1"]), sorted(
            ["pkg:golang/github.com/hanalyx/openwatch@v1?package-id=a", sbom.FRONTEND_REF]))
        self.assertEqual(original, self.f.syft(), "merge must not mutate its input")

    def test_package_sbom_gains_binary_modules_and_edges(self):
        package = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                   "metadata": {"component": {"bom-ref": "pkgfile", "type": "file", "name": "openwatch.rpm"}},
                   "components": [{"bom-ref": "pkg:rpm/openwatch@1?package-id=r", "type": "library",
                                   "name": "openwatch", "purl": "pkg:rpm/openwatch@1?arch=x86_64"}]}
        components, deps = self.f.inventory()
        merged = sbom.merge(package, self.f.syft(), components, deps)
        refs = {c["bom-ref"] for c in merged["components"]}
        self.assertIn("pkg:golang/example.com/mod@v1.2.0?package-id=b", refs)
        edges = {d["ref"]: d["dependsOn"] for d in merged["dependencies"]}
        for owner in ("pkgfile", "pkg:rpm/openwatch@1?package-id=r"):
            self.assertIn(sbom.FRONTEND_REF, edges[owner])
            self.assertIn("pkg:golang/github.com/hanalyx/openwatch@v1?package-id=a", edges[owner])

    def test_collision_with_different_content_fails(self):
        syft = self.f.syft()
        syft["components"].append({"bom-ref": "pkg:npm/react@19.0.0", "type": "library", "name": "react", "version": "18"})
        components, deps = self.f.inventory()
        with self.assertRaisesRegex(ValueError, "collision"):
            sbom.merge(syft, None, components, deps)


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.f = Fixture(self.tmp.name)
        self.good = self.f.merged()

    def problems(self, doc, modules=None):
        return sbom.check(doc, self.f.lock, self.f.artifact, self.f.binary, self.f.spa, modules or self.f.modules())

    def mutate(self, change):
        doc = copy.deepcopy(self.good)
        change(doc)
        return self.problems(doc)

    def npm(self, doc, ref):
        return next(c for c in doc["components"] if c.get("purl") == ref)

    def test_good_sbom_passes(self):
        self.assertEqual(self.problems(self.good), [])

    def assertReports(self, change, pattern):
        problems = self.mutate(change)
        self.assertTrue(any(re.search(pattern, p) for p in problems), problems)

    def test_mutations_are_reported(self):
        react = "pkg:npm/react@19.0.0"
        inter = "pkg:npm/%40fontsource/inter@5.2.8"
        cases = {
            "missing component": (lambda d: d["components"].remove(self.npm(d, react)), "missing: pkg:npm/react"),
            "extra component": (lambda d: d["components"].append(dict(self.npm(d, react), **{
                "bom-ref": "pkg:npm/vitest@3.0.0", "purl": "pkg:npm/vitest@3.0.0"})), "not in the lockfile runtime set"),
            "version": (lambda d: self.npm(d, react).update(version="18.0.0"), "version differs"),
            "license": (lambda d: self.npm(d, react).update(licenses=[{"license": {"id": "ISC"}}]), "license differs"),
            "verified without occurrence": (lambda d: self.npm(d, inter).pop("evidence"), "occurrences differ"),
            "verified without files": (lambda d: self.npm(d, inter).update(properties=[
                p for p in self.npm(d, inter)["properties"] if p["name"] != sbom.VERIFIED_FILE]), "no verified files"),
            "verified count": (lambda d: self.npm(d, inter)["properties"].append(
                {"name": sbom.VERIFIED_COUNT, "value": "9"}) or self.npm(d, inter)["properties"].remove(
                {"name": sbom.VERIFIED_COUNT, "value": "1"}), "does not match the verified files"),
            "file count below verified": (lambda d: [p.update(value="0") for p in self.npm(d, inter)["properties"]
                                                     if p["name"] == sbom.FILE_COUNT], "smaller than the verified"),
            "tarball hash moved into component hashes": (lambda d: self.npm(d, react).update(
                hashes=self.npm(d, react)["externalReferences"][0]["hashes"]), "out of the component's own hashes"),
            "hash source unlabeled": (lambda d: self.npm(d, react).update(properties=[
                p for p in self.npm(d, react)["properties"] if p["name"] != sbom.HASH_SOURCE]), "must be labeled"),
            "distribution hash": (lambda d: self.npm(d, react)["externalReferences"][0]["hashes"][0].update(
                content="00"), "distribution reference differs"),
            "distribution url": (lambda d: self.npm(d, react)["externalReferences"][0].update(
                url="https://elsewhere"), "distribution reference differs"),
            "occurrence not in binary": (lambda d: self.npm(d, inter)["evidence"]["occurrences"].append(
                {"location": "spa/assets/index.js"}), "not in the shipped binary"),
            "lockfile label with occurrences": (lambda d: self.npm(d, inter)["properties"].__setitem__(
                0, {"name": sbom.EVIDENCE, "value": sbom.LOCKFILE}), "labeled lockfile but records verified files"),
            "artifact digest": (lambda d: d["metadata"]["component"].update(version="sha256:00"), "artifact's sha256"),
            "duplicate bom-ref": (lambda d: d["components"].append(dict(d["components"][0])), "duplicated"),
            "dangling ref": (lambda d: d["dependencies"][0]["dependsOn"].append("nowhere"), "does not resolve: nowhere"),
            "frontend edge": (lambda d: next(e for e in d["dependencies"] if e["ref"] == "file-1")["dependsOn"].remove(
                sbom.FRONTEND_REF), "does not depend on the frontend"),
        }
        for name, (change, pattern) in cases.items():
            with self.subTest(name):
                self.assertReports(change, pattern)

    def test_go_module_set_must_match_build_info(self):
        for modules in ({"example.com/mod": "v1.3.0", "stdlib": "go1.26.6"},
                        {"example.com/mod": "v1.2.0", "other.com/x": "v1", "stdlib": "go1.26.6"},
                        {"example.com/mod": "v1.2.0", "stdlib": "go1.26.5"}):
            with self.subTest(modules):
                problems = self.problems(self.good, modules)
                self.assertTrue(any("Go modules differ" in p for p in problems), problems)

    def test_vendored_schemas_match_recorded_hashes(self):
        self.assertEqual(sbom.schema_problems(), [])

    def test_real_duplicate_in_the_lockfile_agrees(self):
        # frontend/package-lock.json installs react-is@16.13.1 twice, nested
        # under hoist-non-react-statics and prop-types. The merge keeps one
        # component with both paths, which is right only while they agree.
        lock = json.loads((REPO / "frontend/package-lock.json").read_text())
        entries = sbom.runtime_entries(lock)
        groups = {}
        for path, item in entries.items():
            groups.setdefault(sbom.purl(item["name"], item["version"]), []).append(item)
        for ref, items in groups.items():
            for field in ("integrity", "license", "resolved"):
                self.assertEqual(len({i[field] for i in items}), 1, (ref, field))

    def test_combined_sbom_validates_against_cyclonedx_1_5(self):
        try:
            import fastjsonschema  # noqa: F401
        except ImportError:
            self.skipTest("fastjsonschema not installed; the release workflow installs it pinned by hash")
        self.assertEqual(sbom.validate(self.good), [])
        broken = copy.deepcopy(self.good)
        broken["components"][0]["type"] = "not-a-type"
        self.assertTrue(sbom.validate(broken))
        self.assertEqual(sbom.validate(dict(self.good, specVersion="1.7")), ["specVersion is '1.7', not 1.5"])


class WorkflowTests(unittest.TestCase):
    def test_syft_is_pinned_by_version_and_hash(self):
        text = (REPO / "packaging/sbom/install-syft.sh").read_text()
        self.assertRegex(text, r"\nSYFT_VERSION=\d+\.\d+\.\d+\n")
        self.assertRegex(text, r"\nSYFT_SHA256=[0-9a-f]{64}\n")
        self.assertIn('sha256sum -c -', text)
        self.assertIn("releases/download/v${SYFT_VERSION}/", text)
        for workflow in ("release.yml", "package-smoke.yml"):
            body = (REPO / ".github/workflows" / workflow).read_text()
            self.assertIn('bash packaging/sbom/install-syft.sh "$HOME/.local/bin"', body, workflow)
            self.assertNotIn("anchore/syft/main", body, workflow)
            self.assertNotRegex(body, r"cyclonedx-json=", workflow)
            self.assertIn("cyclonedx-json@1.5=", body, workflow)

    def test_release_and_pull_request_run_the_same_merge(self):
        script = (REPO / "packaging/sbom/merge-and-check.sh").read_text()
        self.assertIn("for art in dist/openwatch dist/openwatch-*.rpm dist/openwatch_*.deb; do", script)
        for needle in ("rpm2cpio", "dpkg-deb --fsys-tarfile", "--binary-sbom", "scripts/sbom-merge.py merge",
                       "scripts/sbom-merge.py check", "for sbom in dist/*.cdx.json; do",
                       "scripts/sbom-merge.py validate"):
            self.assertIn(needle, script)
        install = ('pip" install --quiet --require-hashes --no-deps -r packaging/sbom/requirements.txt')
        release = (REPO / ".github/workflows/release.yml").read_text()
        step = release[release.index("- name: Add frontend components to the SBOMs and verify them"):
                       release.index("- name: Checksums")]
        self.assertIn(install, step)
        self.assertIn("bash packaging/sbom/merge-and-check.sh", step)
        self.assertLess(release.index("- name: Generate CycloneDX SBOMs"), release.index("- name: Add frontend components"))
        smoke = (REPO / ".github/workflows/package-smoke.yml").read_text()
        build = smoke[smoke.index("  build:\n"):smoke.index("\n  smoke:\n")]
        self.assertIn("bash packaging/sbom/merge-and-check.sh", build)
        self.assertIn(install, build)
        self.assertLess(build.index("run: make packages"), build.index("merge-and-check.sh"))
        # The validator is installed in the one job that needs it.
        self.assertEqual(smoke.count("packaging/sbom/requirements.txt"), 1)
        for path in ("'scripts/sbom-merge.py'", "'frontend/package-lock.json'", "'packaging/**'"):
            self.assertIn(path, smoke[:smoke.index("permissions:")])

    def test_summary_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            line = sbom.summary("x.cdx.json", Fixture(tmp).merged())
        self.assertEqual(line, "x.cdx.json: CycloneDX 1.5, 9 components, 3 golang, 5 npm, "
                               "1 with bundled files verified, 8 dependency entries")

    def test_validator_requirement_is_hash_pinned(self):
        lines = [l for l in (REPO / "packaging/sbom/requirements.txt").read_text().splitlines()
                 if l and not l.startswith("#")]
        self.assertEqual(len(lines), 1)
        self.assertRegex(lines[0], r"^fastjsonschema==\d+\.\d+\.\d+ --hash=sha256:[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main(argv=sys.argv[:1] + sys.argv[1:])
