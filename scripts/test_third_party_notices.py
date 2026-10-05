#!/usr/bin/env python3
"""Exercise inventory failures, upstream bytes and real package staging."""

import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("notices", REPO / "scripts/third-party-notices.py")
notices = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(notices)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.frontend = self.root / "frontend"
        self.frontend.mkdir()
        self.go = self.root / "module"
        self.go.mkdir()
        (self.go / "LICENSE").write_text("Upstream license and copyright\n")
        self.modules = {"example.org/module": {"version": "v1.0.0", "directory": str(self.go)}}
        self.reviewed = {"example.org/module": {"version": "v1.0.0", "license": "MIT", "files": {
            "LICENSE": notices.digest((self.go / "LICENSE").read_bytes())}}}
        for relative in notices.INPUTS:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}\n")
        (self.root / notices.REVIEW).write_text(json.dumps(self.reviewed))
        self.package = {"version": "1.0.0", "license": "OFL-1.1", "integrity": "sha512-fixture"}
        self.lock = {"lockfileVersion": 3, "packages": {"": {},
                     "node_modules/@fontsource/inter": self.package,
                     "node_modules/tool": {**self.package, "dev": True},
                     "node_modules/tool/node_modules/shared": {**self.package, "version": "2.0.0", "dev": True},
                     "node_modules/@platform/optional": {**self.package, "optional": True}}}
        (self.frontend / "package-lock.json").write_text(json.dumps(self.lock))
        for entry in notices.npm_entries(self.lock):
            if entry.get("optional"):
                continue
            directory = self.frontend / entry["path"]
            directory.mkdir(parents=True)
            (directory / "package.json").write_text(json.dumps({"name": entry["name"], "version": entry["version"]}))
            if not entry.get("dev"):
                (directory / "LICENSE").write_bytes(b"SIL OPEN FONT LICENSE Version 1.1\nCopyright fixture\n")
        self.entries = notices.npm_entries(self.lock)

    def collect(self):
        def command(root, *args, **kwargs):
            if args == ("go", "env", "GOROOT"):
                return str(self.go)
            return "fixture"
        with patch.object(notices, "run", side_effect=command):
            return notices.bundle_data(self.root, self.frontend, self.modules, self.entries)

    def test_scoped_nested_optional_and_tooling(self):
        result = notices.render(self.root, self.reviewed, self.entries)
        self.assertEqual(result, notices.render(self.root, self.reviewed, list(self.entries)))
        for item in self.entries:
            self.assertIn(item["path"], result)
        runtime, tooling = result.split("## Frontend build and test dependencies")
        self.assertIn("@fontsource/inter", runtime)
        self.assertIn("node_modules/shared", tooling)
        self.assertIn("2.0.0", tooling)
        self.assertNotIn("node_modules/tool", runtime)

    def test_go_license_and_version_mutations_fail(self):
        notices.verified_go(self.root, self.modules)
        self.modules["example.org/module"]["version"] = "v2.0.0"
        with self.assertRaisesRegex(ValueError, "new Go license version"):
            notices.verified_go(self.root, self.modules)
        self.modules["example.org/module"]["version"] = "v1.0.0"
        (self.go / "LICENSE").write_text("Changed license")
        with self.assertRaisesRegex(ValueError, "license text changed"):
            notices.verified_go(self.root, self.modules)

    def test_unknown_go_module_fails(self):
        self.modules["example.org/new"] = self.modules["example.org/module"]
        with self.assertRaisesRegex(ValueError, "Linked Go modules differ"):
            notices.verified_go(self.root, self.modules)

    def test_preserves_font_and_nested_notice_bytes(self):
        nested = self.go / "vendor/component"
        nested.mkdir(parents=True)
        (nested / "NOTICE").write_bytes(b"Nested copyright\r\n")
        text, manifest = self.collect()
        self.assertIn(b"SIL OPEN FONT LICENSE Version 1.1\nCopyright fixture\n", text)
        self.assertIn(b"Nested copyright\r\n", text)
        self.assertEqual(manifest["optional_not_installed"], ["node_modules/@platform/optional"])
        self.assertFalse(any("npm:node_modules/tool" in item["component"] for item in manifest["sources"]))

    def test_stale_installed_version_fails_even_for_tooling(self):
        path = self.frontend / "node_modules/tool/package.json"
        path.write_text(json.dumps({"name": "tool", "version": "0.1.0"}))
        with self.assertRaisesRegex(ValueError, "Stale installed dependency"):
            self.collect()

    def test_missing_runtime_text_fails(self):
        (self.frontend / "node_modules/@fontsource/inter/LICENSE").unlink()
        with self.assertRaisesRegex(ValueError, "No upstream license text"):
            self.collect()

    def test_missing_required_package_fails(self):
        shutil.rmtree(self.frontend / "node_modules/@fontsource/inter")
        with self.assertRaisesRegex(ValueError, "Missing installed dependency"):
            self.collect()

    def test_missing_lock_license_fails(self):
        del self.package["license"]
        with self.assertRaisesRegex(ValueError, "Incomplete locked metadata"):
            notices.npm_entries(self.lock)

    def test_generated_inventory_mutation_fails(self):
        document = notices.render(self.root, self.reviewed, self.entries)
        (self.root / "THIRD-PARTY-NOTICES.md").write_text(document)
        with patch.object(notices, "ROOT", self.root), patch.object(notices, "go_modules", return_value=self.modules), patch.object(sys, "argv", ["notices", "--check"]):
            notices.main()
            (self.root / "THIRD-PARTY-NOTICES.md").write_text(document.replace("OFL-1.1", "MIT"))
            with self.assertRaisesRegex(ValueError, "is stale"):
                notices.main()


class PackagingTests(unittest.TestCase):
    def test_callers(self):
        workflow = (REPO / ".github/workflows/go-ci.yml").read_text()
        self.assertIn("run: make license-bundle", workflow)
        pattern = re.search(r"grep -qE '([^']+)'", workflow).group(1)
        self.assertIsNotNone(re.search(pattern, "THIRD-PARTY-NOTICES.md"))
        self.assertIsNone(re.search(pattern, "README.md"))
        self.assertLess(workflow.index("run: npm ci"), workflow.index("run: make license-bundle"))
        # The step must not carry a condition on a step id its job does not have: an
        # undefined steps.<id> output is empty, so the check would be skipped silently.
        step = re.search(r"- name: Verify third-party notices and license texts\n((?:        .*\n)+)", workflow).group(1)
        self.assertNotIn("steps.", step)
        self.assertIn("--check --bundle $(DIST_DIR)/licenses", (REPO / "Makefile").read_text())
        for kind in ("rpm", "deb"):
            text = (REPO / f"packaging/{kind}/build-{kind}.sh").read_text()
            self.assertIn("\nmake license-bundle\n", text)
            self.assertIn('"$DIST_DIR/licenses', text)

    def build_package(self, kind):
        required = ("rpmbuild", "rpm", "rpm2cpio", "cpio") if kind == "rpm" else ("dpkg-deb",)
        if any(shutil.which(tool) is None for tool in required):
            self.skipTest(f"{kind} package inspection tools not installed")
        with tempfile.TemporaryDirectory(prefix="openwatch-license-package-") as tmp:
            root = Path(tmp)
            shutil.copytree(REPO / "packaging", root / "packaging")
            # kensa-version.sh reads the linked Kensa version from go.mod.
            for name in ("go.mod", "go.sum"):
                shutil.copy2(REPO / name, root / name)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            # Only compilation and collection are fixtures. Staging and packagers are real.
            maker = bin_dir / "make"
            maker.write_text('#!/bin/sh\nset -eu\nmkdir -p dist\ncase "$1" in\n'
                             'build) cp /bin/true dist/openwatch ;;\n'
                             'license-bundle) cp -R fixtures/licenses dist/licenses ;;\n'
                             '*) exit 97 ;;\nesac\n')
            maker.chmod(0o755)
            fixture = root / "fixtures/licenses"
            fixture.mkdir(parents=True)
            files = {name: f"fixture {name}\n".encode() for name in (
                "LICENSE", "THIRD-PARTY-NOTICES.md", "THIRD-PARTY-LICENSES.txt", "license-manifest.json")}
            for name, data in files.items():
                (fixture / name).write_bytes(data)
            env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
                       ARCH="amd64", VERSION="0.8.0-rc.99")
            result = subprocess.run(["bash", f"packaging/{kind}/build-{kind}.sh"], cwd=root,
                                    env=env, capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            package = next((root / "dist").glob(f"*.{kind}"))
            unpack = root / "unpacked"
            unpack.mkdir()
            if kind == "deb":
                subprocess.run(["dpkg-deb", "-x", str(package), str(unpack)], check=True)
            else:
                archive = subprocess.run(["rpm2cpio", str(package)], check=True, capture_output=True).stdout
                subprocess.run(["cpio", "-idm", "--quiet"], cwd=unpack, input=archive, check=True)
            for name, data in files.items():
                self.assertEqual((unpack / "usr/share/licenses/openwatch" / name).read_bytes(), data)

    def test_rpm_payload(self):
        self.build_package("rpm")

    def test_deb_payload(self):
        self.build_package("deb")


if __name__ == "__main__":
    unittest.main()
