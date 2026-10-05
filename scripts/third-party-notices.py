#!/usr/bin/env python3
"""Generate the dependency inventory and collect upstream license texts.

Uses the standard library only. Never installs packages or runs npm scripts.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
REVIEW = "packaging/third-party-go-licenses.json"
INPUTS = ("go.mod", "go.sum", "frontend/package.json", "frontend/package-lock.json", REVIEW)
LICENSE_NAME = re.compile(r"^(licen[cs]e|copying|copyright|notice)([._-]|$)", re.I)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def run(root, *args, env=None):
    return subprocess.check_output(args, cwd=root, env=env, text=True).strip()


def go_modules(root):
    """Union of linked modules for both released Linux architectures."""
    modules = {}
    for arch in ("amd64", "arm64"):
        env = dict(os.environ, GOOS="linux", GOARCH=arch, CGO_ENABLED="0", GOFLAGS="-mod=readonly")
        output = run(root, "go", "list", "-deps", "-f",
                     '{{with .Module}}{{if not .Main}}{{.Path}}\t{{.Version}}\t{{.Dir}}\t{{if .Replace}}replaced{{end}}{{end}}{{end}}',
                     "./cmd/openwatch", env=env)
        for line in output.splitlines():
            if not line.strip():
                continue
            parts = line.split("\t")
            name, version, directory = parts[:3]
            if len(parts) > 3 and parts[3]:
                raise ValueError(f"Review replacement module before release: {name}")
            item = {"version": version, "directory": directory}
            if name in modules and modules[name] != item:
                raise ValueError(f"Module differs between build targets: {name}")
            modules[name] = item
    return modules


def verified_go(root, modules):
    reviewed = read_json(root / REVIEW)
    if set(modules) != set(reviewed):
        raise ValueError("Linked Go modules differ from the reviewed license inventory; review " + REVIEW)
    for name, module in modules.items():
        entry = reviewed[name]
        if module["version"] != entry["version"]:
            raise ValueError(f"Review the new Go license version: {name}")
        for relative, expected in entry["files"].items():
            path = Path(module["directory"]) / relative
            if digest(path.read_bytes()) != expected:
                raise ValueError(f"Reviewed license text changed: {name}/{relative}")
    return reviewed


def npm_entries(lock):
    if lock.get("lockfileVersion") != 3:
        raise ValueError("Expected npm lockfileVersion 3")
    entries = []
    for path, item in sorted(lock["packages"].items()):
        if not path:
            continue
        if not path.startswith("node_modules/") or ".." in Path(path).parts or item.get("link"):
            raise ValueError(f"Unsupported npm package path: {path}")
        name = path.rsplit("node_modules/", 1)[1]
        if not item.get("license") or not item.get("version") or not item.get("integrity"):
            raise ValueError(f"Incomplete locked metadata: {path}")
        entries.append({"path": path, "name": name, **item})
    return entries


def render(root, reviewed, entries):
    lines = [
        "# Third-party notices for OpenWatch", "",
        "This inventory covers third-party open-source and source-available components.",
        "It is generated from the dependency inputs below, not from a developer's installed tree.", "",
        "## Scope and license terms", "",
        "OpenWatch's own terms are in [LICENSE](LICENSE). Each dependency keeps its own terms.",
        "The tables are an index, not a substitute for the upstream license and notice texts.", "",
        "The Go table covers modules linked for Linux amd64 and arm64 with CGO disabled.",
        "Its labels describe reviewed module-level licenses; upstream notices may name other terms.",
        "For example, modernc.org/libc carries notices for code from musl and other sources.",
        "The Go runtime's license is also included in the package license bundle.", "",
        "Separate packages, such as kensa-rules and PostgreSQL, are outside this inventory.", "",
        "Kensa uses Business Source License 1.1 (SPDX: BUSL-1.1), a source-available license.",
        "Its pinned license defines a Compliance Scanning Service restriction and an additional",
        "grant for individuals or organizations with annual revenue below USD 5,000,000,",
        "allowing use for any purpose, including commercial use. Its stated Change Date is",
        "2029-01-01 and Change License is Apache-2.0. Read the full pinned terms, including",
        "the effective-date clause, before redistributing or offering a hosted service.", "",
        "The frontend tables cover the full lockfile, including scoped, nested and optional",
        "packages for other platforms. Runtime candidates are not proof of bundle inclusion:",
        "Vite can omit unused code. Build/test-only means npm marks the entry as dev-only.",
        "The Inter and JetBrains Mono fonts are bundled assets under OFL-1.1.", "",
        "RPM and DEB builds install this inventory, OpenWatch's LICENSE, and",
        "THIRD-PARTY-LICENSES.txt under /usr/share/licenses/openwatch/.",
        "The bundle preserves upstream license, copyright and notice files for linked Go",
        "modules and installed frontend runtime candidates. Build/test dependencies are",
        "inventoried separately; their license texts are not shipped in this bundle.",
        "Optional packages absent from the build platform are listed in the inventory but",
        "not copied into the bundle. license-manifest.json records bundled sources, hashes,",
        "the source commit and the dependency inputs used for that build.", "",
        "## Dependency inputs", "",
        "Content hashes identify the inputs without a date that changes on each run.", "",
        "| Input | SHA-256 |", "|---|---|",
    ]
    for path in INPUTS:
        lines.append(f"| `{path}` | `{digest((root / path).read_bytes())}` |")
    lines += ["", "## Go modules", "", "| Module | Version | Module-level license |", "|---|---|---|"]
    for name, item in sorted(reviewed.items()):
        lines.append(f"| `{name}` | {item['version']} | {item['license']} |")
    for dev, title in ((False, "Frontend runtime candidates"), (True, "Frontend build and test dependencies")):
        lines += ["", f"## {title}", "", "Paths retain nested versions and optional platform packages.", "",
                  "| Lockfile path | Version | Declared license | Optional |", "|---|---|---|---|"]
        for item in entries:
            if bool(item.get("dev")) == dev:
                lines.append(f"| `{item['path']}` | {item['version']} | {item['license']} | {'yes' if item.get('optional') else 'no'} |")
    lines += ["", "## Regeneration", "",
              "Run `make notices` to update this file. Run `make check-notices` to check for drift.",
              "Both commands need the Go toolchain and cached modules, but do not read node_modules.",
              "A Go module change requires review of its license texts and the versioned hashes in",
              f"`{REVIEW}`. Unknown modules or changed license bytes stop generation.", "",
              "Run `npm ci --ignore-scripts --no-audit --no-fund` in a clean frontend directory",
              "before `make license-bundle`. Package builds run the bundle check themselves.",
              "The check rejects stale installed versions, missing non-optional dependencies and",
              "missing license text. It never downloads a guessed license or substitutes a label",
              "for the upstream text. To audit a separate clean install, use", "",
              "```bash",
              "python3 -S scripts/third-party-notices.py --check \\",
              "  --bundle dist/licenses --frontend-root /path/to/clean/frontend",
              "```", "",
              "CI checks inventory drift and builds the license bundle after npm ci.",
              "Do not edit generated rows by hand or infer release contents from a stale install.", ""]
    return "\n".join(lines)


def license_files(directory):
    """Keep upstream bytes, including nested licenses and bundled-code notices."""
    found = []
    for base, dirs, files in os.walk(directory, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in ("node_modules", ".git") and not (Path(base) / d).is_symlink())
        for name in sorted(files):
            path = Path(base) / name
            relative = path.relative_to(directory)
            if LICENSE_NAME.match(name) or any(p.lower() in ("licenses", "licences") for p in relative.parts[:-1]):
                if path.is_symlink() or not path.is_file():
                    raise ValueError(f"Not a regular license file: {path}")
                data = path.read_bytes()
                if data.strip():
                    found.append((relative.as_posix(), data))
    if not found:
        raise ValueError(f"No upstream license text found: {directory}")
    return found


def bundle_data(root, frontend, modules, entries):
    for name in ("package.json", "package-lock.json"):
        if (frontend / name).read_bytes() != (root / "frontend" / name).read_bytes():
            raise ValueError(f"Frontend audit input differs from repository: {name}")
    texts, sources, absent = [], [], []

    def collect(component, directory):
        for path, data in license_files(directory):
            texts.extend([f"\n===== {component} / {path} =====\n\n".encode(), data, b"\n"])
            sources.append({"component": component, "file": path, "sha256": digest(data)})

    for name, item in sorted(modules.items()):
        collect(f"go:{name}@{item['version']}", Path(item["directory"]))
    goroot = Path(run(root, "go", "env", "GOROOT"))
    # The toolchain contains source for unused platforms too; retain all its notices.
    collect("go-toolchain:" + run(root, "go", "env", "GOVERSION"), goroot)
    for item in entries:
        directory = frontend / item["path"]
        if not directory.exists():
            if item.get("optional"):
                absent.append(item["path"])
                continue
            raise ValueError(f"Missing installed dependency: {item['path']}; run npm ci")
        if directory.is_symlink():
            raise ValueError(f"Linked dependency is not a clean npm install: {item['path']}")
        installed = read_json(directory / "package.json")
        if installed.get("name") != item["name"] or installed.get("version") != item["version"]:
            raise ValueError(f"Stale installed dependency: {item['path']}; run npm ci")
        if item.get("dev"):
            continue
        collect(f"npm:{item['path']}@{item['version']}", directory)
    manifest = {"source_commit": run(root, "git", "rev-parse", "HEAD"),
                "tracked_tree_dirty": bool(run(root, "git", "status", "--porcelain", "--untracked-files=no")),
                "inputs": {p: digest((root / p).read_bytes()) for p in INPUTS},
                "optional_not_installed": absent, "sources": sources}
    return b"".join(texts), manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--frontend-root", type=Path, default=ROOT / "frontend")
    args = parser.parse_args()
    modules = go_modules(ROOT)
    reviewed = verified_go(ROOT, modules)
    entries = npm_entries(read_json(ROOT / "frontend/package-lock.json"))
    document = render(ROOT, reviewed, entries)
    notices = ROOT / "THIRD-PARTY-NOTICES.md"
    if args.write:
        notices.write_text(document, encoding="utf-8")
    elif notices.read_text(encoding="utf-8") != document:
        raise ValueError("THIRD-PARTY-NOTICES.md is stale; run make notices")
    if args.bundle:
        # Validate every input before touching a previous output bundle.
        text, manifest = bundle_data(ROOT, args.frontend_root, modules, entries)
        args.bundle.mkdir(parents=True, exist_ok=True)
        (args.bundle / "THIRD-PARTY-LICENSES.txt").write_bytes(text)
        (args.bundle / "THIRD-PARTY-NOTICES.md").write_text(document, encoding="utf-8")
        (args.bundle / "LICENSE").write_bytes((ROOT / "LICENSE").read_bytes())
        manifest["bundle_sha256"] = digest(text)
        manifest["notices_sha256"] = digest(document.encode())
        (args.bundle / "license-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"License bundle: {len(manifest['sources'])} upstream files")
    print(f"Notices verified: {len(modules)} Go modules, {len(entries)} npm lockfile entries")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"third-party-notices: {exc}", file=sys.stderr)
        sys.exit(1)
