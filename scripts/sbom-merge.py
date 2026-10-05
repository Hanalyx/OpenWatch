#!/usr/bin/env python3
"""Add the frontend's npm components to an OpenWatch release SBOM, then check it.

syft scans the Go binary and the packages. It cannot see the React bundle the
binary embeds, and a package SBOM lists only the package itself. This script
adds one component per runtime (non-dev) entry of frontend/package-lock.json,
so the frontend inventory is complete against the runtime lockfile. It does not
say which JavaScript ships: Vite drops unused code, and nothing here proves
which JavaScript the bundle contains.

Each npm component says how it is known, in its properties:

  openwatch:evidence = lockfile
      A runtime lockfile entry. No claim that any of its files ship.
  openwatch:evidence = bundle-files-verified
      Some files of the installed package, at the locked version, are
      byte-identical to files in the embedded SPA, and those bytes are in the
      shipped binary. This proves those files ship, not the whole package.
      openwatch:bundle-files-verified is how many package files matched,
      openwatch:package-file-count is how many files the installed package
      has, and each openwatch:verified-file names one match as
      "<file in the package> -> <file in the SPA>". The SPA files are also
      listed as evidence occurrences.

The lockfile integrity value is the hash of the npm registry tarball the
package was installed from. It is not a hash of the installed files or of
anything that ships. It is recorded as a hash of the component's
"distribution" external reference (the tarball URL), never in the
component's own hashes, and openwatch:hash-source says so.

Uses the standard library only. `merge` writes the combined SBOM; `check`
verifies a combined SBOM against the lockfile, the shipped binary and the
artifact it describes; `validate` checks the CycloneDX 1.5 schema.
Spec system-supply-chain C-09.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

EVIDENCE = "openwatch:evidence"
LOCKFILE_PATH = "openwatch:lockfile-path"
LOCKFILE, VERIFIED = "lockfile", "bundle-files-verified"
VERIFIED_COUNT = "openwatch:bundle-files-verified"
FILE_COUNT = "openwatch:package-file-count"
VERIFIED_FILE = "openwatch:verified-file"
HASH_SOURCE = "openwatch:hash-source"
HASH_SOURCE_VALUE = "npm-registry-tarball (package-lock integrity)"
FRONTEND_REF = "openwatch-frontend"
# A matched file must be at least this large, so an empty or boilerplate file
# shared by many packages cannot verify anything.
MIN_MATCH_BYTES = 512
SPDX_ID = re.compile(r"^[A-Za-z0-9.+-]+$")


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def purl(name, version):
    return "pkg:npm/" + name.replace("@", "%40", 1) + "@" + version


def runtime_entries(lock):
    """Runtime (non-dev) lockfile entries, keyed by lockfile path."""
    if lock.get("lockfileVersion") != 3:
        raise ValueError("expected npm lockfileVersion 3")
    entries = {}
    for path, item in lock["packages"].items():
        if not path or item.get("dev") or item.get("link"):
            continue
        if not path.startswith("node_modules/"):
            raise ValueError(f"unsupported npm package path: {path}")
        name = path.rsplit("node_modules/", 1)[1]
        for field in ("version", "license", "integrity", "resolved"):
            if not item.get(field):
                raise ValueError(f"lockfile entry {path} has no {field}")
        entries[path] = dict(item, name=name)
    return entries


def resolve(lock_packages, from_path, dep):
    """Node's lookup: the nearest node_modules/<dep> walking up from from_path."""
    base = from_path
    while True:
        candidate = (base + "/" if base else "") + "node_modules/" + dep
        if candidate in lock_packages:
            return candidate
        if not base:
            return None
        cut = base.rfind("/node_modules/")
        base = base[:cut] if cut >= 0 else ""


def licenses(expression):
    if SPDX_ID.match(expression):
        return [{"license": {"id": expression}}] if expression in SPDX_IDS else [{"license": {"name": expression}}]
    return [{"expression": expression}]


def sri_to_hash(integrity):
    alg, _, b64 = integrity.split(" ")[0].partition("-")
    names = {"sha512": "SHA-512", "sha384": "SHA-384", "sha256": "SHA-256", "sha1": "SHA-1"}
    if alg not in names:
        raise ValueError(f"unsupported integrity algorithm: {alg}")
    return {"alg": names[alg], "content": base64.b64decode(b64).hex()}


def bundle_matches(entries, node_modules, bundle_dir, binary):
    """lockfile path -> (package file count, sorted (package file, SPA file) matches).

    Only packages installed at their locked version are examined. A match needs
    a package file of at least MIN_MATCH_BYTES, byte-identical to an SPA file
    whose bytes appear in the binary."""
    bundled = {}
    for path in sorted(Path(bundle_dir).rglob("*")):
        if path.is_file() and path.stat().st_size >= MIN_MATCH_BYTES:
            bundled.setdefault(sha256_file(path), []).append(path)
    blob = Path(binary).read_bytes() if binary else None
    found = {}
    for lock_path, item in entries.items():
        package_dir = Path(node_modules).parent / lock_path
        manifest = package_dir / "package.json"
        if not manifest.is_file() or read_json(manifest).get("version") != item["version"]:
            continue
        files, hits = 0, set()
        for path in package_dir.rglob("*"):
            relative = path.relative_to(package_dir)
            if "node_modules" in relative.parts or not path.is_file():
                continue
            files += 1
            for asset in bundled.get(sha256_file(path), []):
                if blob is None or asset.read_bytes() in blob:
                    hits.add((relative.as_posix(), asset.relative_to(Path(bundle_dir).parent).as_posix()))
        if hits:
            found[lock_path] = (files, sorted(hits))
    return found


def frontend_inventory(lock, node_modules, bundle_dir, binary):
    entries = runtime_entries(lock)
    matches = bundle_matches(entries, node_modules, bundle_dir, binary)
    by_purl, paths_of = {}, {}
    for lock_path in sorted(entries):
        item = entries[lock_path]
        ref = purl(item["name"], item["version"])
        paths_of.setdefault(ref, []).append(lock_path)
        if ref in by_purl:
            # The same name@version installed at two paths is one component,
            # only if the lockfile says the two copies are the same package.
            first = entries[paths_of[ref][0]]
            for field in ("integrity", "license", "resolved"):
                if first[field] != item[field]:
                    raise ValueError(f"{ref} is locked at {paths_of[ref][0]} and {lock_path} "
                                     f"with different {field}; refusing to merge them")
            continue
        group, _, short = item["name"].rpartition("/")
        component = {"bom-ref": ref, "type": "library"}
        if group:
            component["group"] = group
        component.update({
            "name": short, "version": item["version"], "scope": "optional" if item.get("optional") else "required",
            "licenses": licenses(item["license"]), "purl": ref,
            "externalReferences": [{"type": "distribution", "url": item["resolved"],
                                    "comment": "npm registry tarball; the hash is the package-lock integrity value",
                                    "hashes": [sri_to_hash(item["integrity"])]}]})
        by_purl[ref] = component
    for ref, component in by_purl.items():
        found = [matches[p] for p in paths_of[ref] if p in matches]
        pairs = sorted({pair for _, hits in found for pair in hits})
        properties = [{"name": EVIDENCE, "value": VERIFIED if pairs else LOCKFILE},
                      {"name": HASH_SOURCE, "value": HASH_SOURCE_VALUE}]
        properties += [{"name": LOCKFILE_PATH, "value": p} for p in paths_of[ref]]
        if pairs:
            properties += [{"name": VERIFIED_COUNT, "value": str(len({f for f, _ in pairs}))},
                           {"name": FILE_COUNT, "value": str(max(n for n, _ in found))}]
            properties += [{"name": VERIFIED_FILE, "value": f"{f} -> {a}"} for f, a in pairs]
            component["evidence"] = {"occurrences": [{"location": a} for a in sorted({a for _, a in pairs})]}
        component["properties"] = properties
    root = lock["packages"][""]
    dependencies = {FRONTEND_REF: sorted({purl(entries[p]["name"], entries[p]["version"])
                                          for p in (resolve(lock["packages"], "", d) for d in root.get("dependencies", {})) if p})}
    for lock_path, item in entries.items():
        refs = dependencies.setdefault(purl(item["name"], item["version"]), set())
        for dep in list(item.get("dependencies", {})) + list(item.get("optionalDependencies", {})):
            target = resolve(lock["packages"], lock_path, dep)
            if target is None:
                if dep in item.get("optionalDependencies", {}):
                    continue
                raise ValueError(f"{lock_path} depends on {dep}, which the lockfile does not resolve")
            if target in entries:
                refs.add(purl(entries[target]["name"], entries[target]["version"]))
    frontend = {"bom-ref": FRONTEND_REF, "type": "application", "name": root.get("name", "frontend"),
                "version": root.get("version", "0.0.0"), "description": "The React UI embedded in the openwatch binary",
                "properties": [{"name": EVIDENCE, "value": LOCKFILE}]}
    return [frontend] + list(by_purl.values()), {k: sorted(v) for k, v in dependencies.items()}


def merge(sbom, binary_sbom, frontend_components, frontend_dependencies):
    out = json.loads(json.dumps(sbom))
    components = out.setdefault("components", [])
    deps = {d["ref"]: list(d.get("dependsOn", [])) for d in out.get("dependencies", [])}
    known = {c["bom-ref"]: c for c in components}

    def add(component):
        ref = component["bom-ref"]
        if ref in known:
            if known[ref] != component:
                raise ValueError(f"bom-ref collision with different content: {ref}")
            return
        known[ref] = component
        components.append(component)

    def add_deps(ref, refs):
        current = deps.setdefault(ref, [])
        current.extend(r for r in refs if r not in current)

    go_root = None
    if binary_sbom is not None:
        for component in binary_sbom.get("components", []):
            add(component)
        for entry in binary_sbom.get("dependencies", []):
            add_deps(entry["ref"], entry.get("dependsOn", []))
    for entry in out.get("dependencies", []) + (binary_sbom or {}).get("dependencies", []):
        if entry["ref"].startswith("pkg:golang/github.com/hanalyx/openwatch@"):
            go_root = entry["ref"]
    for component in frontend_components:
        add(component)
    for ref, refs in frontend_dependencies.items():
        add_deps(ref, refs)
    # The artifact contains the binary's Go modules and the embedded UI. For a
    # package, its own package component carries the same edges.
    owners = [out["metadata"]["component"]["bom-ref"]] + [
        c["bom-ref"] for c in components if c.get("purl", "").startswith(("pkg:rpm/openwatch@", "pkg:deb/debian/openwatch@", "pkg:deb/openwatch@"))]
    for owner in owners:
        add_deps(owner, ([go_root] if go_root else []) + [FRONTEND_REF])
    out["dependencies"] = [{"ref": ref, "dependsOn": refs} for ref, refs in deps.items()]
    return out


def go_modules(binary):
    """Module path -> version from the binary's build info."""
    output = subprocess.check_output(["go", "version", "-m", str(binary)], text=True)
    # syft records the Go toolchain as the component "stdlib".
    modules = {"stdlib": output.splitlines()[0].rsplit(" ", 1)[-1]}
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) >= 4 and parts[1] == "dep":
            modules[parts[2]] = parts[3]
        elif len(parts) >= 4 and parts[1] == "=>":
            raise ValueError(f"replaced module needs review: {parts[2]}")
    return modules


def check(sbom, lock, artifact, binary, bundle_dir, modules):
    """Return a list of problems; empty means the SBOM passed."""
    problems = []
    components = sbom.get("components", [])
    refs = [c.get("bom-ref") for c in components]
    if None in refs or len(refs) != len(set(refs)):
        problems.append("bom-refs are missing or duplicated")
    known = set(refs) | {sbom["metadata"]["component"]["bom-ref"]}
    seen = set()
    for entry in sbom.get("dependencies", []):
        if entry["ref"] in seen:
            problems.append(f"dependency entry repeated: {entry['ref']}")
        seen.add(entry["ref"])
        for ref in [entry["ref"]] + entry.get("dependsOn", []):
            if ref not in known:
                problems.append(f"dependency ref does not resolve: {ref}")
    if sbom["metadata"]["component"].get("version") != "sha256:" + sha256_file(artifact):
        problems.append("metadata.component does not carry the artifact's sha256")
    owner_edges = {e["ref"]: set(e.get("dependsOn", [])) for e in sbom.get("dependencies", [])}
    if FRONTEND_REF not in owner_edges.get(sbom["metadata"]["component"]["bom-ref"], set()):
        problems.append("the artifact component does not depend on the frontend")
    entries = runtime_entries(lock)
    expected = {}
    for item in entries.values():
        expected[purl(item["name"], item["version"])] = item
    npm = {c["purl"]: c for c in components if c.get("purl", "").startswith("pkg:npm/")}
    for missing in sorted(set(expected) - set(npm)):
        problems.append(f"lockfile runtime component missing: {missing}")
    for extra in sorted(set(npm) - set(expected)):
        problems.append(f"npm component not in the lockfile runtime set: {extra}")
    bundle_root = Path(bundle_dir).parent
    blob = Path(binary).read_bytes()
    for ref, component in sorted(npm.items()):
        if ref not in expected:
            continue
        item = expected[ref]
        if component.get("version") != item["version"]:
            problems.append(f"{ref}: version differs from the lockfile")
        if component.get("licenses") != licenses(item["license"]):
            problems.append(f"{ref}: license differs from the lockfile")
        props = {p["name"]: p["value"] for p in component.get("properties", [])}
        if props.get(HASH_SOURCE) != HASH_SOURCE_VALUE or component.get("hashes"):
            problems.append(f"{ref}: the tarball hash must be labeled and kept out of the component's own hashes")
        distribution = [r for r in component.get("externalReferences", []) if r.get("type") == "distribution"]
        if [r.get("hashes") for r in distribution] != [[sri_to_hash(item["integrity"])]] or \
                [r.get("url") for r in distribution] != [item["resolved"]]:
            problems.append(f"{ref}: distribution reference differs from the lockfile")
        evidence = props.get(EVIDENCE)
        occurrences = [o["location"] for o in component.get("evidence", {}).get("occurrences", [])]
        verified = [p["value"].split(" -> ") for p in component.get("properties", []) if p["name"] == VERIFIED_FILE]
        if evidence == LOCKFILE and (occurrences or verified or VERIFIED_COUNT in props):
            problems.append(f"{ref}: labeled lockfile but records verified files")
        elif evidence == VERIFIED:
            if not occurrences or not verified:
                problems.append(f"{ref}: labeled {VERIFIED} with no verified files")
            if props.get(VERIFIED_COUNT) != str(len({f for f, _ in verified})):
                problems.append(f"{ref}: {VERIFIED_COUNT} does not match the verified files listed")
            if not props.get(FILE_COUNT, "").isdigit() or int(props[FILE_COUNT]) < len({f for f, _ in verified}):
                problems.append(f"{ref}: {FILE_COUNT} is missing or smaller than the verified count")
            if sorted({a for _, a in verified}) != sorted(occurrences):
                problems.append(f"{ref}: occurrences differ from the verified files")
            for location in occurrences:
                path = bundle_root / location
                if not path.is_file() or path.read_bytes() not in blob:
                    problems.append(f"{ref}: occurrence {location} is not in the shipped binary")
        elif evidence != LOCKFILE:
            problems.append(f"{ref}: evidence label is {evidence!r}")
    golang = {}
    for c in components:
        if c.get("purl", "").startswith("pkg:golang/") and c["name"] != "github.com/Hanalyx/openwatch":
            golang[c["name"]] = c["version"]
    if golang != modules:
        diff = sorted(set(golang.items()) ^ set(modules.items()))
        problems.append(f"Go modules differ from the binary's build info: {diff[:5]}")
    return problems


SCHEMA_DIR = Path(__file__).resolve().parent.parent / "packaging/sbom/schema"
SCHEMAS = ("bom-1.5.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")


def schema_problems():
    """The vendored schemas must match their recorded hashes."""
    recorded = {}
    for line in (SCHEMA_DIR / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split()
        recorded[name] = digest
    return [f"vendored schema {name} does not match SHA256SUMS" for name in SCHEMAS
            if recorded.get(name) != sha256_file(SCHEMA_DIR / name)]


def validate(sbom):
    """Validate against the vendored CycloneDX 1.5 schema. Needs fastjsonschema,
    which the release workflow installs pinned by hash
    (packaging/sbom/requirements.txt)."""
    import fastjsonschema

    problems = schema_problems()
    if problems:
        return problems
    schemas = {name: read_json(SCHEMA_DIR / name) for name in SCHEMAS}

    def local(uri):
        # The schemas refer to each other by cyclonedx.org URL; never fetch.
        return schemas[uri.rsplit("/", 1)[-1].split("#")[0]]

    validator = fastjsonschema.compile(schemas["bom-1.5.schema.json"], handlers={"http": local, "https": local})
    if sbom.get("specVersion") != "1.5":
        return [f"specVersion is {sbom.get('specVersion')!r}, not 1.5"]
    try:
        validator(sbom)
    except fastjsonschema.JsonSchemaValueException as err:
        return [f"CycloneDX 1.5 schema: {err.message}"]
    return []


def summary(name, doc):
    components = doc.get("components", [])

    def count(prefix):
        return sum(c.get("purl", "").startswith(prefix) for c in components)
    verified = sum({"name": EVIDENCE, "value": VERIFIED} in c.get("properties", []) for c in components)
    return (f"{name}: CycloneDX {doc.get('specVersion')}, {len(components)} components, "
            f"{count('pkg:golang/')} golang, {count('pkg:npm/')} npm, {verified} with bundled files verified, "
            f"{len(doc.get('dependencies', []))} dependency entries")


def load_spdx_ids():
    return frozenset(read_json(SCHEMA_DIR / "spdx.schema.json")["enum"])


SPDX_IDS = load_spdx_ids()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate").add_argument("--sbom", required=True, type=Path)
    sub.add_parser("summary").add_argument("--sbom", required=True, type=Path)
    for name in ("merge", "check"):
        p = sub.add_parser(name)
        p.add_argument("--sbom", required=True, type=Path)
        p.add_argument("--lockfile", default=Path("frontend/package-lock.json"), type=Path)
        p.add_argument("--bundle-dir", default=Path("internal/server/spa"), type=Path)
        p.add_argument("--binary", required=True, type=Path, help="the openwatch binary the artifact ships")
    m = sub.choices["merge"]
    m.add_argument("--node-modules", default=Path("frontend/node_modules"), type=Path)
    m.add_argument("--binary-sbom", type=Path, help="syft SBOM of --binary, for a package SBOM")
    m.add_argument("--out", required=True, type=Path)
    sub.choices["check"].add_argument("--artifact", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.command == "summary":
        print(summary(args.sbom, read_json(args.sbom)))
        return 0
    if args.command == "validate":
        problems = validate(read_json(args.sbom))
        for problem in problems:
            print(f"{args.sbom}: {problem}", file=sys.stderr)
        if not problems:
            print(f"{args.sbom}: valid CycloneDX 1.5")
        return 1 if problems else 0
    lock = read_json(args.lockfile)
    if args.command == "merge":
        components, dependencies = frontend_inventory(lock, args.node_modules, args.bundle_dir, args.binary)
        merged = merge(read_json(args.sbom), read_json(args.binary_sbom) if args.binary_sbom else None, components, dependencies)
        args.out.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
        verified = sum(1 for c in components if {"name": EVIDENCE, "value": VERIFIED} in c.get("properties", []))
        print(f"{args.out}: {len(components) - 1} npm components (complete against the runtime lockfile), "
              f"{verified} with bundled files verified")
        return 0
    problems = check(read_json(args.sbom), lock, args.artifact, args.binary, args.bundle_dir, go_modules(args.binary))
    for problem in problems:
        print(f"{args.sbom}: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"{args.sbom}: checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
