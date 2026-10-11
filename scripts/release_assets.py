#!/usr/bin/env python3
"""Verify a release's assets against its candidate commit, read-only.

    python3 -S scripts/release_assets.py --tag vX.Y.Z --commit <40-hex> \\
        --key <40-hex fingerprint> --evidence DIR [--from DOWNLOADED_DIR]

Every expectation is read from the candidate commit, never typed:
VERSION from packaging/version.env, the Go toolchain and module versions from
go.mod, the kensa module version from go.mod, the release key from
security/KEYS, and the notices from THIRD-PARTY-NOTICES.md. The assets come
from the release (draft or published) with `gh release download`, or from a
directory already downloaded (--from).

Checks, all run and all reported; the exit status is 0 only if every one
passes:

  release   the tag on origin names the commit; with a download, each asset's
            sha256 matches the digest GitHub reports for it
  manifest  SHA256SUMS lists exactly the package and SBOM assets, each once,
            and every file matches its entry; the KEYS asset equals
            security/KEYS at the commit
  signature SHA256SUMS.asc is a good signature by the release key, which is a
            primary key in security/KEYS at the commit (a throwaway GnuPG home)
  rpm       every RPM's header signature and digests verify against that key
            (a throwaway rpm database)
  binary    each openwatch package's /usr/bin/openwatch: `go version -m`
            reports go.mod's toolchain, vcs.revision = the commit,
            vcs.modified=false, ldflags Version and Commit, the package's
            architecture, and every dependency at go.mod's version
  vulns     `govulncheck -mode=binary` on each binary finds no vulnerability
            in code the binary calls (findings only in required modules are
            reported, not failed)
  notices   each openwatch package ships LICENSE, THIRD-PARTY-LICENSES.txt,
            license-manifest.json and a THIRD-PARTY-NOTICES.md identical to
            the commit's
  inventory every asset declared in release/assets.toml at the commit is present
            (each package by architecture, its SBOM, and the required files),
            and nothing undeclared is; kensa-rules is named by go.mod's version
  sbom      each package has a CycloneDX SBOM whose subject is that package's
            file and sha256; openwatch SBOMs list Go modules at go.mod's
            versions

Every external command runs through scripts/evidence_capture.py with an
explicit timeout, so its raw stdout, stderr and exit status are kept under
DIR/captures. The derived results are DIR/report.json and DIR/REPORT.md. The
tool reads the release and changes nothing: no upload, edit, tag or publish.

Spec: release-asset-verification.
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

REPO_SLUG = "Hanalyx/OpenWatch"
_SHA = re.compile(r"^[0-9a-f]{40}$")
_FPR = re.compile(r"^[0-9A-F]{40}$")
_TAG = re.compile(r"^v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$")

# Explicit timeouts, in seconds, for every command this tool runs.
TIMEOUTS = {"download": 1800, "gh": 120, "git": 120, "gpg": 120, "rpm": 120,
            "extract": 300, "go": 120, "govulncheck": 600}

# Every area must report at least one check; an area that could not run is a
# failure, never a silent pass.
AREAS = ("release", "inventory", "manifest", "signature", "rpm", "binary", "vulns",
         "notices", "sbom")

INVENTORY = "release/assets.toml"

# What each openwatch package must ship under /usr/share/licenses/openwatch.
LICENSE_FILES = ("LICENSE", "THIRD-PARTY-LICENSES.txt", "THIRD-PARTY-NOTICES.md",
                 "license-manifest.json")

ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}


class AssetError(Exception):
    """The run could not proceed at all (bad input, unreadable commit)."""


class Tools(object):
    """External programs, by name. Tests replace entries with fakes."""

    def __init__(self, **over):
        self.cmd = {n: n for n in ("gh", "git", "gpg", "rpm", "rpm2cpio", "cpio",
                                   "dpkg-deb", "go", "govulncheck")}
        self.cmd.update(over)


class Run(object):
    def __init__(self, a, tools):
        self.tag, self.commit, self.key = a.tag, a.commit, a.key
        self.repo = os.path.abspath(a.repo)
        self.tools = tools
        self.out = os.path.abspath(a.evidence)
        self.captures = os.path.join(self.out, "captures")
        self.results = []
        self.notes = []
        self.n = 0
        self.inventory_from_tree = getattr(a, "inventory_from_tree", False)

    # -- running things --------------------------------------------------

    def capture(self, name, argv, kind, stdin_file=None, cwd=None):
        """Run one command through the capture library; return its record."""
        self.n += 1
        cap = "%03d-%s" % (self.n, re.sub(r"[^A-Za-z0-9._-]", "_", name))[:120]
        try:
            rec = ec.capture(argv, self.captures, cap, self.tag, self.commit,
                             timeout=TIMEOUTS[kind], stdin_file=stdin_file,
                             cwd=cwd or self.repo, purpose="release asset check: " + name)
        except ec.CaptureIncomplete as e:
            rec = dict(e.record, path=e.path)
        rec.setdefault("path", os.path.join(self.captures, cap))
        return rec

    def stdout(self, rec):
        with open(os.path.join(rec["path"], "stdout"), "rb") as f:
            return f.read()

    def ok(self, rec):
        return rec.get("status") == ec.COMPLETE and rec["exit"].get("code") == 0

    def check(self, area, subject, ok, detail, evidence=None):
        self.results.append({"area": area, "subject": subject, "ok": bool(ok),
                             "detail": detail, "evidence": evidence})

    def git_show(self, path):
        r = subprocess.run([self.tools.cmd["git"], "show", "%s:%s" % (self.commit, path)],
                           cwd=self.repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode != 0:
            raise AssetError("%s does not exist at %s" % (path, self.commit))
        return r.stdout


# -- expectations, read from the commit -------------------------------------

def expectations(run):
    version = None
    for line in run.git_show("packaging/version.env").decode().splitlines():
        if line.strip().startswith("VERSION="):
            version = line.split("=", 1)[1].strip().strip("\"'")
    m = _TAG.match(run.tag)
    if not version or not m or m.group(1) != version:
        raise AssetError("tag %s does not match VERSION=%r at %s" % (run.tag, version, run.commit))
    gomod = run.git_show("go.mod").decode()
    go = None
    requires = {}
    in_block = False
    for line in gomod.splitlines():
        s = line.split("//")[0].strip()
        if s.startswith("go "):
            go = go or "go" + s.split()[1]
        elif s.startswith("toolchain "):
            go = s.split()[1]
        elif s.startswith("require ("):
            in_block = True
        elif in_block and s == ")":
            in_block = False
        elif in_block and len(s.split()) >= 2:
            requires[s.split()[0]] = s.split()[1]
        elif s.startswith("require ") and len(s.split()) >= 3:
            requires[s.split()[1]] = s.split()[2]
    if not go:
        raise AssetError("go.mod at %s declares no go version" % run.commit)
    exp = {"version": version, "go": go, "requires": requires,
           "kensa": (requires.get("github.com/Hanalyx/kensa") or "").lstrip("v"),
           "keys": run.git_show("security/KEYS"),
           "notices": run.git_show("THIRD-PARTY-NOTICES.md")}
    exp["inventory"], exp["inventory_source"] = inventory(run, exp)
    return exp


def inventory(run, exp):
    """The assets this release must carry, from release/assets.toml.

    Read at the candidate commit. With --inventory-from-tree (for a candidate
    that predates the file) it is read from this tool's own tree instead, and
    the report says so. Returns (inventory or None, source description).
    """
    if run.inventory_from_tree:
        path = _here.parent / INVENTORY
        raw, source = path.read_bytes(), "this tool's tree (%s), not the candidate" % path
    else:
        try:
            raw, source = run.git_show(INVENTORY), "%s at the candidate commit" % INVENTORY
        except AssetError:
            return None, "%s does not exist at %s" % (INVENTORY, run.commit)
    data = tomllib.loads(raw.decode())
    name_version = exp["version"].replace("-", ".", 1)
    pkgs = []
    for p in data.get("package", []):
        pkgs.append({"file": p["file"].format(version=name_version, kensa=exp["kensa"]),
                     "binary": bool(p.get("binary"))})
    files = data.get("files", {})
    return ({"packages": pkgs, "required": list(files.get("required", [])),
             "optional": list(files.get("optional", []))}, source)


# -- checks -----------------------------------------------------------------

def read(path):
    with open(path, "rb") as f:
        return f.read()


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(run, assets, src):
    """Fill `assets` from the release, or record what --from holds."""
    if src:
        return {}
    os.makedirs(assets)
    rec = run.capture("gh-release-download", [run.tools.cmd["gh"], "release", "download",
                                              run.tag, "--repo", REPO_SLUG, "--dir", assets],
                      "download")
    run.check("release", "download", run.ok(rec), "gh release download " + run.tag, rec["path"])
    rec = run.capture("gh-release-assets", [run.tools.cmd["gh"], "api", "--paginate",
                                            "repos/%s/releases" % REPO_SLUG], "gh")
    digests = {}
    if run.ok(rec):
        releases = json.loads(run.stdout(rec) or b"[]")
        mine = [r for r in releases if r.get("tag_name") == run.tag]
        run.check("release", "release record", len(mine) == 1,
                  "%d release(s) use %s" % (len(mine), run.tag), rec["path"])
        for r in mine[:1]:
            for a in r.get("assets", []):
                digests[a["name"]] = (a.get("digest") or "").replace("sha256:", "")
    else:
        run.check("release", "release record", False, "could not list releases", rec["path"])
    return digests


def check_release(run, assets, digests):
    rec = run.capture("git-ls-remote-tag", [run.tools.cmd["git"], "ls-remote", "origin",
                                            "refs/tags/%s^{}" % run.tag], "git")
    peeled = run.stdout(rec).decode().split("\t")[0].strip()
    run.check("release", "tag on origin", run.ok(rec) and peeled == run.commit,
              "refs/tags/%s^{} on origin is %r" % (run.tag, peeled or None), rec["path"])
    for name, want in sorted(digests.items()):
        p = os.path.join(assets, name)
        got = sha256(p) if os.path.isfile(p) else None
        run.check("release", name, bool(want) and got == want,
                  "GitHub digest %s, downloaded %s" % (want or "missing", got))


def check_inventory(run, assets, exp):
    """Every declared asset is present, and nothing undeclared is."""
    inv = exp["inventory"]
    if inv is None:
        run.check("inventory", INVENTORY, False, exp["inventory_source"] +
                  "; completeness cannot be shown. For a candidate that predates the file, "
                  "pass --inventory-from-tree")
        return
    run.check("inventory", "source", True, exp["inventory_source"])
    present = set(os.listdir(assets))
    expected = [p["file"] for p in inv["packages"]] + [
        p["file"] + ".cdx.json" for p in inv["packages"]] + inv["required"]
    for f in expected:
        run.check("inventory", f, f in present, "present" if f in present else "missing")
    extra = sorted(present - set(expected) - set(inv["optional"]))
    run.check("inventory", "unexpected assets", not extra, ", ".join(extra) or "none")
    for f in inv["optional"]:
        if f in present:
            run.notes.append("%s is present; this tool does not verify it" % f)


def check_manifest(run, assets, exp):
    files = sorted(os.listdir(assets))
    sums_path = os.path.join(assets, "SHA256SUMS")
    if not os.path.isfile(sums_path):
        run.check("manifest", "SHA256SUMS", False, "SHA256SUMS is not among the assets")
        return {}
    listed = {}
    bad = []
    for line in read(sums_path).decode("utf-8", "replace").splitlines():
        m = re.match(r"^([0-9a-f]{64})  (\S+)$", line)
        if not m or m.group(2) in listed:
            bad.append(line)
            continue
        listed[m.group(2)] = m.group(1)
    run.check("manifest", "SHA256SUMS format", not bad and listed,
              "%d entries%s" % (len(listed), "; bad lines: %r" % bad[:3] if bad else ""))
    inv = exp["inventory"]
    if inv is None:
        expected = set(f for f in files if f not in ("SHA256SUMS", "SHA256SUMS.asc", "KEYS")
                       and not f.endswith(".cosign.sig"))
    else:
        expected = set(p["file"] for p in inv["packages"]) | set(
            p["file"] + ".cdx.json" for p in inv["packages"]) | (
            set(inv["required"]) - {"SHA256SUMS", "SHA256SUMS.asc", "KEYS"})
    run.check("manifest", "coverage", set(listed) == expected,
              "unlisted: %s; listed but absent: %s" % (
                  sorted(expected - set(listed)) or "none",
                  sorted(set(listed) - expected) or "none"))
    for name, want in sorted(listed.items()):
        p = os.path.join(assets, name)
        got = sha256(p) if os.path.isfile(p) else None
        run.check("manifest", name, got == want, "listed %s, file %s" % (want, got))
    keys = os.path.join(assets, "KEYS")
    same = os.path.isfile(keys) and read(keys) == exp["keys"]
    run.check("manifest", "KEYS", same, "the KEYS asset %s security/KEYS at the commit" % (
        "equals" if same else "differs from or is missing beside"))
    return listed


def check_signature(run, assets, exp):
    home = os.path.join(run.out, "gnupg")
    os.makedirs(home, mode=0o700)
    keys = os.path.join(run.out, "KEYS.from-commit")
    with open(keys, "wb") as f:
        f.write(exp["keys"])
    env_gpg = [run.tools.cmd["gpg"], "--homedir", home, "--batch"]
    rec = run.capture("gpg-keys-show", env_gpg + ["--with-colons", "--import-options",
                                                  "show-only", "--import", keys], "gpg")
    primaries = []
    want = False
    for line in run.stdout(rec).decode().splitlines():
        f = line.split(":")
        if f[0] == "pub":
            want = True
        elif f[0] == "fpr" and want:
            primaries.append(f[9])
            want = False
        elif f[0] == "sub":
            want = False
    run.check("signature", "release key", run.key in primaries,
              "%s %s a primary key in security/KEYS at the commit"
              % (run.key, "is" if run.key in primaries else "is not"), rec["path"])
    run.capture("gpg-import", env_gpg + ["--import", keys], "gpg")
    rec = run.capture("gpg-verify-sha256sums",
                      env_gpg + ["--status-fd", "1", "--verify",
                                 os.path.join(assets, "SHA256SUMS.asc"),
                                 os.path.join(assets, "SHA256SUMS")], "gpg")
    valid = [l.split() for l in run.stdout(rec).decode().splitlines()
             if l.startswith("[GNUPG:] VALIDSIG ")]
    good = run.ok(rec) and valid and run.key in (valid[0][2], valid[0][-1])
    run.check("signature", "SHA256SUMS.asc", good,
              "VALIDSIG from %s" % (valid[0][-1] if valid else "nobody"), rec["path"])
    # gpg may have started an agent or keyboxd for the throwaway home; stop
    # them so nothing keeps running after the run.
    subprocess.run(["gpgconf", "--homedir", home, "--kill", "all"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return keys


def check_rpms(run, assets, keys, exp):
    inv = exp["inventory"]
    rpms = (sorted(p["file"] for p in inv["packages"] if p["file"].endswith(".rpm")) if inv
            else sorted(f for f in os.listdir(assets) if f.endswith(".rpm")))
    db = os.path.join(run.out, "rpmdb")
    os.makedirs(db)
    rec = run.capture("rpm-import-keys", [run.tools.cmd["rpm"], "--dbpath", db, "--import", keys],
                      "rpm")
    run.check("rpm", "keyring", run.ok(rec), "imported security/KEYS into a throwaway rpm database",
              rec["path"])
    for name in rpms:
        if not os.path.isfile(os.path.join(assets, name)):
            run.check("rpm", name, False, "could not run: the package is missing")
            continue
        rec = run.capture("rpm-K-" + name, [run.tools.cmd["rpm"], "--dbpath", db, "-K",
                                             os.path.join(assets, name)], "rpm")
        text = run.stdout(rec).decode("utf-8", "replace")
        good = run.ok(rec) and "signatures OK" in text and "NOT OK" not in text
        run.check("rpm", name, good, text.strip().split(": ", 1)[-1][:200], rec["path"])


def extract(run, assets, name):
    """Unpack one package into DIR/extract/NAME; return the directory or None."""
    dest = os.path.join(run.out, "extract", name)
    os.makedirs(dest)
    pkg = os.path.join(assets, name)
    if name.endswith(".deb"):
        rec = run.capture("extract-" + name, [run.tools.cmd["dpkg-deb"], "-x", pkg, dest],
                          "extract")
        return dest if run.ok(rec) else None
    rec = run.capture("rpm2cpio-" + name, [run.tools.cmd["rpm2cpio"], pkg], "extract")
    if not run.ok(rec):
        return None
    # The cpio archive is the capture's own stdout: no pipe, and it is kept.
    rec = run.capture("cpio-" + name, [run.tools.cmd["cpio"], "-idm", "--quiet",
                                       "--no-absolute-filenames"], "extract",
                      stdin_file=os.path.join(rec["path"], "stdout"), cwd=dest)
    return dest if run.ok(rec) else None


def package_arch(name):
    m = re.match(r"^openwatch(?:-[^-]+-\d+\.(x86_64|aarch64)\.rpm|_[^_]+_(amd64|arm64)\.deb)$",
                 name)
    return ARCH.get(m.group(1) or m.group(2)) if m else None


def check_binary(run, name, root, exp):
    binary = os.path.join(root, "usr", "bin", "openwatch")
    if not os.path.isfile(binary):
        run.check("binary", name, False, "/usr/bin/openwatch is not in the package")
        return None
    rec = run.capture("go-version-m-" + name, [run.tools.cmd["go"], "version", "-m", binary],
                      "go")
    if not run.ok(rec):
        run.check("binary", name, False, "go version -m failed", rec["path"])
        return binary
    text = run.stdout(rec).decode("utf-8", "replace")
    lines = text.splitlines()
    gov = lines[0].rsplit(" ", 1)[-1].strip() if lines else ""
    build, deps = {}, {}
    for line in lines[1:]:
        f = line.strip().split("\t")
        if f[0] == "build" and len(f) >= 2 and "=" in f[1]:
            k, v = f[1].split("=", 1)
            build[k] = v
        elif f[0] == "dep" and len(f) >= 3:
            deps[f[1]] = f[2]
        elif f[0] == "=>" and len(f) >= 3 and deps:
            deps[list(deps)[-1]] = "replaced"
    problems = []
    if gov != exp["go"]:
        problems.append("built with %s, go.mod says %s" % (gov, exp["go"]))
    if build.get("vcs.revision") != run.commit:
        problems.append("vcs.revision %s" % build.get("vcs.revision"))
    if build.get("vcs.modified") != "false":
        problems.append("vcs.modified %s" % build.get("vcs.modified"))
    ld = build.get("-ldflags", "")
    if "internal/version.Version=%s " % exp["version"] not in ld + " ":
        problems.append("ldflags Version is not %s" % exp["version"])
    if "internal/version.Commit=%s" % run.commit[:8] not in ld:
        problems.append("ldflags Commit is not %s" % run.commit[:8])
    if build.get("GOARCH") != package_arch(name):
        problems.append("GOARCH %s in a %s package" % (build.get("GOARCH"), package_arch(name)))
    wrong = sorted("%s %s (go.mod %s)" % (m, v, exp["requires"].get(m))
                   for m, v in deps.items() if exp["requires"].get(m) != v)
    if wrong:
        problems.append("dependencies not at go.mod's version: " + "; ".join(wrong[:5]))
    run.check("binary", name, not problems and bool(deps),
              "; ".join(problems) or "%s, revision %s, %d dependencies at go.mod's versions"
              % (gov, run.commit[:12], len(deps)), rec["path"])
    return binary


def check_vulns(run, name, binary):
    rec = run.capture("govulncheck-" + name, [run.tools.cmd["govulncheck"], "-mode=binary",
                                               "-format", "json", binary], "govulncheck")
    # In -format json mode govulncheck exits 0 whether or not it finds anything;
    # any other status is a scanner failure, not a result.
    if rec.get("status") != ec.COMPLETE or rec["exit"].get("code") != 0:
        run.check("vulns", name, False, "govulncheck did not complete with exit 0 (%s)"
                  % ec._exit_text(rec.get("exit") or {}).strip(), rec["path"])
        return
    try:
        objs = _json_stream(run.stdout(rec).decode("utf-8", "replace"))
    except ValueError as e:
        run.check("vulns", name, False, "govulncheck output is not a JSON stream: %s" % e,
                  rec["path"])
        return
    configs = [o["config"] for o in objs if "config" in o]
    osvs = set((o["osv"] or {}).get("id") for o in objs if "osv" in o)
    findings = [o["finding"] for o in objs if "finding" in o]
    problems = []
    if len(configs) != 1 or configs[0].get("scanner_name") != "govulncheck" or \
            configs[0].get("scan_mode") != "binary":
        problems.append("expected one govulncheck config in binary mode, found %r" % configs)
    if not any("SBOM" in o for o in objs):
        problems.append("no SBOM object: the scan did not report what it scanned")
    for f in findings:
        if not f.get("osv") or f.get("osv") not in osvs:
            problems.append("finding %r has no matching osv entry" % f.get("osv"))
        if not f.get("trace"):
            problems.append("finding %r has no trace" % f.get("osv"))
    if problems:
        run.check("vulns", name, False, "inconsistent govulncheck output: " + "; ".join(
            problems[:3]), rec["path"])
        return
    called, imported, required = set(), set(), set()
    for f in findings:
        frame = f["trace"][0]
        (called if frame.get("function") else imported if frame.get("package")
         else required).add(f["osv"])
    run.check("vulns", name, not called,
              "called: %s; imported only: %s; required modules only: %s" % (
                  sorted(called) or "none", sorted(imported) or "none",
                  sorted(required) or "none"), rec["path"])


def _json_stream(text):
    """Every JSON object in a govulncheck stream; ValueError if any is malformed."""
    dec = json.JSONDecoder()
    out = []
    i = 0
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            return out
        obj, i = dec.raw_decode(text, i)
        if not isinstance(obj, dict):
            raise ValueError("a stream element is not an object")
        out.append(obj)


def check_notices(run, name, root, exp):
    base = os.path.join(root, "usr", "share", "licenses", "openwatch")
    missing = [f for f in LICENSE_FILES if not os.path.isfile(os.path.join(base, f))]
    same = (not missing and
            read(os.path.join(base, "THIRD-PARTY-NOTICES.md")) == exp["notices"])
    run.check("notices", name, not missing and same,
              "missing: %s; THIRD-PARTY-NOTICES.md %s the commit's" % (
                  missing or "none", "equals" if same else "differs from"))


def check_sboms(run, assets, exp):
    inv = exp["inventory"]
    pkgs = (sorted(p["file"] for p in inv["packages"]) if inv else
            sorted(f for f in os.listdir(assets) if f.endswith((".rpm", ".deb"))))
    for name in pkgs:
        if not os.path.isfile(os.path.join(assets, name)):
            run.check("sbom", name, False, "could not run: the package is missing")
            continue
        path = os.path.join(assets, name + ".cdx.json")
        if not os.path.isfile(path):
            run.check("sbom", name, False, "no %s.cdx.json" % name)
            continue
        try:
            bom = json.loads(read(path))
        except ValueError as e:
            run.check("sbom", name, False, "not JSON: %s" % e)
            continue
        comp = (bom.get("metadata") or {}).get("component") or {}
        problems = []
        if bom.get("bomFormat") != "CycloneDX":
            problems.append("bomFormat %r" % bom.get("bomFormat"))
        if comp.get("name") != name:
            problems.append("subject %r" % comp.get("name"))
        if comp.get("version") != "sha256:" + sha256(os.path.join(assets, name)):
            problems.append("subject digest %r is not the package's" % comp.get("version"))
        compared = 0
        if name.startswith("openwatch"):
            wrong = []
            for c in bom.get("components") or []:
                m = re.match(r"^pkg:golang/(.+)@(v[^?#]+)", c.get("purl") or "")
                if m and m.group(1) in exp["requires"]:
                    compared += 1
                    if exp["requires"][m.group(1)] != m.group(2):
                        wrong.append("%s@%s" % (m.group(1), m.group(2)))
            if wrong:
                problems.append("Go modules not at go.mod's version: %s" % ", ".join(wrong[:5]))
            if not compared:
                problems.append("lists no Go module that go.mod requires")
        run.check("sbom", name, not problems, "; ".join(problems) or (
            "CycloneDX %s, subject is the package and its sha256%s" % (
                bom.get("specVersion"),
                ", %d Go modules at go.mod's versions" % compared if compared else "")))
    run.check("sbom", "openwatch.cdx.json", os.path.isfile(os.path.join(assets, "openwatch.cdx.json")),
              "the merged SBOM is %s" % ("present" if os.path.isfile(
                  os.path.join(assets, "openwatch.cdx.json")) else "missing"))


def report(run, assets, src):
    # An area with no check at all did not run; that is a failure, and a run
    # with no checks can never pass.
    for area in AREAS:
        if not any(r["area"] == area for r in run.results):
            run.check(area, "(area)", False, "could not run: no check in this area produced "
                      "a result")
    failed = [r for r in run.results if not r["ok"]]
    data = {"tag": run.tag, "commit": run.commit, "key": run.key,
            "assets": assets, "downloaded": not src,
            "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
            "verdict": "PASS" if run.results and not failed else "FAIL",
            "notes": run.notes, "checks": run.results}
    ec._write_new(os.path.join(run.out, "report.json"),
                  (json.dumps(data, indent=2, sort_keys=True) + "\n").encode())
    lines = ["# Asset verification: %s at %s" % (run.tag, run.commit), "",
             "Derived from the raw captures in `captures/`, which are authoritative. "
             "This report records no release decision.", "",
             "**%s**: %d checks, %d failed." % (data["verdict"], len(run.results), len(failed)),
             ""] + ["- Note: %s" % n for n in run.notes] + [
             "", "| Area | Subject | Result | Detail |", "|---|---|---|---|"]
    for r in run.results:
        lines.append("| %s | %s | %s | %s |" % (r["area"], r["subject"],
                                                "ok" if r["ok"] else "FAIL",
                                                r["detail"].replace("|", "\\|")))
    ec._write_new(os.path.join(run.out, "REPORT.md"), ("\n".join(lines) + "\n").encode())
    return data


def verify(a, tools=None):
    tools = tools or Tools()
    if not _SHA.match(a.commit or ""):
        raise AssetError("--commit must be a full 40-character lowercase SHA")
    if not _FPR.match(a.key or ""):
        raise AssetError("--key must be the release key's full 40-character fingerprint")
    if not _TAG.match(a.tag or ""):
        raise AssetError("--tag must be a release tag such as v0.8.4")
    if os.path.lexists(a.evidence):
        raise AssetError("%s already exists; evidence is never overwritten" % a.evidence)
    if a.src and not os.path.isdir(a.src):
        raise AssetError("--from %s is not a directory" % a.src)
    run = Run(a, tools)
    exp = expectations(run)
    os.makedirs(run.captures)
    assets = os.path.abspath(a.src) if a.src else os.path.join(run.out, "assets")
    digests = download(run, assets, a.src)
    if not os.path.isdir(assets):
        run.check("release", "assets", False, "could not run: %s does not exist" % assets)
        return report(run, assets, a.src)
    if not a.src and not all(r["ok"] for r in run.results
                             if r["area"] == "release" and r["subject"] == "download"):
        # Nothing downloaded can be trusted as the release's assets; every
        # other area is reported as not run.
        return report(run, assets, a.src)
    check_release(run, assets, digests)
    check_inventory(run, assets, exp)
    check_manifest(run, assets, exp)
    keys = check_signature(run, assets, exp)
    check_rpms(run, assets, keys, exp)
    inv = exp["inventory"]
    binaries = ([p["file"] for p in inv["packages"] if p["binary"]] if inv else
                [f for f in sorted(os.listdir(assets)) if package_arch(f)])
    for name in binaries:
        if not os.path.isfile(os.path.join(assets, name)):
            for area in ("binary", "vulns", "notices"):
                run.check(area, name, False, "could not run: the package is missing")
            continue
        root = extract(run, assets, name)
        if root is None:
            for area in ("binary", "vulns", "notices"):
                run.check(area, name, False, "could not run: the package could not be unpacked")
            continue
        binary = check_binary(run, name, root, exp)
        if binary:
            check_vulns(run, name, binary)
        else:
            run.check("vulns", name, False, "could not run: no binary to scan")
        check_notices(run, name, root, exp)
    check_sboms(run, assets, exp)
    return report(run, assets, a.src)


def main(argv=None, out=sys.stdout, tools=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--tag", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--evidence", required=True, help="a new directory for this run")
    p.add_argument("--from", dest="src", help="assets already downloaded; read in place")
    p.add_argument("--inventory-from-tree", action="store_true",
                   help="read release/assets.toml from this tool's tree, for a candidate that "
                        "predates it; the report records this")
    p.add_argument("--repo", default=".", help=argparse.SUPPRESS)
    a = p.parse_args(argv)
    try:
        data = verify(a, tools)
    except (AssetError, ec.CaptureError) as e:
        out.write("REFUSED: %s\n" % e)
        return 2
    failed = [r for r in data["checks"] if not r["ok"]]
    for r in failed:
        out.write("FAIL  %-9s %s: %s\n" % (r["area"], r["subject"], r["detail"]))
    out.write("%s: %d checks, %d failed. Report: %s\n" % (
        data["verdict"], len(data["checks"]), len(failed),
        os.path.join(os.path.abspath(a.evidence), "REPORT.md")))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
