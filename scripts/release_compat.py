#!/usr/bin/env python3
"""Run the engine/corpus compatibility test locally against a release's packages.

    python3 -S scripts/release_compat.py --tag vX.Y.Z --commit <40-hex> \\
        --key <40-hex fingerprint> --old-tag vA.B.C --evidence DIR \\
        [--from NEW_ASSETS_DIR] [--old-from OLD_ASSETS_DIR] [--inventory-from-tree]

The release-upgrade pairing test (TestUpgrade_EngineCorpusPairingInContainers)
runs in package-smoke against packages that workflow builds. This runs the
candidate commit's own copy of that test, in local containers, against the
packages the release actually carries (the draft's, or a published release's)
as the new pair, and an older release's packages as the old pair. For v0.8.4
this was done by hand.

Steps, every command captured through scripts/evidence_capture.py with an
explicit timeout:

  1. the new and old packages: downloaded from their releases with
     `gh release download`, or read from --from / --old-from;
  2. each release's SHA256SUMS.asc verified against the release key, a primary
     key in security/KEYS at the candidate commit, and each package used
     checked against its SHA256SUMS entry;
  3. the packages staged into per-format directories, hashed;
  4. the candidate commit's source extracted with `git archive` (never a
     working tree), and its generated prerequisites made;
  5. `docker info`, so a missing daemon is a failure, not a skipped test;
  6. the test in each mode: Rocky 9 RPM, Ubuntu 24.04 DEB, and Rocky 9 RPM
     with scriptlets off. A mode passes only with exit 0, the test and its
     subtest reported PASS, no SKIP, the container's "all checks passed"
     line, at least one PASS check line and no FAIL line;
  7. the staged packages hashed again, unchanged.

The new pair is named by release/assets.toml at the candidate commit
(--inventory-from-tree is the recorded fallback for an older candidate). The
old pair is the old release's x86_64 RPM and amd64 DEB with its kensa-rules,
found by version in its SHA256SUMS.

It changes no release and no host: the containers are local and disposable.
It records no decision. Spec: release-compat-runs.
"""

import argparse
import importlib.util
import os
import re
import shutil
import sys
from pathlib import Path

_here = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("release_assets", _here / "release_assets.py")
ra = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ra)
ec = ra.ec

TIMEOUTS = dict(ra.TIMEOUTS, archive=300, make=600, docker=60, compat=3000)

# (name, image, kind, scriptlet mode). The label is what the container script
# prints in its final line: "kensa-rules compat (<label>): all checks passed".
MODES = (("rocky9-rpm", "rockylinux:9", "rpm", "scripts"),
         ("ubuntu2404-deb", "ubuntu:24.04", "deb", "scripts"),
         ("rocky9-rpm-noscripts", "rockylinux:9", "rpm", "noscripts"))

TEST = "TestUpgrade_EngineCorpusPairingInContainers"
AREAS = ("inputs", "signature", "source", "docker", "compat", "inputs-after")


class Run(ra.Run):
    def capture(self, name, argv, kind, stdin_file=None, cwd=None):
        self.n += 1
        cap = "%03d-%s" % (self.n, re.sub(r"[^A-Za-z0-9._-]", "_", name))[:120]
        try:
            rec = ec.capture(argv, self.captures, cap, self.tag, self.commit,
                             timeout=TIMEOUTS[kind], stdin_file=stdin_file,
                             cwd=cwd or self.repo, purpose="release compat run: " + name)
        except ec.CaptureIncomplete as e:
            rec = dict(e.record, path=e.path)
        rec.setdefault("path", os.path.join(self.captures, cap))
        return rec


def label(kind, mode):
    return kind if mode == "scripts" else "%s %s" % (kind, mode)


def fetch(run, tag, dest, src):
    """The release's assets, downloaded into dest or read from src. Returns a directory."""
    if src:
        return os.path.abspath(src)
    os.makedirs(dest)
    rec = run.capture("gh-release-download-" + tag, [run.tools.cmd["gh"], "release", "download",
                                                     tag, "--repo", ra.REPO_SLUG, "--dir", dest],
                      "download")
    run.check("inputs", "download " + tag, run.ok(rec), "gh release download " + tag, rec["path"])
    return dest if run.ok(rec) else None


def sums(path):
    out = {}
    for line in ra.read(path).decode("utf-8", "replace").splitlines():
        m = re.match(r"^([0-9a-f]{64})  (\S+)$", line)
        if m:
            out[m.group(2)] = m.group(1)
    return out


def verify_release(run, which, d, keys):
    """SHA256SUMS of one release directory carries a good signature by the key."""
    home = os.path.join(run.out, "gnupg-" + which)
    os.makedirs(home, mode=0o700)
    gpg = [run.tools.cmd["gpg"], "--homedir", home, "--batch"]
    run.capture("gpg-import-" + which, gpg + ["--import", keys], "gpg")
    rec = run.capture("gpg-verify-" + which, gpg + ["--status-fd", "1", "--verify",
                                                    os.path.join(d, "SHA256SUMS.asc"),
                                                    os.path.join(d, "SHA256SUMS")], "gpg")
    valid = [l.split() for l in run.stdout(rec).decode().splitlines()
             if l.startswith("[GNUPG:] VALIDSIG ")]
    good = run.ok(rec) and valid and run.key in (valid[0][2], valid[0][-1])
    ra.subprocess.run(["gpgconf", "--homedir", home, "--kill", "all"],
                      stdout=ra.subprocess.DEVNULL, stderr=ra.subprocess.DEVNULL)
    run.check("signature", which + " SHA256SUMS.asc", good,
              "VALIDSIG from %s" % (valid[0][-1] if valid else "nobody"), rec["path"])
    return good


def pick(run, which, d, wanted):
    """Check each wanted file against the release's SHA256SUMS; return their paths or None."""
    listed = sums(os.path.join(d, "SHA256SUMS")) if os.path.isfile(
        os.path.join(d, "SHA256SUMS")) else {}
    paths = {}
    for kind, name in wanted:
        p = os.path.join(d, name)
        got = ra.sha256(p) if os.path.isfile(p) else None
        ok = got is not None and listed.get(name) == got
        run.check("inputs", "%s %s" % (which, name), ok, "listed %s, file %s" % (
            listed.get(name), got))
        if not ok:
            return None
        paths.setdefault(kind, []).append(p)
    return paths


def old_wanted(run, d, old_tag):
    """The old pair: openwatch x86_64 RPM and amd64 DEB of the old version, with kensa-rules."""
    listed = sums(os.path.join(d, "SHA256SUMS")) if os.path.isfile(
        os.path.join(d, "SHA256SUMS")) else {}
    ver = old_tag[1:].replace("-", ".", 1)
    rpm_k = sorted(n for n in listed if re.match(r"^kensa-rules-[^-]+-1\.noarch\.rpm$", n))
    deb_k = sorted(n for n in listed if re.match(r"^kensa-rules_[^_]+_all\.deb$", n))
    if len(rpm_k) != 1 or len(deb_k) != 1:
        run.check("inputs", "old kensa-rules", False,
                  "the old release lists %d kensa-rules RPMs and %d DEBs, not one of each"
                  % (len(rpm_k), len(deb_k)))
        return None
    return [("rpm", "openwatch-%s-1.x86_64.rpm" % ver), ("rpm", rpm_k[0]),
            ("deb", "openwatch_%s_amd64.deb" % ver), ("deb", deb_k[0])]


def new_wanted(exp):
    files = [p["file"] for p in exp["inventory"]["packages"]]
    want = []
    for f in files:
        if f.endswith(".x86_64.rpm") or f.endswith(".noarch.rpm"):
            want.append(("rpm", f))
        elif f.endswith("_amd64.deb") or f.endswith("_all.deb"):
            want.append(("deb", f))
    return want


def stage(run, which, paths):
    """Copy each format's packages into stage/<which>-<kind>; return {kind: dir}."""
    dirs = {}
    for kind, files in sorted(paths.items()):
        d = os.path.join(run.out, "stage", "%s-%s" % (which, kind))
        os.makedirs(d)
        for p in files:
            shutil.copy2(p, d)
        dirs[kind] = d
    return dirs


def digests(dirs):
    return dict((os.path.join(k, n), ra.sha256(os.path.join(d, n)))
                for k, d in dirs.items() for n in sorted(os.listdir(d)))


def source(run):
    """Extract the candidate commit's tree and make the test prerequisites."""
    src = os.path.join(run.out, "src")
    os.makedirs(src)
    rec = run.capture("git-archive", [run.tools.cmd["git"], "archive", "--format=tar",
                                      run.commit], "archive")
    if not run.ok(rec):
        run.check("source", "git archive", False, "could not archive " + run.commit, rec["path"])
        return None
    rec = run.capture("tar-extract", [run.tools.cmd["tar"], "-xf", "-"], "archive",
                      stdin_file=os.path.join(rec["path"], "stdout"), cwd=src)
    if not run.ok(rec):
        run.check("source", "extract", False, "could not extract the archive", rec["path"])
        return None
    rec = run.capture("make-prerequisites", [run.tools.cmd["make"],
                                             "internal/server/openapi_embed.yaml",
                                             "internal/server/spa/index.html"], "make", cwd=src)
    run.check("source", run.commit, run.ok(rec), "the candidate's tree, from git archive, with "
              "its generated prerequisites", rec["path"])
    return src if run.ok(rec) else None


def run_mode(run, src, name, image, kind, mode, old, new):
    argv = [run.tools.cmd["env"],
            "OPENWATCH_KENSA_COMPAT_IMAGE=" + image, "OPENWATCH_KENSA_COMPAT_KIND=" + kind,
            "OPENWATCH_KENSA_COMPAT_OLD_DIR=" + old[kind],
            "OPENWATCH_KENSA_COMPAT_NEW_DIR=" + new[kind],
            "OPENWATCH_KENSA_COMPAT_MODE=" + mode,
            run.tools.cmd["go"], "test", "-count=1", "-v", "-timeout", "45m",
            "-run", "^%s$" % TEST, "./packaging/tests/"]
    rec = run.capture("compat-" + name, argv, "compat", cwd=src)
    text = run.stdout(rec).decode("utf-8", "replace") + "\n" + ra.read(
        os.path.join(rec["path"], "stderr")).decode("utf-8", "replace")
    problems = []
    if not run.ok(rec):
        problems.append("go test ended with %s" % ec._exit_text(rec.get("exit") or {}).strip())
    for want in ("--- PASS: %s " % TEST, "--- PASS: %s/containers " % TEST):
        if want not in text:
            problems.append("no %r" % want.strip())
    if re.search(r"--- SKIP: %s" % TEST, text):
        problems.append("the test was SKIPPED")
    final = "kensa-rules compat (%s): all checks passed" % label(kind, mode)
    if final not in text:
        problems.append("no %r line" % final)
    passes = len(re.findall(r"^\s*PASS: ", text, re.M))
    fails = len(re.findall(r"^\s*FAIL: ", text, re.M))
    if passes == 0:
        problems.append("no PASS check lines")
    if fails:
        problems.append("%d FAIL check lines" % fails)
    run.check("compat", name, not problems, "; ".join(problems) or "%s on %s: %d checks passed"
              % (label(kind, mode), image, passes), rec["path"])


def report(run):
    for area in AREAS:
        if not any(r["area"] == area for r in run.results):
            run.check(area, "(area)", False, "could not run: no check in this area produced a "
                      "result")
    failed = [r for r in run.results if not r["ok"]]
    verdict = "PASS" if run.results and not failed else "FAIL"
    data = {"tag": run.tag, "commit": run.commit, "old_tag": run.old_tag,
            "verdict": verdict, "notes": run.notes, "checks": run.results}
    ec._write_new(os.path.join(run.out, "report.json"),
                  (ra.json.dumps(data, indent=2, sort_keys=True) + "\n").encode())
    lines = ["# Compatibility runs: %s at %s, old pair %s" % (run.tag, run.commit, run.old_tag),
             "", "Derived from the raw captures in `captures/`, which are authoritative. "
             "This report records no release decision.", "",
             "**%s**: %d checks, %d failed." % (verdict, len(run.results), len(failed)), ""] + [
             "- Note: %s" % n for n in run.notes] + [
             "", "| Area | Subject | Result | Detail |", "|---|---|---|---|"]
    for r in run.results:
        lines.append("| %s | %s | %s | %s |" % (r["area"], r["subject"],
                                                "ok" if r["ok"] else "FAIL",
                                                r["detail"].replace("|", "\\|")))
    ec._write_new(os.path.join(run.out, "REPORT.md"), ("\n".join(lines) + "\n").encode())
    return data


def compat(a, tools=None):
    tools = tools or ra.Tools(env="env", make="make", tar="tar", docker="docker")
    for flag, pattern, value in (("--commit", ra._SHA, a.commit), ("--key", ra._FPR, a.key),
                                 ("--tag", ra._TAG, a.tag), ("--old-tag", ra._TAG, a.old_tag)):
        if not pattern.match(value or ""):
            raise ra.AssetError("%s %r is malformed" % (flag, value))
    if os.path.lexists(a.evidence):
        raise ra.AssetError("%s already exists; evidence is never overwritten" % a.evidence)
    for flag, d in (("--from", a.src), ("--old-from", a.old_src)):
        if d and not os.path.isdir(d):
            raise ra.AssetError("%s %s is not a directory" % (flag, d))
    run = Run(a, tools)
    run.old_tag = a.old_tag
    exp = ra.expectations(run)
    if exp["inventory"] is None:
        raise ra.AssetError(exp["inventory_source"] + "; pass --inventory-from-tree for a "
                            "candidate that predates it")
    run.notes.append("new-pair inventory: " + exp["inventory_source"])
    os.makedirs(run.captures)
    keys = os.path.join(run.out, "KEYS.from-commit")
    with open(keys, "wb") as f:
        f.write(exp["keys"])

    new_dir = fetch(run, a.tag, os.path.join(run.out, "new"), a.src)
    old_dir = fetch(run, a.old_tag, os.path.join(run.out, "old"), a.old_src)
    new = old = None
    if new_dir and old_dir and verify_release(run, "new", new_dir, keys) and \
            verify_release(run, "old", old_dir, keys):
        newp = pick(run, "new", new_dir, new_wanted(exp))
        ow = old_wanted(run, old_dir, a.old_tag)
        oldp = pick(run, "old", old_dir, ow) if ow else None
        if newp and oldp:
            new, old = stage(run, "new", newp), stage(run, "old", oldp)
    if not (new and old):
        return report(run)
    before = digests(new)
    before.update(digests(old))
    src = source(run)
    if not src:
        return report(run)
    rec = run.capture("docker-info", [run.tools.cmd["docker"], "info", "--format",
                                      "{{.ServerVersion}}"], "docker")
    run.check("docker", "daemon", run.ok(rec), "docker %s" % run.stdout(rec).decode().strip(),
              rec["path"])
    if not run.ok(rec):
        return report(run)
    for name, image, kind, mode in MODES:
        run_mode(run, src, name, image, kind, mode, old, new)
    after = digests(new)
    after.update(digests(old))
    run.check("inputs-after", "staged packages", after == before,
              "%d staged packages %s" % (len(before), "unchanged" if after == before else
                                         "CHANGED during the runs"))
    return report(run)


def main(argv=None, out=sys.stdout, tools=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--tag", required=True, help="the candidate release")
    p.add_argument("--commit", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--old-tag", required=True, help="the release supplying the old pair")
    p.add_argument("--evidence", required=True, help="a new directory for this run")
    p.add_argument("--from", dest="src", help="the candidate's assets, already downloaded")
    p.add_argument("--old-from", dest="old_src", help="the old release's assets, downloaded")
    p.add_argument("--inventory-from-tree", action="store_true",
                   help="read release/assets.toml from this tool's tree for an older candidate; "
                        "the report records this")
    p.add_argument("--repo", default=".", help=argparse.SUPPRESS)
    a = p.parse_args(argv)
    try:
        data = compat(a, tools)
    except (ra.AssetError, ec.CaptureError) as e:
        out.write("REFUSED: %s\n" % e)
        return 2
    failed = [r for r in data["checks"] if not r["ok"]]
    for r in failed:
        out.write("FAIL  %-12s %s: %s\n" % (r["area"], r["subject"], r["detail"]))
    out.write("%s: %d checks, %d failed. Report: %s\n" % (
        data["verdict"], len(data["checks"]), len(failed),
        os.path.join(os.path.abspath(a.evidence), "REPORT.md")))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
