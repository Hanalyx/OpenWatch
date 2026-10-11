#!/usr/bin/env python3
"""Upgrade an OpenWatch server with UPGRADE_PROCEDURE.md Steps 1 to 8, capturing evidence.

    python3 -S scripts/release_upgrade.py PHASE HOSTARGS [--execute]

    plan      read-only preflight ("Before you upgrade"); always runs
    backup    Step 1: a fresh database dump, proven readable
    install   Steps 2 and 3: stop, record the roll-back point, install the
              packages (staged on the host and checked against their digests)
    verify    Steps 4 to 7: check-config, migrate (must be a no-op), the
              service is active, health and version report the new version,
              journal, database
    rules     Step 8: restart, prove the rule library loaded, and compare the
              served rules with the installed rules; must end in MATCH
    status    what is verified and what is next

    HOSTARGS: --host NAME --ssh-target USER@ADDR --ssh-key PATH --tag vX.Y.Z
              --commit <40-hex> --evidence DIR --kind rpm|deb
              [--package FILE ...] [--token-file PATH-ON-HOST] [--url URL]

Every phase runs a maintained script from release/prep/upgrade/ on the host
through scripts/evidence_capture.py, then fetches and verifies the capture.
A phase that changes the host (backup, install, verify, rules) does nothing
without --execute; without it, it prints exactly what would run. A phase
needs the previous phase's capture from the same machine, verified, with
every step passing: install needs a verified backup, rules needs verified
Steps 4 to 7. --execute also needs the preflight to have shown the host's
hostname to be --host.

What it never does: start the service by hand after a failed install, roll
back, change configuration, or reboot. The one restart is Step 8's, which
the procedure requires. The API token for Step 8 stays in a root-only file
on the host; it is never read or sent from here.

Spec: release-upgrade-steps.
"""

import argparse
import importlib.util
import os
import shlex
import sys
from pathlib import Path

_here = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("release_prep", _here / "release_prep.py")
rp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rp)
ec = rp.ec

SCRIPTS = _here.parent / "release" / "prep" / "upgrade"


class Phase(object):
    def __init__(self, name, script, requires, mutates, timeout, done, next_step):
        self.name, self.script, self.requires = name, script, requires
        self.mutates, self.timeout, self.done, self.next_step = mutates, timeout, done, next_step


# Explicit timeouts, in seconds. `done` is the line a phase's script prints
# only when every step passed.
PHASES = [
    Phase("plan", "preflight.sh", (), False, 300, None,
          "Review the preflight. Then take the backup: {cmd} backup {args} --execute"),
    Phase("backup", "backup.sh", ("plan",), True, 1800, "BACKUP DONE",
          "Install the packages: {cmd} install {args} --execute"),
    Phase("install", "install.sh", ("plan", "backup"), True, 1800, "INSTALL DONE",
          "Verify Steps 4 to 7: {cmd} verify {args} --execute"),
    Phase("verify", "verify.sh", ("plan", "backup", "install"), True, 600, "VERIFY DONE",
          "Run Step 8 before any scan: {cmd} rules {args} --execute"),
    Phase("rules", "rules.sh", ("plan", "backup", "install", "verify"), True, 600,
          "STEP 8 DONE: MATCH", "The upgrade is verified through Step 8. Scans may run."),
]
TRANSFER_TIMEOUT = 300
STAGE_TIMEOUT = 900


class UpgradeError(rp.PrepError):
    pass


def phase(name):
    for p in PHASES:
        if p.name == name:
            return p
    raise UpgradeError("unknown phase %r" % name)


def verified(host, name, machine_id=None):
    """The record of a phase capture that verifies, exited 0, failed no step, and finished."""
    path = os.path.join(host.local_dir, "upgrade-" + name)
    if not os.path.isdir(path):
        raise UpgradeError("no verified %s capture for %s" % (name, host.name))
    try:
        rec = ec.verify_capture(path, tag=host.tag, commit=host.commit, machine_id=machine_id)
    except ec.VerifyError as e:
        raise UpgradeError("the %s capture for %s does not verify: %s" % (name, host.name, e))
    with open(os.path.join(path, "stdout"), "rb") as f:
        out = f.read()
    failed = rp._failed_sections(out)
    if rec["exit"].get("code") != 0 or failed:
        raise UpgradeError("the %s phase on %s did not pass (%s%s); see %s" % (
            name, host.name, ec._exit_text(rec["exit"]).strip(),
            "; failed: %s" % ", ".join("%s (exit %s)" % f for f in failed) if failed else "",
            path))
    done = phase(name).done
    if done and done.encode() not in out:
        raise UpgradeError("the %s phase on %s did not print %r; see %s" % (
            name, host.name, done, path))
    return rec


def preflight_hostname(host):
    with open(os.path.join(host.local_dir, "upgrade-plan", "stdout"), "rb") as f:
        sections = rp._sections(f.read())
    return [l.strip() for l in sections.get("hostname", []) if l.strip()]


def script_for(p, env):
    with open(SCRIPTS / "common.sh") as f:
        common = f.read()
    with open(SCRIPTS / p.script) as f:
        body = f.read()
    assigns = "".join("export %s=%s\n" % (k, shlex.quote(v)) for k, v in sorted(env.items()))
    # The assignments come first: common.sh derives its paths from them.
    return assigns + "\n" + common + "\n" + body


def stage_packages(host, packages, execute):
    """Copy each package to the host's stage directory; return (paths, sums lines)."""
    stage = host.remote_dir + "/packages"
    paths, sums = [], []
    for pkg in packages:
        if not os.path.isfile(pkg):
            raise UpgradeError("--package %s is not a file" % pkg)
        name = os.path.basename(pkg)
        dest = "%s/%s" % (stage, name)
        paths.append(dest)
        sums.append("%s  %s" % (ec._sha256_file(pkg), dest))
        if not execute:
            continue
        argv = host.remote(host.sudo + ["mkdir", "-p", "-m", "0700", stage],
                           host.sudo + ["sh", "-c", 'umask 077; cat > "$1"', "sh", dest])
        try:
            rec = ec.capture(argv, host.local_dir, "stage-" + name, host.tag, host.commit,
                             timeout=STAGE_TIMEOUT, stdin_file=pkg,
                             purpose="copy %s to %s" % (name, host.name))
        except ec.CaptureError as e:
            raise UpgradeError("staging %s on %s did not complete: %s" % (name, host.name, e))
        if rec["exit"]["code"] != 0:
            raise UpgradeError("staging %s on %s ended with %s; see %s" % (
                name, host.name, ec._exit_text(rec["exit"]).strip(), rec["path"]))
    return paths, sums


def run_phase(host, a, name):
    p = phase(name)
    for q in PHASES:
        if not (isinstance(q.timeout, (int, float)) and q.timeout > 0):
            raise UpgradeError("phase %s has no explicit positive timeout" % q.name)
    machine_id = None
    for req in p.requires:
        rec = verified(host, req, machine_id)
        machine_id = machine_id or (rec.get("host") or {}).get("machine_id")
    names = preflight_hostname(host) if p.requires else []
    if p.mutates and a.execute and not any(h == host.name or h.split(".")[0] == host.name
                                           for h in names):
        raise UpgradeError("the preflight on this connection reported hostname %r, not %s; "
                           "refusing to change the host" % (names, host.name))
    env = {"OW_URL": a.url, "OW_KIND": a.kind, "OW_VERSION": a.tag[1:]}
    if name == "install":
        if not a.package:
            raise UpgradeError("install needs --package for every package to install")
        paths, sums = stage_packages(host, a.package, a.execute)
        env.update(OW_PKGS=" ".join(paths), OW_SUMS="\n".join(sums))
    if name == "rules":
        if not a.token_file:
            raise UpgradeError("rules needs --token-file: a root-only file on the host holding "
                               "an owk_ token with scan:read")
        env["OW_TOKEN_FILE"] = a.token_file
    if a.root:
        env["OW_ROOT"] = a.root
    script = script_for(p, env)
    cap = "upgrade-" + name
    if p.mutates and not a.execute:
        return None, ("DRY RUN: %s would run this on %s as root, through the capture library, "
                      "and nothing has been changed:\n\n%s" % (name, host.name, script))
    rp.remote_capture(host, cap, script, p.timeout, TRANSFER_TIMEOUT, machine_id,
                      "upgrade %s on %s" % (name, host.name))
    return verified(host, name, machine_id), None


def status(host):
    lines, machine_id, nxt = [], None, None
    for p in PHASES:
        try:
            rec = verified(host, p.name, machine_id)
            machine_id = machine_id or (rec.get("host") or {}).get("machine_id")
            lines.append("%-8s verified" % p.name)
        except rp.PrepError as e:
            lines.append("%-8s not ready: %s" % (p.name, e))
            nxt = nxt or p.name
    lines.append("next: %s" % (nxt or "none; Step 8 reached MATCH"))
    return "\n".join(lines)


def main(argv=None, out=sys.stdout):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("phase", choices=[x.name for x in PHASES] + ["status"])
    p.add_argument("--host", required=True)
    p.add_argument("--tag", required=True, help="the release being installed")
    p.add_argument("--commit", required=True)
    p.add_argument("--evidence", required=True)
    p.add_argument("--kind", required=True, choices=("rpm", "deb"))
    p.add_argument("--package", action="append", default=[], help="local package file; repeat")
    p.add_argument("--token-file", help="Step 8: a root-only file ON THE HOST with an owk_ token")
    p.add_argument("--url", default="https://localhost:8443")
    p.add_argument("--execute", action="store_true", help="actually change the host")
    p.add_argument("--ssh-target")
    p.add_argument("--ssh-key")
    p.add_argument("--sudo", default="sudo -n")
    p.add_argument("--remote-python", default="python3")
    p.add_argument("--remote-dir", default="/root/openwatch-release-evidence")
    p.add_argument("--transport", help=argparse.SUPPRESS)  # tests: a JSON argv replacing ssh
    p.add_argument("--root", help=argparse.SUPPRESS)  # tests: OW_ROOT on the fake host
    a = p.parse_args(argv)
    try:
        host = rp.Host(a, section="upgrade")
        if a.phase == "status":
            out.write(status(host) + "\n")
            return 0
        rec, dry = run_phase(host, a, a.phase)
        if dry:
            out.write(dry + "\n")
            return 0
        args = " ".join(shlex.quote(x) for x in (argv if argv is not None else sys.argv[1:])
                        if x not in (a.phase, "--execute"))
        out.write("%s passed on %s. %s\n" % (a.phase, host.name, phase(a.phase).next_step.format(
            cmd="python3 -S scripts/release_upgrade.py", args=args)))
        return 0
    except (rp.PrepError, ec.CaptureError) as e:
        out.write("release_upgrade: %s\n" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
