#!/usr/bin/env python3
"""Release preparation: maintained steps that gather fleet evidence for the captain.

Every host command runs through scripts/evidence_capture.py. Its raw stdout,
stderr and exit status are kept, bound to the candidate and the host, and
verified after transfer. Every capture and transfer has an explicit timeout.
This tool prepares evidence; it records no verdict. Confirmations,
attestations, merging, tagging and publication stay with the release captain.

F2, staged remediation (release/gates.toml), runs in three phases against one
host. Each phase captures the same read-only snapshot (release/prep/
f2-host-snapshot.sh):

    python3 -S scripts/release_prep.py f2 preflight HOSTARGS
        # the host must report `enabled 2`; then apply the remediation in the UI
    python3 -S scripts/release_prep.py f2 staged HOSTARGS
        # prints the rollback prompt only after the staged capture verifies
    python3 -S scripts/release_prep.py f2 after HOSTARGS
        # refused unless the staged capture is present and verifies
    python3 -S scripts/release_prep.py f2 status HOSTARGS
    python3 -S scripts/release_prep.py f2 packet HOSTARGS

    HOSTARGS: --host NAME --ssh-target USER@ADDR [--ssh-key PATH]
              --tag vX.Y.Z --commit <40-hex> --evidence DIR

A phase runs the capture library on the host (sent over SSH standard input,
its digest recorded), then fetches the capture with tar and verifies its
checksums, candidate and machine id before naming it. Whether a phase may run
is derived from the verified captures on disk each time, never from a state
file, so a capture that is missing, altered or failed blocks the next phase.

Spec: release-preparation.
"""

import argparse
import difflib
import importlib.util
import json
import os
import re
import shlex
import sys
from pathlib import Path

_here = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("evidence_capture", _here / "evidence_capture.py")
ec = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ec)

LIBRARY = _here / "evidence_capture.py"
SNAPSHOT = _here.parent / "release" / "prep" / "f2-host-snapshot.sh"

SSH_OPTIONS = ["-q", "-o", "LogLevel=ERROR", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
# Added to a phase's own timeout for the SSH session that wraps it.
SSH_MARGIN = 60

_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")


class PrepError(Exception):
    """A step was refused or did not produce verified evidence."""


class Phase(object):
    def __init__(self, name, requires, timeout, transfer_timeout, next_step):
        self.name = name
        self.requires = requires
        self.timeout = timeout
        self.transfer_timeout = transfer_timeout
        self.next_step = next_step


# Explicit timeouts, in seconds, for every capture this tool makes. A phase
# without one cannot be declared (see _check_phases).
F2_PHASES = [
    Phase("preflight", (), 120, 120,
          "Next, in the OpenWatch UI: remediate the audit_rule_set rule on {host}. Wait until it "
          "shows as staged. Do not roll back yet. Then run:\n    {cmd} f2 staged {args}"),
    Phase("staged", ("preflight",), 120, 120,
          "Staged host evidence for {host} is captured and verified:\n    {path}\n"
          "Now record what the UI shows, roll the remediation back in the UI, then run:\n"
          "    {cmd} f2 after {args}"),
    Phase("after", ("preflight", "staged"), 120, 120,
          "All three F2 captures for {host} are verified. Build the review packet with:\n"
          "    {cmd} f2 packet {args}"),
]


def _check_phases(phases):
    for p in phases:
        for label, value in (("timeout", p.timeout), ("transfer_timeout", p.transfer_timeout)):
            if not isinstance(value, (int, float)) or not value > 0:
                raise PrepError("phase %s has no explicit positive %s" % (p.name, label))


def _phase(name):
    for p in F2_PHASES:
        if p.name == name:
            return p
    raise PrepError("unknown F2 phase %r" % name)


class Host(object):
    """How to reach one fleet host, and where its evidence lives on both ends."""

    def __init__(self, a):
        if not _HOST.match(a.host or ""):
            raise PrepError("--host must be a host name such as owas-rhn02")
        ec.check_candidate(a.tag, a.commit)
        self.name = a.host
        self.tag = a.tag
        self.commit = a.commit
        if a.transport:
            self.transport = json.loads(a.transport)
        else:
            if not a.ssh_target:
                raise PrepError("--ssh-target is required")
            self.transport = ["ssh"] + SSH_OPTIONS + (["-i", a.ssh_key] if a.ssh_key else []) \
                + [a.ssh_target]
        self.sudo = shlex.split(a.sudo)
        self.python = a.remote_python
        self.remote_dir = "%s/%s/f2" % (a.remote_dir.rstrip("/"), a.tag)
        self.local_dir = os.path.join(os.path.abspath(a.evidence), "f2", a.host)
        self.snapshot = a.snapshot

    def remote(self, *commands):
        """One remote shell command line joining the given argument vectors with &&."""
        return self.transport + [" && ".join(" ".join(shlex.quote(x) for x in c)
                                             for c in commands)]


def _verified(host, name, machine_id=None):
    """The record of a complete, verified capture with exit 0, or a PrepError."""
    path = os.path.join(host.local_dir, name)
    if not os.path.isdir(path):
        raise PrepError("no verified %s capture for %s (%s is missing)" % (name, host.name, path))
    try:
        rec = ec.verify_capture(path, tag=host.tag, commit=host.commit, machine_id=machine_id)
    except ec.VerifyError as e:
        raise PrepError("the %s capture for %s does not verify: %s" % (name, host.name, e))
    if (rec.get("exit") or {}).get("code") != 0:
        raise PrepError("the %s snapshot on %s ended with %s; see %s/stderr" % (
            name, host.name, ec._exit_text(rec["exit"]).strip(), path))
    # Belt and braces: a section that reported a failure fails the capture even
    # if the script's own status hid it.
    with open(os.path.join(path, "stdout"), "rb") as f:
        failed = _failed_sections(f.read())
    if failed:
        raise PrepError("the %s snapshot on %s has failed sections: %s; see %s" % (
            name, host.name, ", ".join("%s (exit %s)" % x for x in failed), path))
    if name == "f2-preflight":
        # The gate's precondition is part of what makes preflight usable, so it
        # is checked wherever preflight is relied on, not only when it runs.
        with open(os.path.join(path, "stdout"), "rb") as f:
            status = _sections(f.read()).get("auditctl -s", [])
        if "enabled 2" not in [l.strip() for l in status]:
            raise PrepError(
                "F2 needs a host whose `auditctl -s` reports `enabled 2`. %s does not; its "
                "capture is kept at %s. Choose another host." % (host.name, path))
    return rec


def _failed_sections(stdout_bytes):
    """(title, status) for every section whose '== exit N' line is not 0."""
    out = []
    title = None
    for line in stdout_bytes.decode("utf-8", "replace").splitlines():
        m = re.match(r"^== exit (\S+)$", line)
        if m:
            if m.group(1) != "0":
                out.append((title, m.group(1)))
        elif line.startswith("== "):
            title = line[3:]
    return out


def _sections(stdout_bytes):
    """Map section title -> body text, from the snapshot's '== title' lines."""
    out = {}
    title = None
    for line in stdout_bytes.decode("utf-8", "replace").splitlines():
        if line.startswith("== ") and not line.startswith("== exit "):
            title = line[3:]
            out[title] = []
        elif title is not None and not line.startswith("== exit "):
            out[title].append(line)
    return out


def run_phase(host, name):
    """Capture one F2 phase on the host, fetch it, verify it, and say what is next."""
    _check_phases(F2_PHASES)
    phase = _phase(name)
    machine_id = None
    for req in phase.requires:
        rec = _verified(host, "f2-" + req, machine_id)
        machine_id = machine_id or (rec.get("host") or {}).get("machine_id")
    os.makedirs(host.local_dir, mode=0o700, exist_ok=True)
    with open(host.snapshot) as f:
        snapshot = f.read()
    cap = "f2-" + phase.name
    run = host.remote(
        host.sudo + ["mkdir", "-p", "-m", "0700", host.remote_dir],
        host.sudo + [host.python, "-", "run", "--out", host.remote_dir, "--name", cap,
                     "--tag", host.tag, "--commit", host.commit,
                     "--timeout", str(phase.timeout),
                     "--purpose", "F2 %s snapshot of %s" % (phase.name, host.name),
                     "--", "sh", "-c", snapshot])
    try:
        rrec = ec.capture(run, host.local_dir, cap + ".remote-run", host.tag, host.commit,
                          timeout=phase.timeout + SSH_MARGIN, stdin_file=str(LIBRARY),
                          purpose="run the F2 %s capture on %s" % (phase.name, host.name))
    except ec.CaptureError as e:
        raise PrepError("the remote run of %s on %s did not complete: %s" % (cap, host.name, e))
    if rrec["exit"]["code"] != 0:
        raise PrepError(
            "the remote run of %s on %s ended with %s. Its raw output is in %s. The host's "
            "capture, if any, is in %s on the host; it was not fetched." % (
                cap, host.name, ec._exit_text(rrec["exit"]).strip(), rrec["path"],
                host.remote_dir))
    try:
        ec.fetch(host.remote(host.sudo + ["tar", "-C", host.remote_dir, "-cf", "-", cap]),
                 host.local_dir, cap, host.tag, host.commit, machine_id=machine_id,
                 timeout=phase.transfer_timeout)
    except ec.CaptureError as e:
        raise PrepError("the %s capture from %s was not accepted: %s" % (cap, host.name, e))
    return _verified(host, cap, machine_id)


def status(host):
    lines = []
    machine_id = None
    nxt = None
    for p in F2_PHASES:
        try:
            rec = _verified(host, "f2-" + p.name, machine_id)
            machine_id = machine_id or (rec.get("host") or {}).get("machine_id")
            lines.append("%-10s verified  %s" % (p.name, os.path.join(host.local_dir, "f2-" + p.name)))
        except PrepError as e:
            lines.append("%-10s not ready: %s" % (p.name, e))
            nxt = nxt or p.name
    lines.append("next: %s" % (nxt or "packet"))
    return "\n".join(lines)


def packet(host):
    """Write F2-PACKET.md from the three verified captures. Confirmations stay blank."""
    recs = {}
    machine_id = None
    for p in F2_PHASES:
        recs[p.name] = _verified(host, "f2-" + p.name, machine_id)
        machine_id = machine_id or (recs[p.name].get("host") or {}).get("machine_id")
    out = os.path.join(host.local_dir, "F2-PACKET.md")
    if os.path.lexists(out):
        raise PrepError("%s already exists; a packet is never overwritten" % out)
    raw = {}
    for p in F2_PHASES:
        with open(os.path.join(host.local_dir, "f2-" + p.name, "stdout"), "rb") as f:
            raw[p.name] = f.read().decode("utf-8", "replace")
    h = recs["preflight"].get("host") or {}
    doc = ["# F2 evidence packet: %s, %s" % (host.name, host.tag), "",
           "Prepared by scripts/release_prep.py. It records no verdict.", "",
           "- Candidate: `%s` at `%s`" % (host.tag, host.commit),
           "- Host: `%s`, machine-id `%s`" % (h.get("hostname"), h.get("machine_id")), ""]
    doc += ["## Captures", "", "| Phase | Captured (UTC) | Exit | stdout sha256 | Path |",
            "|---|---|---|---|---|"]
    for p in F2_PHASES:
        r = recs[p.name]
        doc.append("| %s | %s | %s | `%s` | `%s` |" % (
            p.name, r["invocation"]["started_at"], ec._exit_text(r["exit"]).strip(),
            r["streams"]["stdout"]["sha256"], os.path.join(host.local_dir, "f2-" + p.name)))
    doc += ["", "## Changes between captures (derived)", "",
            "Derived from the raw stdout files above, which are authoritative. "
            "Nothing was filtered; every differing line is shown.", ""]
    for a, b in (("preflight", "staged"), ("staged", "after"), ("preflight", "after")):
        diff = list(difflib.unified_diff(raw[a].splitlines(), raw[b].splitlines(),
                                         fromfile=a, tofile=b, lineterm=""))
        doc += ["### %s to %s" % (a, b), "", "```diff"] + (diff or ["(no differences)"]) \
            + ["```", ""]
    doc += ["## For the release captain", "",
            "Left blank on purpose. Only the captain fills these.", "",
            "- UI showed amber 'Staged, reboot required' with a working Roll back: ______",
            "- Observed by: ______",
            "- Observed at: ______", ""]
    data = "\n".join(doc).encode()
    tmp = out + ".partial"
    ec._write_new(tmp, data)
    os.rename(tmp, out)
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="gate")
    f2 = sub.add_parser("f2", help="F2, staged remediation")
    f2.add_argument("step", choices=[x.name for x in F2_PHASES] + ["status", "packet"])
    f2.add_argument("--host", required=True)
    f2.add_argument("--tag", required=True)
    f2.add_argument("--commit", required=True)
    f2.add_argument("--evidence", required=True, help="local evidence directory for this release")
    f2.add_argument("--ssh-target", help="USER@ADDRESS")
    f2.add_argument("--ssh-key")
    f2.add_argument("--sudo", default="sudo -n", help="privilege prefix on the host; '' as root")
    f2.add_argument("--remote-python", default="python3")
    f2.add_argument("--remote-dir", default="/root/openwatch-release-evidence")
    f2.add_argument("--snapshot", default=str(SNAPSHOT), help=argparse.SUPPRESS)
    f2.add_argument("--transport", help=argparse.SUPPRESS)  # tests: a JSON argv replacing ssh
    a = p.parse_args(argv)
    if a.gate != "f2":
        p.print_help(sys.stderr)
        return 2
    try:
        host = Host(a)
        if a.step == "status":
            print(status(host))
            return 0
        if a.step == "packet":
            print("packet written: %s" % packet(host))
            return 0
        rec = run_phase(host, a.step)
        args = " ".join(shlex.quote(x) for x in (argv if argv is not None else sys.argv[1:])
                        if x not in ("f2", a.step))
        print(_phase(a.step).next_step.format(
            host=host.name, path=rec.get("path") or os.path.join(host.local_dir, "f2-" + a.step),
            cmd="python3 -S scripts/release_prep.py", args=args))
        return 0
    except (PrepError, ec.CaptureError) as e:
        print("release_prep: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
