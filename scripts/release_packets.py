#!/usr/bin/env python3
"""Prepare the F1, F3 and D1 evidence packets for the release captain.

    python3 -S scripts/release_packets.py f1 HOSTARGS --scan-id UUID ARTIFACT
    python3 -S scripts/release_packets.py f3 HOSTARGS --token-file PATH-ON-HOST ARTIFACT
    python3 -S scripts/release_packets.py d1 --tag vX.Y.Z --commit <40-hex> --evidence DIR
                                             [--inherit-from PRIOR-REVIEW.toml]

    HOSTARGS: --host NAME --ssh-target USER@ADDR --ssh-key PATH --tag vX.Y.Z
              --commit <40-hex> --evidence DIR [--url URL]
    ARTIFACT: --sums SHA256SUMS --artifact NAME (the package the server runs,
              from the candidate's verified checksum list)

F1 and F3 read an OpenWatch server, read-only, after the release captain has
done the check in the UI: F1 reads the records of the scan the captain ran
(the tool never starts one), and F3 reads the scan variables the server
resolves. Each runs a maintained script from release/prep/packets/ on the
server through scripts/evidence_capture.py, then fetches and verifies the
capture. D1 runs scripts/doc-review-skeleton.py from this checkout, which must
be a clean commit, through the capture library.

Each writes a packet (Markdown) and an attestation skeleton (TOML). The
packet shows what the evidence says and where it is. The skeleton is bound to
the candidate and its artifact digest and leaves every human field blank:
performed_by, performed_at, the captain's confirmation and observation, and
every D1 verdict. This tool records no verdict and never writes one.

Spec: release-packets.
"""

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
import tomllib
from pathlib import Path

_here = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("release_prep", _here / "release_prep.py")
rp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rp)
ec = rp.ec

REPO = _here.parent
SCRIPTS = REPO / "release" / "prep" / "packets"
SKELETON = _here / "doc-review-skeleton.py"

# Explicit timeouts, in seconds, for every capture this tool makes.
READ_TIMEOUT = 300
TRANSFER_TIMEOUT = 300
D1_TIMEOUT = 300

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_ARTIFACT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]*$")


class PacketError(rp.PrepError):
    pass


class Gate(object):
    def __init__(self, name, kind, script, title):
        self.name, self.kind, self.script, self.title = name, kind, script, title


GATES = {
    "f1": Gate("F1", "fleet-scan", "f1-readings.sh", "Scan a real host end to end"),
    "f3": Gate("F3", "fleet-scan-variables", "f3-readings.sh",
               "Scan variables populate on a packaged install"),
}


def check_timeouts():
    for label, value in (("READ_TIMEOUT", READ_TIMEOUT), ("TRANSFER_TIMEOUT", TRANSFER_TIMEOUT),
                         ("D1_TIMEOUT", D1_TIMEOUT)):
        if not isinstance(value, (int, float)) or not value > 0:
            raise PacketError("%s is not an explicit positive timeout" % label)


def artifact_digest(sums, name):
    """(artifact sha256, sha256 of the checksum list) from the candidate's SHA256SUMS."""
    if not _ARTIFACT.match(name or ""):
        raise PacketError("--artifact must be a package file name such as openwatch-0.9.0-1.x86_64.rpm")
    try:
        with open(sums, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise PacketError("cannot read --sums %s: %s" % (sums, e))
    found = []
    for line in raw.decode("utf-8", "replace").splitlines():
        m = re.match(r"^([0-9a-f]{64}) [ *](.+)$", line)
        if m and m.group(2) == name:
            found.append(m.group(1))
    if len(found) != 1:
        raise PacketError("%s lists %s %d times, not once" % (sums, name, len(found)))
    return found[0], hashlib.sha256(raw).hexdigest()


def script_for(gate, env):
    with open(SCRIPTS / "common.sh") as f:
        common = f.read()
    with open(SCRIPTS / gate.script) as f:
        body = f.read()
    assigns = "".join("export %s=%s\n" % (k, shlex.quote(v)) for k, v in sorted(env.items()))
    # The assignments come first: common.sh derives its paths from them.
    return assigns + "\n" + common + "\n" + body


def _sections(host, cap):
    with open(os.path.join(host.local_dir, cap, "stdout"), "rb") as f:
        return rp._sections(f.read())


def _one(sections, title):
    lines = [l.strip() for l in sections.get(title, []) if l.strip()]
    if len(lines) != 1:
        raise PacketError("the %s section holds %d lines, not one" % (title, len(lines)))
    return lines[0]


def read_server(host, gate, env):
    """Run the gate's readings on the server; return (record, capture path)."""
    cap = gate.name.lower() + "-readings"
    if os.path.lexists(os.path.join(host.local_dir, cap)):
        raise PacketError("%s already exists; a capture is never taken twice under one name. "
                          "Move it aside and say so in the hand-off" %
                          os.path.join(host.local_dir, cap))
    rp.remote_capture(host, cap, script_for(gate, env), READ_TIMEOUT, TRANSFER_TIMEOUT, None,
                      "%s readings on %s" % (gate.name, host.name))
    path = os.path.join(host.local_dir, cap)
    rec = ec.verify_capture(path, tag=host.tag, commit=host.commit)
    with open(os.path.join(path, "stdout"), "rb") as f:
        failed = rp._failed_sections(f.read())
    if rec["exit"].get("code") != 0 or failed:
        raise PacketError("the %s readings on %s did not pass (%s%s); the raw capture is in %s. "
                          "No packet was written." % (
                              gate.name, host.name, ec._exit_text(rec["exit"]).strip(),
                              "; failed: %s" % ", ".join("%s (exit %s)" % f for f in failed)
                              if failed else "", path))
    return rec, path


# The build stamps `git rev-parse --short HEAD`, whose length git chooses.
_SHORT = re.compile(r"^[0-9a-f]{7,40}$")


def server_identity(s, host, path):
    """(version, commit) the server runs, checked against the candidate.

    Two sources, both required, and they must agree: the installed binary
    (openwatch --version) and the running service (GET /api/v1/version, a
    VersionResponse). A binary that matches behind a service that was not
    restarted is a mismatch. Raises PacketError naming every problem; the raw
    capture stays where it is."""
    want = host.tag[1:]
    problems, found = [], {}
    lines = [l.strip() for l in s.get("openwatch --version", []) if l.strip()]
    ver = [m.group(1) for m in (re.match(r"^openwatch (\S+)$", l) for l in lines) if m]
    com = [m.group(1) for m in (re.match(r"^commit:\s+(\S+)$", l) for l in lines) if m]
    if len(ver) != 1 or len(com) != 1:
        problems.append("openwatch --version does not report one version and one commit")
    else:
        found["binary"] = (ver[0], com[0])
    body = [l.strip() for l in s.get("version endpoint", []) if l.strip()]
    try:
        if not body or body[-1] != "http 200":
            raise ValueError("the version endpoint did not answer 200")
        d = json.loads(body[0])
        if not isinstance(d, dict) or not isinstance(d.get("openwatch"), str) \
                or not isinstance(d.get("commit"), str):
            raise ValueError("the version endpoint's body has no openwatch and commit strings")
        found["service"] = (d["openwatch"], d["commit"])
    except ValueError as e:
        problems.append(str(e))
    for source, (v, c) in sorted(found.items()):
        if v != want:
            problems.append("the %s reports version %s, not the candidate's %s" % (source, v, want))
        if not _SHORT.match(c):
            problems.append("the %s reports commit %r, not a commit id" % (source, c))
        elif not host.commit.startswith(c):
            problems.append("the %s reports commit %s, not the candidate's %s" % (
                source, c, host.commit[:12]))
    if len(found) == 2 and found["binary"] != found["service"]:
        problems.append("the installed binary (%s, %s) and the running service (%s, %s) differ; "
                        "was the service restarted?" % (found["binary"] + found["service"]))
    if problems:
        raise PacketError("%s does not run the candidate %s at %s: %s. The raw capture is in %s. "
                          "No packet was written." % (host.name, host.tag, host.commit[:12],
                                                      "; ".join(problems), path))
    return found["service"]


def upgrade_record(host, machine_id):
    """The Step 8 capture from scripts/release_upgrade.py for this server, or None.

    When it exists it must verify, come from the same machine and have ended in
    MATCH; the F1 scan must then have been queued after it finished."""
    path = os.path.join(os.path.dirname(os.path.dirname(host.local_dir)), "upgrade",
                        host.name, "upgrade-rules")
    if not os.path.isdir(path):
        return None
    try:
        rec = ec.verify_capture(path, tag=host.tag, commit=host.commit, machine_id=machine_id)
    except ec.VerifyError as e:
        raise PacketError("the Step 8 capture %s does not verify for this server: %s" % (path, e))
    with open(os.path.join(path, "stdout"), "rb") as f:
        if rec["exit"].get("code") != 0 or b"STEP 8 DONE: MATCH" not in f.read():
            raise PacketError("the Step 8 capture %s did not end in MATCH" % path)
    rec["path"] = path
    return rec


def _iso(ts):
    """A psql timestamptz ('2026-10-09 21:05:30.939461-04') as an aware datetime."""
    m = re.match(r"^(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d(?:\.\d+)?)([+-]\d\d)(?::?(\d\d))?$", ts)
    if not m:
        raise PacketError("cannot read the timestamp %r" % ts)
    off = int(m.group(3)) * 3600 + (int(m.group(4) or 0) * 60 * (1 if m.group(3)[0] == "+" else -1))
    base = datetime.datetime.fromisoformat(m.group(1) + "T" + m.group(2))
    return base.replace(tzinfo=datetime.timezone(datetime.timedelta(seconds=off)))


def _toml_str(s):
    return '"%s"' % s.replace("\\", "\\\\").replace('"', '\\"')


def _toml_block(s):
    return '"""\n%s\n"""' % s.replace("\\", "\\\\").replace('"""', '\\"""')


def write_new(path, text):
    if os.path.lexists(path):
        raise PacketError("%s already exists; a packet is never overwritten" % path)
    tmp = path + ".partial"
    ec._write_new(tmp, text.encode())
    os.rename(tmp, path)
    return path


def f1(host, a):
    if not _UUID.match(a.scan_id or ""):
        raise PacketError("--scan-id must be the scan's UUID, lower case, as the UI and API show it")
    sha, sums_sha = artifact_digest(a.sums, a.artifact)
    env = {"OW_URL": a.url, "OW_SCAN_ID": a.scan_id}
    if a.root:
        env["OW_ROOT"] = a.root
    rec, path = read_server(host, GATES["f1"], env)
    s = _sections(host, "f1-readings")
    version, commit = server_identity(s, host, path)
    hostname, machine_id = _one(s, "hostname"), _one(s, "machine-id")
    run = [l for l in s.get("scan run", []) if l.strip()]
    if len(run) != 2:
        raise PacketError("the scan run section holds %d lines, not a header and one row" % len(run))
    row = dict(zip([c.strip() for c in run[0].split("|")], [c.strip() for c in run[1].split("|")]))
    step8 = upgrade_record(host, (rec.get("host") or {}).get("machine_id"))
    if step8 is not None:
        finished = step8["invocation"].get("finished_at") or ""
        try:
            done = datetime.datetime.fromisoformat(finished.replace("Z", "+00:00"))
        except ValueError:
            raise PacketError("the Step 8 capture %s records no finish time" % step8["path"])
        if _iso(row["queued_at"]) <= done:
            raise PacketError("scan %s was queued at %s, before the Step 8 capture finished at %s; "
                              "a scan must follow Step 8's MATCH" % (
                                  a.scan_id, row["queued_at"], finished))
    readings = "\n".join(
        ["Server records, derived from %s (stdout sha256 %s), which is authoritative." % (
            path, rec["streams"]["stdout"]["sha256"]),
         "The server runs openwatch %s, commit %s: the binary and the running service agree, "
         "and match the candidate." % (version, commit),
         "Scan %s: status %s, trigger %s, requested_by %s." % (
             row["id"], row["status"], row["trigger_source"], row["requested_by"] or "(none)"),
         "Queued %s, started %s, finished %s." % (row["queued_at"], row["started_at"],
                                                 row["finished_at"]),
         "Run counts: %s pass, %s fail, %s skipped, %s error; engine %s, corpus %s." % (
             row["rules_pass"], row["rules_fail"], row["rules_skipped"], row["rules_error"],
             row["engine_version"] or "(not recorded)", row["corpus_version"] or "(not recorded)"),
         "Result rows by status: %s." % "; ".join(
             l.strip() for l in [x for x in s.get("result counts", []) if x.strip()][1:]),
         "The run's counts equal its result rows, and its audit trail holds one scan.queued and "
         "one scan.completed, bound by scan id and correlation id (consistency section).",
         "Step 8: %s." % ("MATCH in %s, finished before the scan was queued" % step8["path"]
                          if step8 else "no release_upgrade.py Step 8 capture for this server "
                          "in this evidence directory; the captain confirms Step 8 MATCH "
                          "preceded the scan")])
    return finish(host, GATES["f1"], a, sha, sums_sha, rec, path, hostname, machine_id, readings,
                  ["the scan id and its counts in the UI's Compliance view match these records",
                   "the scan was started by the captain from the UI after Step 8 MATCH"])


def f3(host, a):
    if not (a.token_file or "").startswith("/"):
        raise PacketError("--token-file must be an absolute path to a root-only file on the server")
    sha, sums_sha = artifact_digest(a.sums, a.artifact)
    env = {"OW_URL": a.url, "OW_TOKEN_FILE": a.token_file}
    if a.root:
        env["OW_ROOT"] = a.root
    rec, path = read_server(host, GATES["f3"], env)
    s = _sections(host, "f3-readings")
    version, commit = server_identity(s, host, path)
    hostname, machine_id = _one(s, "hostname"), _one(s, "machine-id")
    summary = [l.strip() for l in s.get("summary", []) if l.strip()]
    counts = dict(l.split(" ", 1) for l in summary if not l.startswith("name "))
    names = [l[5:] for l in summary if l.startswith("name ")]
    lines = ["Server records, derived from %s (stdout sha256 %s), which is authoritative." % (
                 path, rec["streams"]["stdout"]["sha256"]),
             "The server runs openwatch %s, commit %s: the binary and the running service "
             "agree, and match the candidate." % (version, commit),
             "GET /api/v1/system/scan/variables answered 200 with %s variables, %s needing "
             "organization settings (configure_me) and %s overridden." % (
                 counts.get("variables"), counts.get("configure_me"), counts.get("overridden"))]
    if a.prior_names:
        with open(a.prior_names) as f:
            prior = [l.strip() for l in f if l.strip()]
        added = sorted(set(names) - set(prior))
        removed = sorted(set(prior) - set(names))
        lines.append("Against %s (%d names): %s." % (
            a.prior_names, len(prior), "the same names" if not (added or removed) else
            "added %s; removed %s" % (added or "none", removed or "none")))
    return finish(host, GATES["f3"], a, sha, sums_sha, rec, path, hostname, machine_id,
                  "\n".join(lines),
                  ["Settings > Compliance policies lists these scan variables (not a blank panel)"])


def finish(host, gate, a, sha, sums_sha, rec, path, hostname, machine_id, readings, confirm):
    """Write the packet and the attestation skeleton. Every human field stays blank."""
    tag = host.tag
    base = os.path.join(host.local_dir, "attest-%s-%s-%s" % (gate.name, gate.kind, tag))
    skel = "\n".join([
        "# UNSIGNED SKELETON from scripts/release_packets.py. Not evidence until the release",
        "# captain performs the check and completes the captain fields; the tool records no",
        "# verdict. Gate %s (%s). Internal evidence: never committed or uploaded." % (
            gate.name, gate.title),
        "kind = %s" % _toml_str(gate.kind),
        "tag = %s" % _toml_str(tag),
        "commit = %s" % _toml_str(host.commit),
        "artifact = %s" % _toml_str(a.artifact),
        "artifact_sha256 = %s  # pragma: allowlist secret" % _toml_str(sha),
        "sums_sha256 = %s  # the SHA256SUMS this digest was read from" % _toml_str(sums_sha),
        "server = %s" % _toml_str("%s, machine-id %s" % (hostname, machine_id)),
        "",
        "# --- captain fields: complete these yourself ---",
        'performed_by = ""',
        'performed_at = ""',
        'captain_confirmation = ""',
        'observed = ""',
        "",
        "# --- prepared from the server's records; the checker does not read these ---",
        "server_records = %s" % _toml_block(readings),
        "evidence = [",
        "  %s," % _toml_str("%s (stdout sha256 %s)" % (path, rec["streams"]["stdout"]["sha256"])),
        "]", ""])
    try:
        tomllib.loads(skel)
    except tomllib.TOMLDecodeError as e:
        raise PacketError("internal: the skeleton is not valid TOML: %s" % e)
    pkt = "\n".join(
        ["# %s evidence packet: %s, %s" % (gate.name, host.name, tag), "",
         "Prepared by scripts/release_packets.py. It records no verdict.", "",
         "- Gate: %s, %s" % (gate.name, gate.title),
         "- Candidate: `%s` at `%s`" % (tag, host.commit),
         "- Artifact: `%s`, sha256 `%s`, from a SHA256SUMS with sha256 `%s`" % (
             a.artifact, sha, sums_sha),
         "- Server: `%s`, machine-id `%s`" % (hostname, machine_id),
         "- Capture: `%s`, taken %s, exit %s, stdout sha256 `%s`" % (
             path, rec["invocation"]["started_at"], ec._exit_text(rec["exit"]).strip(),
             rec["streams"]["stdout"]["sha256"]),
         "- Attestation skeleton: `%s.skeleton.toml`" % base, "",
         "## Server records (derived)", "", readings, "",
         "## For the release captain", "", "Left blank on purpose. Only the captain fills these.",
         ""] + ["- %s: ______" % c for c in confirm] +
        ["- Observed by: ______", "- Observed at: ______", ""])
    write_new(base + ".skeleton.toml", skel)
    return write_new(os.path.join(host.local_dir, "%s-PACKET.md" % gate.name), pkt)


def _git(repo, *args):
    p = subprocess.run(["git", "-C", str(repo)] + list(args), capture_output=True, text=True)
    if p.returncode != 0:
        raise PacketError("git %s failed: %s" % (" ".join(args), p.stderr.strip()))
    return p.stdout


def d1(a):
    """Generate the D1 skeleton through the capture library, from a clean checker commit."""
    ec.check_candidate(a.tag, a.commit)
    repo = a.repo or str(REPO)
    if _git(repo, "status", "--porcelain", "--untracked-files=no").strip():
        raise PacketError("this checkout has tracked changes; D1 needs the checker at a clean, "
                          "named commit")
    checker = _git(repo, "rev-parse", "HEAD").strip()
    local = os.path.join(os.path.abspath(a.evidence), "d1")
    os.makedirs(local, mode=0o700, exist_ok=True)
    cap = "d1-skeleton"
    if os.path.lexists(os.path.join(local, cap)):
        raise PacketError("%s already exists; a capture is never taken twice under one name" %
                          os.path.join(local, cap))
    argv = [sys.executable, "-S", a.skeleton or os.path.join(repo, "scripts", SKELETON.name),
            "--commit", a.commit, "--tag", a.tag]
    if a.inherit_from:
        argv += ["--inherit-from", os.path.abspath(a.inherit_from)]
    rec = ec.capture(argv, local, cap, a.tag, a.commit, timeout=D1_TIMEOUT, cwd=repo,
                     purpose="D1 skeleton for %s from checker %s" % (a.tag, checker))
    path = os.path.join(local, cap)
    rec = ec.verify_capture(path, tag=a.tag, commit=a.commit)
    if rec["exit"].get("code") != 0:
        raise PacketError("the skeleton generator ended with %s; its raw output is in %s" % (
            ec._exit_text(rec["exit"]).strip(), path))
    with open(os.path.join(path, "stdout"), "rb") as f:
        raw = f.read()
    try:
        doc = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise PacketError("the skeleton in %s is not TOML: %s" % (path, e))
    reviewed = doc.get("reviewed") or []
    inherited = doc.get("inherited") or []
    # The tool must not have produced a verdict or a signature, whatever the
    # generator does: refuse rather than hand the captain a filled-in review.
    if doc.get("performed_by") or doc.get("performed_at"):
        raise PacketError("the skeleton carries a performed_by or performed_at; refusing")
    filled = [r.get("path") for r in reviewed if r.get("verdict") != "pending"]
    if filled:
        raise PacketError("the skeleton carries a verdict other than pending for %s; refusing" %
                          filled)
    if not reviewed and not inherited:
        raise PacketError("the skeleton lists no documents; refusing")
    skel = write_new(os.path.join(local, "doc-review-%s.skeleton.toml" % a.tag), raw.decode())
    pkt = "\n".join(
        ["# D1 evidence packet: %s" % a.tag, "",
         "Prepared by scripts/release_packets.py. It records no verdict.", "",
         "- Candidate: `%s` at `%s`" % (a.tag, a.commit),
         "- Checker: scripts/doc-review-skeleton.py at `%s` (clean tree)" % checker,
         "- Inheriting from: %s" % ("`%s`" % os.path.abspath(a.inherit_from)
                                    if a.inherit_from else "nothing (every document reviewed)"),
         "- Capture: `%s`, taken %s, stdout sha256 `%s`" % (
             path, rec["invocation"]["started_at"], rec["streams"]["stdout"]["sha256"]),
         "- Skeleton: `%s` (byte-identical to the capture's stdout)" % skel, "",
         "## Documents", "",
         "%d to review (verdict pending), %d inherited from the prior review." % (
             len(reviewed), len(inherited)), "",
         "| Document | Blob | State |", "|---|---|---|"] +
        ["| `%s` | `%s` | to review |" % (r.get("path"), (r.get("blob") or "")[:12])
         for r in reviewed] +
        ["| `%s` | `%s` | inherited |" % (r.get("path"), (r.get("blob") or "")[:12])
         for r in inherited] +
        ["", "## For the reviewer", "",
         "Left blank on purpose. Only a human who has read each document fills these, in the "
         "skeleton: every verdict, performed_by, performed_at%s." % (
             ", and changes_reviewed" if a.inherit_from else ""), ""])
    return write_new(os.path.join(local, "D1-PACKET.md"), pkt)


def main(argv=None, out=sys.stdout):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="gate")
    for name in ("f1", "f3"):
        s = sub.add_parser(name)
        s.add_argument("--host", required=True)
        s.add_argument("--tag", required=True)
        s.add_argument("--commit", required=True)
        s.add_argument("--evidence", required=True)
        s.add_argument("--sums", required=True, help="the candidate's verified SHA256SUMS")
        s.add_argument("--artifact", required=True, help="the package the server runs")
        s.add_argument("--url", default="https://localhost:8443")
        s.add_argument("--ssh-target")
        s.add_argument("--ssh-key")
        s.add_argument("--sudo", default="sudo -n")
        s.add_argument("--remote-python", default="python3")
        s.add_argument("--remote-dir", default="/root/openwatch-release-evidence")
        s.add_argument("--transport", help=argparse.SUPPRESS)  # tests: a JSON argv replacing ssh
        s.add_argument("--root", help=argparse.SUPPRESS)  # tests: OW_ROOT on the fake server
        if name == "f1":
            s.add_argument("--scan-id", required=True, help="the scan the captain ran in the UI")
        else:
            s.add_argument("--token-file", required=True,
                           help="a root-only file ON THE SERVER with an owk_ token (system:read)")
            s.add_argument("--prior-names", help="a file of the previous release's variable names")
    s = sub.add_parser("d1")
    s.add_argument("--tag", required=True)
    s.add_argument("--commit", required=True)
    s.add_argument("--evidence", required=True)
    s.add_argument("--inherit-from", help="the last published release's documentation review")
    s.add_argument("--repo", help=argparse.SUPPRESS)  # tests: the checker checkout
    s.add_argument("--skeleton", help=argparse.SUPPRESS)  # tests: a generator to refuse
    a = p.parse_args(argv)
    if a.gate is None:
        p.print_help(sys.stderr)
        return 2
    try:
        check_timeouts()
        if a.gate == "d1":
            out.write("packet written: %s\n" % d1(a))
            return 0
        host = rp.Host(a, section="packets")
        out.write("packet written: %s\n" % (f1(host, a) if a.gate == "f1" else f3(host, a)))
        return 0
    except (rp.PrepError, ec.CaptureError, ec.VerifyError) as e:
        out.write("release_packets: %s\n" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
