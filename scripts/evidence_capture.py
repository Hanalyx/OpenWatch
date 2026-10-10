#!/usr/bin/env python3
"""Evidence capture for release preparation.

Every command whose output is release evidence runs through `capture`. It keeps
three raw records, written by the operating system and never filtered: the
command's stdout and stderr byte for byte, and its exit status. A display view
is made later from those files, and never replaces them.

    python3 -S scripts/evidence_capture.py run --out DIR --name NAME \\
        --tag v0.8.4 --commit <40-hex> [--purpose TEXT] [--timeout SECONDS] \\
        [--secret-env VAR ...] -- COMMAND [ARG ...]
    python3 -S scripts/evidence_capture.py verify DIR [--tag T --commit C]
        [--machine-id ID] [--allow-incomplete]
    python3 -S scripts/evidence_capture.py fetch --out DIR --name NAME \\
        --tag T --commit C [--machine-id ID] -- TRANSFER COMMAND [ARG ...]

One capture is one directory:

    stdout, stderr   the raw streams
    exit             "exit=N", "signal=N" or "not-started"
    record.json      what ran, for which candidate, on which host, when
    SHA256SUMS       sha256sum-compatible digests of the four files above

The directory appears under its final name only once it is complete and
checksummed. Until then it is a hidden `.NAME.partial-<id>` directory, so a
killed capture can never be mistaken for a finished one. A capture that did not
finish normally keeps what it captured, under a name that says so:
`NAME.interrupted`, `NAME.timed-out` or `NAME.not-started`.

A non-zero exit is evidence, not a capture failure: the capture is complete and
`exit` records the status. The `run` subcommand therefore exits 0 whenever the
capture is complete; read `exit` for the command's status.

Secrets never travel in arguments. Name the environment variables that hold
them with --secret-env: their values reach the command through its environment,
any argument containing one is refused before anything runs, and only the
variable names are recorded. If a secret value appears in stdout or stderr, the
streams are deleted rather than redacted, and the capture is kept as
`NAME.withheld-secret` with the record alone. Redaction would turn raw evidence
into a derived view.

This protects the secret values supplied to the capture, and nothing more. It
is not a scanner for every secret a command might print: a credential the
command reads or prints by itself, without being supplied, is kept like any
other output. Keep such commands out of evidence, or supply the value so it is
checked. The inline-credential check on arguments is a guard for common forms,
not a guarantee.

`fetch` brings a capture made on another host back to this one. The transfer
command (for example `ssh -q host sudo tar -C /root/evidence -cf - NAME`) must
write a tar of one capture directory to stdout. The transfer is itself captured
as `NAME.transfer`. The capture is unpacked into a hidden directory and checked
against its own SHA256SUMS, record and binding, and only then renamed to NAME.
When any check fails, everything that arrived is isolated in
`NAME.transfer-failed/`: `transfer/` (the transfer's capture), `received/`
(what was unpacked) and `REASON`. Neither subdirectory carries a capture name,
so neither ever verifies as evidence.

Checksums detect accidental change and inconsistent edits. They do not prove
who wrote a capture: anyone able to rewrite every file consistently can forge
one. Keep the evidence store's permissions and its own checksum manifest.

Standard library only; the tests run under `python3 -S`.
Spec: release-evidence-capture.
"""

import argparse
import datetime
import getpass
import hashlib
import json
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import threading
import time
import uuid

FORMAT = "openwatch-evidence-capture/1"

COMPLETE = "complete"
INTERRUPTED = "interrupted"
TIMED_OUT = "timed-out"
NOT_STARTED = "not-started"
WITHHELD = "withheld-secret"

# The directory name says how a capture ended, so a listing cannot pass an
# incomplete capture off as a complete one.
SUFFIX = {
    COMPLETE: "",
    INTERRUPTED: ".interrupted",
    TIMED_OUT: ".timed-out",
    NOT_STARTED: ".not-started",
    WITHHELD: ".withheld-secret",
}
TRANSFER_SUFFIXES = (".transfer", ".transfer-failed")

STREAMS = ("stdout", "stderr")
SUMS = "SHA256SUMS"
RECORD = "record.json"
EXIT = "exit"

# Seconds between asking an interrupted command to stop and killing it.
KILL_GRACE = 5.0
POLL = 0.1

# A shorter value would match ordinary output by chance, and it is too weak to
# be a real credential anyway.
MIN_SECRET_LEN = 8

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_TAG = re.compile(r"^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SUM_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$")

# A guard, not a guarantee: a credential written inline as key=value. The
# reliable rule is --secret-env, which also catches the value itself.
_INLINE_SECRET = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|dsn)=\S"
    r"|hlx_live_|://[^/\s:@]+:[^/\s@]+@")


class CaptureError(Exception):
    """The capture was refused or could not be written."""


class CaptureIncomplete(CaptureError):
    """The command was interrupted, timed out or never started.

    What was captured is kept at `path`, under a name that says so."""

    def __init__(self, message, path, record):
        CaptureError.__init__(self, message)
        self.path = path
        self.record = record


class SecretInEvidence(CaptureError):
    """A secret value appeared in a stream; the streams were deleted."""

    def __init__(self, message, path, record):
        CaptureError.__init__(self, message)
        self.path = path
        self.record = record


class VerifyError(CaptureError):
    """A capture directory does not match its checksums, record or binding."""


class TransferError(CaptureError):
    """A capture could not be brought back intact."""


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def _fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _library_sha256():
    try:
        return _sha256_file(os.path.abspath(__file__))
    except (NameError, OSError):
        # Run from stdin (`python3 - run ...` on a remote host): no file to hash.
        return None


def host_identity():
    """Who this host is, read here rather than supplied by the caller."""

    def read(path):
        try:
            with open(path) as f:
                return f.read().strip() or None
        except OSError:
            return None

    return {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "machine_id": read("/etc/machine-id"),
        "boot_id": read("/proc/sys/kernel/random/boot_id"),
    }


def check_name(name, transfer=False):
    """Refuse a name that could pass for another capture's state.

    `transfer` admits the one internal name fetch() gives its own transfer
    capture, NAME.transfer.
    """
    if transfer:
        if not isinstance(name, str) or not name.endswith(".transfer"):
            raise CaptureError("transfer capture name %r must end with .transfer" % (name,))
        name = name[:-len(".transfer")]
    if not isinstance(name, str) or not _NAME.match(name):
        raise CaptureError("capture name %r: use letters, digits, '.', '_' and '-', "
                           "starting with a letter or digit" % (name,))
    for suffix in list(SUFFIX.values()) + list(TRANSFER_SUFFIXES):
        if suffix and name.endswith(suffix):
            raise CaptureError("capture name %r ends with the reserved suffix %r" % (name, suffix))
    if ".partial-" in name:
        raise CaptureError("capture name %r contains the reserved '.partial-'" % (name,))


def check_candidate(tag, commit):
    if not isinstance(tag, str) or not _TAG.match(tag):
        raise CaptureError("candidate tag %r is not a release tag such as v0.8.4" % (tag,))
    if not isinstance(commit, str) or not _COMMIT.match(commit):
        raise CaptureError("candidate commit must be a full 40-character lowercase SHA")


def _check_secrets(secrets, argv, others):
    for env_name, value in secrets.items():
        if not isinstance(value, str) or len(value) < MIN_SECRET_LEN:
            raise CaptureError("secret %s is unset or shorter than %d characters"
                               % (env_name, MIN_SECRET_LEN))
        for arg in list(argv) + list(others):
            if value in arg:
                raise CaptureError("the value of secret %s appears in the command or its "
                                   "binding; pass it through the environment only" % env_name)
    for arg in argv:
        if _INLINE_SECRET.search(arg):
            raise CaptureError("argument %r looks like an inline credential; put the value "
                               "in an environment variable named with --secret-env"
                               % (arg[:24] + ("..." if len(arg) > 24 else ""),))


def _find_secrets(path, secrets):
    """Names of the secrets whose values occur in the file, chunk-boundary safe."""
    if not secrets:
        return []
    values = dict((k, v.encode()) for k, v in secrets.items())
    keep = max(len(v) for v in values.values()) - 1
    hits = set()
    tail = b""
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            buf = tail + chunk
            for k, v in values.items():
                if v in buf:
                    hits.add(k)
            tail = buf[-keep:] if keep else b""
    return sorted(hits)


def _exit_text(exit_info):
    if exit_info.get("start_error") is not None:
        return "not-started\n"
    if exit_info.get("signal") is not None:
        return "signal=%d\n" % exit_info["signal"]
    return "exit=%d\n" % exit_info["code"]


def _signal_group(proc, sig):
    try:
        os.killpg(proc.pid, sig)
    except OSError:
        pass


def _final_path(out_dir, name, status):
    return os.path.join(out_dir, name + SUFFIX[status])


def _seal(tmp, record, out_dir, final):
    """Write exit, record and SHA256SUMS, then publish the directory by rename."""
    _write_new(os.path.join(tmp, EXIT), _exit_text(record["exit"]).encode())
    _write_new(os.path.join(tmp, RECORD),
               (json.dumps(record, indent=2, sort_keys=True) + "\n").encode())
    names = sorted(n for n in os.listdir(tmp) if n != SUMS)
    sums = "".join("%s  %s\n" % (_sha256_file(os.path.join(tmp, n)), n) for n in names)
    _write_new(os.path.join(tmp, SUMS), sums.encode())
    _fsync_dir(tmp)
    if os.path.lexists(final):
        raise CaptureError("%s appeared while capturing; the capture is left at %s" % (final, tmp))
    os.rename(tmp, final)
    _fsync_dir(out_dir)


def capture(argv, out_dir, name, tag, commit, secrets=None, timeout=None, purpose="",
            cwd=None, host=None, _transfer=False):
    """Run argv and keep its raw stdout, stderr and exit status as evidence.

    Returns the record of a complete capture. Raises CaptureIncomplete for an
    interrupted, timed-out or unstartable command, SecretInEvidence when a
    secret reached a stream, and CaptureError when the capture was refused.
    """
    argv = list(argv)
    if not argv:
        raise CaptureError("no command to capture")
    check_name(name, transfer=_transfer)
    check_candidate(tag, commit)
    secrets = dict(secrets or {})
    _check_secrets(secrets, argv, [name, purpose, out_dir, cwd or ""])
    out_dir = os.path.abspath(out_dir)
    if not os.path.isdir(out_dir):
        raise CaptureError("output directory %s does not exist" % out_dir)
    for status in SUFFIX:
        if os.path.lexists(_final_path(out_dir, name, status)):
            raise CaptureError("%s already exists; a capture is never overwritten"
                               % _final_path(out_dir, name, status))

    inv_id = str(uuid.uuid4())
    tmp = os.path.join(out_dir, ".%s.partial-%s" % (name, inv_id))
    os.mkdir(tmp, 0o700)
    record = {
        "format": FORMAT,
        "name": name,
        "purpose": purpose,
        "candidate": {"tag": tag, "commit": commit},
        "host": host if host is not None else host_identity(),
        "invocation": {
            "id": inv_id,
            "argv": argv,
            "cwd": os.path.abspath(cwd or os.getcwd()),
            "operator": getpass.getuser(),
            "secret_env": sorted(secrets),
            "timeout_seconds": timeout,
            "capturer": {"python": sys.version.split()[0], "library_sha256": _library_sha256()},
        },
    }

    env = os.environ.copy()
    env.update(secrets)
    fds = dict((s, os.open(os.path.join(tmp, s), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
               for s in STREAMS)
    caught = []
    timed_out = False
    record["invocation"]["started_at"] = _now()
    try:
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=fds["stdout"],
                                    stderr=fds["stderr"], env=env, cwd=cwd,
                                    start_new_session=True)
        except OSError as e:
            exit_info = {"code": None, "signal": None, "start_error": str(e)}
        else:
            stop_requested = [None]

            def on_signal(signum, _frame):
                caught.append(signum)
                if stop_requested[0] is None:
                    stop_requested[0] = time.monotonic()
                _signal_group(proc, signal.SIGTERM)

            handled = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
            previous = {}
            if threading.current_thread() is threading.main_thread():
                for s in handled:
                    previous[s] = signal.signal(s, on_signal)
            started = time.monotonic()
            try:
                while True:
                    try:
                        rc = proc.wait(timeout=POLL)
                        break
                    except subprocess.TimeoutExpired:
                        pass
                    now = time.monotonic()
                    if timeout is not None and not timed_out and now - started > timeout:
                        timed_out = True
                        stop_requested[0] = now
                        _signal_group(proc, signal.SIGTERM)
                    if stop_requested[0] is not None and now - stop_requested[0] > KILL_GRACE:
                        _signal_group(proc, signal.SIGKILL)
            finally:
                for s, h in previous.items():
                    signal.signal(s, h)
            if caught or timed_out:
                # Anything the command started in its session goes too.
                _signal_group(proc, signal.SIGKILL)
            exit_info = {"code": rc if rc >= 0 else None, "signal": -rc if rc < 0 else None,
                         "start_error": None}
    finally:
        for fd in fds.values():
            os.fsync(fd)
            os.close(fd)
    record["invocation"]["finished_at"] = _now()

    if exit_info.get("start_error") is not None:
        status = NOT_STARTED
    elif caught:
        status = INTERRUPTED
        exit_info["interrupted_by"] = signal.Signals(caught[0]).name
    elif timed_out:
        status = TIMED_OUT
    else:
        status = COMPLETE
    exit_info["timed_out"] = timed_out
    record["exit"] = exit_info

    leaks = []
    for s in STREAMS:
        for env_name in _find_secrets(os.path.join(tmp, s), secrets):
            leaks.append({"stream": s, "secret_env": env_name})
    if leaks:
        record["status"] = WITHHELD
        record["withheld"] = leaks
        record["streams"] = dict((s, {"bytes": os.path.getsize(os.path.join(tmp, s))})
                                 for s in STREAMS)
        record["status_before_withholding"] = status
        for s in STREAMS:
            os.unlink(os.path.join(tmp, s))
        final = _final_path(out_dir, name, WITHHELD)
        _seal(tmp, record, out_dir, final)
        raise SecretInEvidence(
            "a secret (%s) appeared in %s; the streams were deleted and only the record "
            "is kept at %s" % (", ".join(sorted(set(l["secret_env"] for l in leaks))),
                               ", ".join(sorted(set(l["stream"] for l in leaks))), final),
            final, record)

    record["status"] = status
    record["streams"] = dict(
        (s, {"bytes": os.path.getsize(os.path.join(tmp, s)),
             "sha256": _sha256_file(os.path.join(tmp, s))}) for s in STREAMS)
    final = _final_path(out_dir, name, status)
    _seal(tmp, record, out_dir, final)
    if status != COMPLETE:
        raise CaptureIncomplete("capture %s is %s; what was captured is kept at %s"
                                % (name, status, final), final, record)
    record["path"] = final
    return record


def verify_capture(path, tag=None, commit=None, machine_id=None, allow_incomplete=False,
                   dirname=None):
    """Check a capture directory against its SHA256SUMS, record and binding.

    Returns the record. `dirname` stands in for the directory's own name when
    the directory is still at a temporary path.
    """
    path = os.path.abspath(path)
    base = dirname or os.path.basename(path)
    try:
        entries = sorted(os.listdir(path))
    except OSError as e:
        raise VerifyError("cannot read capture %s: %s" % (path, e))
    for e in entries:
        st = os.lstat(os.path.join(path, e))
        if not stat.S_ISREG(st.st_mode):
            raise VerifyError("%s: %s is not a regular file" % (base, e))
    if SUMS not in entries:
        raise VerifyError("%s: no %s" % (base, SUMS))
    with open(os.path.join(path, SUMS), "rb") as f:
        raw = f.read()
    listed = {}
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise VerifyError("%s: %s is not ASCII" % (base, SUMS))
    for line in text.splitlines():
        m = _SUM_LINE.match(line)
        if not m:
            raise VerifyError("%s: malformed %s line %r" % (base, SUMS, line[:80]))
        if m.group(2) in listed:
            raise VerifyError("%s: %s lists %s twice" % (base, SUMS, m.group(2)))
        listed[m.group(2)] = m.group(1)
    present = set(entries) - {SUMS}
    if set(listed) != present:
        raise VerifyError("%s: files not listed in %s: %s; listed but missing: %s" % (
            base, SUMS, sorted(present - set(listed)) or "none",
            sorted(set(listed) - present) or "none"))
    for n, want in sorted(listed.items()):
        if _sha256_file(os.path.join(path, n)) != want:
            raise VerifyError("%s: %s does not match its checksum" % (base, n))
    if RECORD not in present or EXIT not in present:
        raise VerifyError("%s: %s and %s are required" % (base, RECORD, EXIT))
    try:
        with open(os.path.join(path, RECORD)) as f:
            record = json.load(f)
    except ValueError as e:
        raise VerifyError("%s: %s is not JSON: %s" % (base, RECORD, e))
    if not isinstance(record, dict) or record.get("format") != FORMAT:
        raise VerifyError("%s: not a %s record" % (base, FORMAT))
    status = record.get("status")
    if status not in SUFFIX:
        raise VerifyError("%s: unknown status %r" % (base, status))
    if base != record.get("name", "") + SUFFIX[status]:
        raise VerifyError("%s: the directory name does not match the record's name %r and "
                          "status %r" % (base, record.get("name"), status))
    want_files = {RECORD, EXIT} | (set() if status == WITHHELD else set(STREAMS))
    if present != want_files:
        raise VerifyError("%s: a %s capture holds %s, found %s" % (
            base, status, sorted(want_files), sorted(present)))
    with open(os.path.join(path, EXIT)) as f:
        if f.read() != _exit_text(record.get("exit") or {}):
            raise VerifyError("%s: %s disagrees with the record" % (base, EXIT))
    exit_info = record.get("exit") or {}
    if status == COMPLETE and (exit_info.get("start_error") is not None
                               or exit_info.get("interrupted_by") is not None
                               or exit_info.get("timed_out") is not False):
        raise VerifyError("%s: the record says complete, but its exit record says the "
                          "command was interrupted, timed out or never started" % base)
    if status != WITHHELD:
        for s in STREAMS:
            meta = (record.get("streams") or {}).get(s) or {}
            p = os.path.join(path, s)
            if meta.get("sha256") != listed[s] or meta.get("bytes") != os.path.getsize(p):
                raise VerifyError("%s: %s disagrees with the record" % (base, s))
    cand = record.get("candidate") or {}
    if tag is not None and cand.get("tag") != tag:
        raise VerifyError("%s: captured for %r, not %r" % (base, cand.get("tag"), tag))
    if commit is not None and cand.get("commit") != commit:
        raise VerifyError("%s: captured for commit %r, not %r" % (base, cand.get("commit"), commit))
    if machine_id is not None and (record.get("host") or {}).get("machine_id") != machine_id:
        raise VerifyError("%s: captured on machine-id %r, not %r" % (
            base, (record.get("host") or {}).get("machine_id"), machine_id))
    if status != COMPLETE and not allow_incomplete:
        raise VerifyError("%s: the capture is %s, not complete" % (base, status))
    return record


def _extract_one_capture(tar_path, dest):
    """Unpack a tar holding exactly one capture directory of regular files.

    Returns the directory's name. Links, devices, nested paths, absolute paths
    and '..' are refused before anything is written.
    """
    with tarfile.open(tar_path, "r:") as tf:
        members = tf.getmembers()
        if not members:
            raise TransferError("the transfer held no files")
        tops = set()
        files = []
        for m in members:
            name = m.name[2:] if m.name.startswith("./") else m.name
            parts = name.rstrip("/").split("/")
            if name.startswith("/") or any(p in ("", ".", "..") for p in parts) or len(parts) > 2:
                raise TransferError("refused tar member %r" % m.name)
            tops.add(parts[0])
            if len(parts) == 1:
                if not m.isdir():
                    raise TransferError("refused tar member %r: not inside a capture directory"
                                        % m.name)
                continue
            if not m.isreg():
                raise TransferError("refused tar member %r: not a regular file" % m.name)
            files.append((parts[1], m))
        if len(tops) != 1:
            raise TransferError("the transfer held %d top-level directories, not one"
                                % len(tops))
        seen = set()
        for fname, m in files:
            if fname in seen:
                raise TransferError("the transfer held %s twice" % fname)
            seen.add(fname)
            src = tf.extractfile(m)
            data = src.read()
            if len(data) != m.size:
                raise TransferError("%s arrived truncated" % fname)
            _write_new(os.path.join(dest, fname), data)
        _fsync_dir(dest)
        return tops.pop()


def _quarantine(out_dir, name, transfer_path, received_path, reason):
    """Isolate everything from a failed transfer in NAME.transfer-failed.

    The directory holds `transfer/` (the transfer's own capture), `received/`
    (whatever was unpacked) and `REASON`. Neither subdirectory carries its
    capture's name, so verify_capture refuses both: failed material can be
    read for diagnosis but never accepted as evidence.
    """
    failed = os.path.join(out_dir, name + ".transfer-failed")
    os.mkdir(failed, 0o700)
    if transfer_path is not None:
        os.rename(transfer_path, os.path.join(failed, "transfer"))
    if received_path is not None:
        _fsync_dir(received_path)
        os.rename(received_path, os.path.join(failed, "received"))
    _write_new(os.path.join(failed, "REASON"), (reason + "\n").encode())
    _fsync_dir(failed)
    _fsync_dir(out_dir)
    return failed


def fetch(transfer_argv, out_dir, name, tag, commit, machine_id=None, allow_incomplete=False,
          timeout=None):
    """Bring back a capture made elsewhere, verified before it is named.

    Returns the record. Raises TransferError when the transfer failed or the
    capture does not verify; everything that arrived is then isolated in
    NAME.transfer-failed (see _quarantine).
    """
    check_name(name)
    check_candidate(tag, commit)
    out_dir = os.path.abspath(out_dir)
    failed = os.path.join(out_dir, name + ".transfer-failed")
    for status in SUFFIX:
        if os.path.lexists(_final_path(out_dir, name, status)):
            raise CaptureError("%s already exists" % _final_path(out_dir, name, status))
    if os.path.lexists(failed):
        raise CaptureError("%s already exists; move it aside before retrying" % failed)
    tname = name + ".transfer"
    try:
        trec = capture(transfer_argv, out_dir, tname, tag, commit, timeout=timeout,
                       purpose="transfer of capture %s" % name, _transfer=True)
    except CaptureIncomplete as e:
        reason = "the transfer did not finish (%s)" % e.record["status"]
        failed = _quarantine(out_dir, name, e.path, None, reason)
        raise TransferError("capture %s: %s; isolated in %s" % (name, reason, failed))
    tpath = trec["path"]
    if trec["exit"]["code"] != 0:
        reason = ("the transfer command ended with %s; see transfer/stderr"
                  % _exit_text(trec["exit"]).strip())
        failed = _quarantine(out_dir, name, tpath, None, reason)
        raise TransferError("capture %s: %s; isolated in %s" % (name, reason, failed))

    tmp = os.path.join(out_dir, ".%s.partial-%s" % (name, uuid.uuid4()))
    os.mkdir(tmp, 0o700)
    try:
        top = _extract_one_capture(os.path.join(tpath, "stdout"), tmp)
        if top != name and not (allow_incomplete and top in
                                [name + s for s in SUFFIX.values() if s]):
            raise TransferError("the transfer held capture %r, not %r" % (top, name))
        record = verify_capture(tmp, tag=tag, commit=commit, machine_id=machine_id,
                                allow_incomplete=allow_incomplete, dirname=top)
        final = os.path.join(out_dir, top)
        if os.path.lexists(final):
            raise TransferError("%s appeared during the transfer" % final)
    except Exception as e:  # anything that arrived is isolated for diagnosis
        reason = "the capture did not arrive intact: %s" % e
        failed = _quarantine(out_dir, name, tpath, tmp, reason)
        raise TransferError("capture %s: %s; isolated in %s" % (name, reason, failed))
    os.rename(tmp, final)
    _fsync_dir(out_dir)
    record["path"] = final
    record["transfer"] = tpath
    return record


def _summary(record):
    return json.dumps({"path": record.get("path"), "status": record.get("status"),
                       "exit": _exit_text(record.get("exit") or {}).strip()}, sort_keys=True)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd")

    r = sub.add_parser("run", help="capture one command")
    r.add_argument("--out", required=True)
    r.add_argument("--name", required=True)
    r.add_argument("--tag", required=True)
    r.add_argument("--commit", required=True)
    r.add_argument("--purpose", default="")
    r.add_argument("--timeout", type=float)
    r.add_argument("--secret-env", action="append", default=[],
                   help="environment variable holding a secret; repeatable")
    r.add_argument("command", nargs=argparse.REMAINDER)

    v = sub.add_parser("verify", help="check a capture directory")
    v.add_argument("path")
    v.add_argument("--tag")
    v.add_argument("--commit")
    v.add_argument("--machine-id")
    v.add_argument("--allow-incomplete", action="store_true")

    f = sub.add_parser("fetch", help="bring back a capture made on another host")
    f.add_argument("--out", required=True)
    f.add_argument("--name", required=True)
    f.add_argument("--tag", required=True)
    f.add_argument("--commit", required=True)
    f.add_argument("--machine-id")
    f.add_argument("--allow-incomplete", action="store_true")
    f.add_argument("--timeout", type=float)
    f.add_argument("command", nargs=argparse.REMAINDER)

    a = p.parse_args(argv)

    def command():
        cmd = list(a.command)
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]
        if not cmd:
            p.error("give the command after --")
        return cmd

    try:
        if a.cmd == "run":
            secrets = {}
            for env_name in a.secret_env:
                if env_name not in os.environ:
                    raise CaptureError("secret variable %s is not set" % env_name)
                secrets[env_name] = os.environ[env_name]
            rec = capture(command(), a.out, a.name, a.tag, a.commit, secrets=secrets,
                          timeout=a.timeout, purpose=a.purpose)
            print(_summary(rec))
            return 0
        if a.cmd == "verify":
            rec = verify_capture(a.path, tag=a.tag, commit=a.commit, machine_id=a.machine_id,
                                 allow_incomplete=a.allow_incomplete)
            rec["path"] = os.path.abspath(a.path)
            print(_summary(rec))
            return 0
        if a.cmd == "fetch":
            rec = fetch(command(), a.out, a.name, a.tag, a.commit, machine_id=a.machine_id,
                        allow_incomplete=a.allow_incomplete, timeout=a.timeout)
            print(_summary(rec))
            return 0
        p.print_help(sys.stderr)
        return 2
    except CaptureIncomplete as e:
        print("evidence_capture: %s" % e, file=sys.stderr)
        by = (e.record.get("exit") or {}).get("interrupted_by")
        if by:
            return 128 + int(getattr(signal, by))
        return 4
    except SecretInEvidence as e:
        print("evidence_capture: %s" % e, file=sys.stderr)
        return 3
    except CaptureError as e:
        print("evidence_capture: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
