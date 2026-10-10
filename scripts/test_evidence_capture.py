#!/usr/bin/env python3
"""Tests for the release evidence-capture library.

    python3 -S scripts/test_evidence_capture.py

Each class is one criterion of spec release-evidence-capture; the Go test
packaging/tests/evidence_capture_test.go counts the passing cases per class so
a deleted case is noticed. No network. Real processes, real signals, real tar.
"""

import importlib.util
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from pathlib import Path

_here = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("evidence_capture", _here / "evidence_capture.py")
ec = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ec)

SCRIPT = str(_here / "evidence_capture.py")
TAG = "v0.8.4"
COMMIT = "474d9af26e457fc6a47b5475fab87394433a687b"  # pragma: allowlist secret
OTHER_COMMIT = "92ea8fc534981208dd9b25624aeee6079df9b59c"  # pragma: allowlist secret
HOST = {"hostname": "test-host", "fqdn": "test-host.example", "machine_id": "m" * 32,
        "boot_id": "b-1"}
SECRET = "s3cr3t-value-for-tests-only"  # pragma: allowlist secret

# The banner words that deleted a real evidence line on 2026-10-09.
BANNER_LINES = (b"-rw-r--r--. 1 root root 2201 Aug  9 privileged.rules\n"
                b"You are accessing a U.S. Government (USG) Information System\n"
                b"device purpose communications consent\n")


def sh(script):
    return ["sh", "-c", script]


class Case(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="evcap-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def run_capture(self, argv, name="cap", **kw):
        kw.setdefault("host", HOST)
        return ec.capture(argv, self.dir, name, TAG, COMMIT, **kw)

    def read(self, *parts):
        with open(os.path.join(self.dir, *parts), "rb") as f:
            return f.read()

    def listing(self):
        return sorted(os.listdir(self.dir))

    def cli(self, *args, env=None, **popen):
        e = os.environ.copy()
        e.update(env or {})
        return subprocess.Popen([sys.executable, "-S", SCRIPT] + list(args),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=e, **popen)

    def wait_for(self, pred, seconds=10):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if pred():
                return True
            time.sleep(0.05)
        return False


def kill_quietly(pid):
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def pid_alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    # A zombie still answers kill(0); read its state.
    try:
        with open("/proc/%d/stat" % pid) as f:
            return f.read().split(")")[-1].split()[0] != "Z"
    except OSError:
        return False


class CaptureRawStreams(Case):
    """AC-01: raw stdout, raw stderr and the exit status, byte for byte."""

    def test_streams_are_byte_exact(self):
        payload = BANNER_LINES + b"\x00\xff\xfe not utf-8 \r\n no trailing newline"
        src = os.path.join(self.dir, "payload.bin")
        with open(src, "wb") as f:
            f.write(payload)
        rec = self.run_capture(sh("cat '%s'; printf 'err\\n\\001' >&2" % src))
        self.assertEqual(self.read("cap", "stdout"), payload)
        self.assertEqual(self.read("cap", "stderr"), b"err\n\x01")
        self.assertEqual(self.read("cap", "exit"), b"exit=0\n")
        self.assertEqual(rec["status"], ec.COMPLETE)

    def test_banner_words_are_never_filtered(self):
        self.run_capture(sh("printf '%%s' '%s'" % BANNER_LINES.decode()))
        self.assertIn(b"privileged.rules", self.read("cap", "stdout"))

    def test_nonzero_exit_is_complete_evidence(self):
        rec = self.run_capture(sh("echo partial; exit 7"))
        self.assertEqual(rec["status"], ec.COMPLETE)
        self.assertEqual(rec["exit"]["code"], 7)
        self.assertEqual(self.read("cap", "exit"), b"exit=7\n")
        self.assertEqual(self.read("cap", "stdout"), b"partial\n")

    def test_death_by_signal_is_recorded(self):
        rec = self.run_capture(sh("echo before; kill -9 $$"))
        self.assertEqual(rec["exit"]["signal"], 9)
        self.assertIsNone(rec["exit"]["code"])
        self.assertEqual(self.read("cap", "exit"), b"signal=9\n")

    def test_large_output_is_intact(self):
        rec = self.run_capture(sh("head -c 6000000 /dev/zero | tr '\\0' 'x'"))
        self.assertEqual(rec["streams"]["stdout"]["bytes"], 6000000)
        self.assertEqual(os.path.getsize(os.path.join(self.dir, "cap", "stdout")), 6000000)

    def test_record_hashes_match_the_streams(self):
        rec = self.run_capture(sh("echo out; echo err >&2"))
        import hashlib
        for s in ("stdout", "stderr"):
            self.assertEqual(rec["streams"][s]["sha256"],
                             hashlib.sha256(self.read("cap", s)).hexdigest())

    def test_cli_run_exits_zero_and_reports_the_command_status(self):
        p = self.cli("run", "--out", self.dir, "--name", "c", "--tag", TAG, "--commit", COMMIT,
                     "--", "sh", "-c", "echo hi; exit 3")
        out, err = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 0, err)
        summary = json.loads(out)
        self.assertEqual(summary["status"], "complete")
        self.assertEqual(summary["exit"], "exit=3")
        self.assertEqual(self.read("c", "stdout"), b"hi\n")


class CaptureAtomicWrite(Case):
    """AC-02: a capture appears under its final name only when sealed."""

    def test_only_the_final_directory_remains(self):
        self.run_capture(["true"])
        self.assertEqual(self.listing(), ["cap"])
        self.assertEqual(sorted(os.listdir(os.path.join(self.dir, "cap"))),
                         ["SHA256SUMS", "exit", "record.json", "stderr", "stdout"])

    def test_files_are_owner_only(self):
        self.run_capture(["true"])
        for n in os.listdir(os.path.join(self.dir, "cap")):
            mode = os.stat(os.path.join(self.dir, "cap", n)).st_mode & 0o777
            self.assertEqual(mode, 0o600, n)

    def test_existing_capture_is_never_overwritten(self):
        self.run_capture(sh("echo first"))
        with self.assertRaises(ec.CaptureError):
            self.run_capture(sh("echo second"))
        self.assertEqual(self.read("cap", "stdout"), b"first\n")

    def test_an_incomplete_capture_also_blocks_the_name(self):
        with self.assertRaises(ec.CaptureIncomplete):
            self.run_capture(sh("sleep 5"), timeout=0.2)
        with self.assertRaises(ec.CaptureError):
            self.run_capture(["true"])

    def test_sums_are_sha256sum_compatible(self):
        if not shutil.which("sha256sum"):
            self.skipTest("sha256sum not installed")
        self.run_capture(sh("echo x"))
        r = subprocess.run(["sha256sum", "--check", "--strict", "SHA256SUMS"],
                           cwd=os.path.join(self.dir, "cap"),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_killed_capturer_leaves_no_final_directory(self):
        pidfile = os.path.join(self.dir, "child.pid")
        out = os.path.join(self.dir, "out")
        os.mkdir(out)
        p = self.cli("run", "--out", out, "--name", "k", "--tag", TAG, "--commit", COMMIT,
                     "--", "sh", "-c", "echo $$ > '%s'; echo started; exec sleep 30" % pidfile)
        self.assertTrue(self.wait_for(lambda: os.path.exists(pidfile)
                                      and os.path.getsize(pidfile) > 0))
        p.kill()
        p.communicate(timeout=10)
        with open(pidfile) as f:
            child = int(f.read())
        try:
            os.kill(child, signal.SIGKILL)
        except OSError:
            pass
        names = os.listdir(out)
        self.assertEqual(len(names), 1, names)
        self.assertTrue(names[0].startswith(".k.partial-"), names)
        for status in ec.SUFFIX:
            self.assertFalse(os.path.exists(os.path.join(out, "k" + ec.SUFFIX[status])))

    def test_unsafe_names_are_refused(self):
        for name in ("../x", ".hidden", "a/b", "x.interrupted", "x.transfer",
                     "x.transfer-failed", "a.partial-1", ""):
            with self.assertRaises(ec.CaptureError, msg=name):
                self.run_capture(["true"], name=name)
        self.assertEqual(self.listing(), [])


class CaptureBinding(Case):
    """AC-03: bound to the host, the candidate and the invocation."""

    def test_record_binds_candidate_host_and_invocation(self):
        rec = self.run_capture(["echo", "a b"], purpose="F2 staged state")
        on_disk = json.loads(self.read("cap", "record.json"))
        self.assertEqual(on_disk["candidate"], {"tag": TAG, "commit": COMMIT})
        self.assertEqual(on_disk["host"], HOST)
        inv = on_disk["invocation"]
        self.assertEqual(inv["argv"], ["echo", "a b"])
        self.assertEqual(len(inv["id"]), 36)
        self.assertLessEqual(inv["started_at"], inv["finished_at"])
        self.assertTrue(inv["started_at"].endswith("Z"))
        self.assertEqual(on_disk["purpose"], "F2 staged state")
        self.assertEqual(on_disk["format"], ec.FORMAT)
        self.assertEqual(rec["invocation"]["id"], inv["id"])

    def test_host_identity_is_read_from_the_host(self):
        ident = ec.host_identity()
        self.assertTrue(ident["hostname"])
        if os.path.exists("/etc/machine-id"):
            with open("/etc/machine-id") as f:
                self.assertEqual(ident["machine_id"], f.read().strip())
        rec = ec.capture(["true"], self.dir, "real", TAG, COMMIT)
        self.assertEqual(rec["host"], ident)

    def test_bad_candidates_are_refused_before_running(self):
        marker = os.path.join(self.dir, "ran")
        for tag, commit in (("0.8.4", COMMIT), ("main", COMMIT), (TAG, COMMIT[:12]),
                            (TAG, COMMIT.upper()), (TAG, "")):
            with self.assertRaises(ec.CaptureError):
                ec.capture(["touch", marker], self.dir, "c", tag, commit, host=HOST)
        self.assertFalse(os.path.exists(marker))
        self.assertEqual(self.listing(), [])

    def test_verify_checks_the_binding(self):
        self.run_capture(["true"])
        path = os.path.join(self.dir, "cap")
        ec.verify_capture(path, tag=TAG, commit=COMMIT, machine_id=HOST["machine_id"])
        with self.assertRaises(ec.VerifyError):
            ec.verify_capture(path, commit=OTHER_COMMIT)
        with self.assertRaises(ec.VerifyError):
            ec.verify_capture(path, tag="v0.8.3")
        with self.assertRaises(ec.VerifyError):
            ec.verify_capture(path, machine_id="n" * 32)


class CaptureSecrets(Case):
    """AC-04: secrets stay out of arguments and evidence."""

    def secrets(self):
        return {"OW_TEST_SECRET": SECRET}

    def test_a_secret_in_an_argument_is_refused_before_running(self):
        marker = os.path.join(self.dir, "ran")
        with self.assertRaises(ec.CaptureError):
            self.run_capture(sh("touch '%s'; echo %s" % (marker, SECRET)),
                             secrets=self.secrets())
        self.assertFalse(os.path.exists(marker))
        self.assertEqual(self.listing(), [])

    def test_a_secret_in_the_purpose_is_refused(self):
        with self.assertRaises(ec.CaptureError):
            self.run_capture(["true"], secrets=self.secrets(), purpose="uses " + SECRET)

    def test_inline_credentials_are_refused(self):
        for arg in ("--password=hunter22", "PGPASSWORD=x", "token=abc", "api_key=1",
                    "postgres://user:pw@db/x", "hlx_live_abc"):  # pragma: allowlist secret
            with self.assertRaises(ec.CaptureError, msg=arg):
                self.run_capture(["echo", arg])
        self.run_capture(["echo", "--token-file=/run/secret"], name="ok")

    def test_short_or_unset_secrets_are_refused(self):
        with self.assertRaises(ec.CaptureError):
            self.run_capture(["true"], secrets={"S": "short"})

    def test_the_secret_reaches_the_command_through_its_environment(self):
        rec = self.run_capture(sh('printf %s "$OW_TEST_SECRET" | wc -c'),
                               secrets=self.secrets())
        self.assertEqual(self.read("cap", "stdout").strip(), str(len(SECRET)).encode())
        self.assertEqual(rec["invocation"]["secret_env"], ["OW_TEST_SECRET"])

    def test_a_leaked_secret_withholds_the_streams(self):
        with self.assertRaises(ec.SecretInEvidence) as cm:
            self.run_capture(sh('echo "dsn has $OW_TEST_SECRET inside"; echo ok >&2'),
                             secrets=self.secrets())
        path = os.path.join(self.dir, "cap.withheld-secret")
        self.assertEqual(cm.exception.path, path)
        self.assertEqual(self.listing(), ["cap.withheld-secret"])  # no temporary left
        self.assertNotIn(SECRET, str(cm.exception))
        self.assertEqual(sorted(os.listdir(path)), ["SHA256SUMS", "exit", "record.json"])
        rec = ec.verify_capture(path, allow_incomplete=True)
        self.assertEqual(rec["withheld"], [{"secret_env": "OW_TEST_SECRET", "stream": "stdout"}])  # pragma: allowlist secret
        self.assertEqual(rec["status_before_withholding"], ec.COMPLETE)
        with self.assertRaises(ec.VerifyError):
            ec.verify_capture(path)
        self.assert_secret_absent()

    def test_a_secret_split_across_read_chunks_is_found(self):
        # One secret, straddling the 1 MiB read boundary, in stdout only.
        pad = (1 << 20) - 5
        with self.assertRaises(ec.SecretInEvidence) as cm:
            self.run_capture(sh('head -c %d /dev/zero; printf %%s "$OW_TEST_SECRET"' % pad),
                             secrets=self.secrets())
        self.assertEqual(cm.exception.record["withheld"],
                         [{"secret_env": "OW_TEST_SECRET", "stream": "stdout"}])  # pragma: allowlist secret
        self.assert_secret_absent()

    def test_cli_reads_secrets_by_variable_name(self):
        p = self.cli("run", "--out", self.dir, "--name", "c", "--tag", TAG, "--commit", COMMIT,
                     "--secret-env", "OW_TEST_SECRET", "--", "sh", "-c",
                     'echo "$OW_TEST_SECRET"', env={"OW_TEST_SECRET": SECRET})
        out, err = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 3, err)
        self.assertNotIn(SECRET.encode(), out + err)
        self.assert_secret_absent()
        p = self.cli("run", "--out", self.dir, "--name", "d", "--tag", TAG, "--commit", COMMIT,
                     "--secret-env", "OW_UNSET_VARIABLE", "--", "true")
        p.communicate(timeout=30)
        self.assertEqual(p.returncode, 1)

    def assert_secret_absent(self):
        for root, _dirs, files in os.walk(self.dir):
            for n in files:
                with open(os.path.join(root, n), "rb") as f:
                    self.assertNotIn(SECRET.encode(), f.read(), os.path.join(root, n))


class CaptureInterruption(Case):
    """AC-05: interrupted, timed-out and unstartable commands are kept and named."""

    def test_sigterm_to_the_capturer_keeps_what_was_captured(self):
        pidfile = os.path.join(self.dir, "child.pid")
        out = os.path.join(self.dir, "out")
        os.mkdir(out)
        p = self.cli("run", "--out", out, "--name", "i", "--tag", TAG, "--commit", COMMIT,
                     "--", "sh", "-c",
                     "echo $$ > '%s'; echo partial-line; exec sleep 30" % pidfile)
        self.assertTrue(self.wait_for(lambda: os.path.exists(pidfile)
                                      and os.path.getsize(pidfile) > 0))
        with open(pidfile) as f:
            child = int(f.read())
        p.send_signal(signal.SIGTERM)
        _out, err = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 128 + signal.SIGTERM, err)
        self.assertEqual(os.listdir(out), ["i.interrupted"])
        path = os.path.join(out, "i.interrupted")
        rec = ec.verify_capture(path, allow_incomplete=True)
        self.assertEqual(rec["status"], ec.INTERRUPTED)
        self.assertEqual(rec["exit"]["interrupted_by"], "SIGTERM")
        with open(os.path.join(path, "stdout"), "rb") as f:
            self.assertEqual(f.read(), b"partial-line\n")
        self.assertTrue(self.wait_for(lambda: not pid_alive(child)), "child survived")
        with self.assertRaises(ec.VerifyError):
            ec.verify_capture(path)

    def test_a_command_ignoring_sigterm_is_killed_after_the_grace(self):
        old = ec.KILL_GRACE
        ec.KILL_GRACE = 0.5
        self.addCleanup(setattr, ec, "KILL_GRACE", old)
        timer = threading.Timer(0.5, os.kill, (os.getpid(), signal.SIGTERM))
        timer.start()
        t0 = time.monotonic()
        with self.assertRaises(ec.CaptureIncomplete) as cm:
            self.run_capture(sh("trap '' TERM; echo stubborn; sleep 30 & wait; sleep 30"))
        self.assertLess(time.monotonic() - t0, 15)
        self.assertEqual(cm.exception.record["status"], ec.INTERRUPTED)
        self.assertEqual(cm.exception.record["exit"]["signal"], signal.SIGKILL)
        self.assertEqual(self.listing(), ["cap.interrupted"])

    def test_signal_handlers_are_restored(self):
        before = signal.getsignal(signal.SIGTERM)
        self.run_capture(["true"])
        self.assertIs(signal.getsignal(signal.SIGTERM), before)

    def test_timeout_is_kept_as_timed_out(self):
        with self.assertRaises(ec.CaptureIncomplete) as cm:
            self.run_capture(sh("echo early; exec sleep 30"), timeout=0.5)
        self.assertEqual(cm.exception.path, os.path.join(self.dir, "cap.timed-out"))
        rec = ec.verify_capture(cm.exception.path, allow_incomplete=True)
        self.assertTrue(rec["exit"]["timed_out"])
        self.assertEqual(self.read("cap.timed-out", "stdout"), b"early\n")

    def test_an_unstartable_command_is_kept_as_not_started(self):
        with self.assertRaises(ec.CaptureIncomplete) as cm:
            self.run_capture(["/nonexistent/evidence-command"])
        self.assertEqual(self.listing(), ["cap.not-started"])
        self.assertEqual(self.read("cap.not-started", "exit"), b"not-started\n")
        self.assertIn("nonexistent", cm.exception.record["exit"]["start_error"])
        p = self.cli("run", "--out", self.dir, "--name", "n2", "--tag", TAG, "--commit",
                     COMMIT, "--", "/nonexistent/evidence-command")
        p.communicate(timeout=30)
        self.assertEqual(p.returncode, 4)


ESCAPED = """
import os, sys
gate, pidfile, donefile = sys.argv[1:4]
os.setsid()  # leave the capture's process group, as a daemonizing child would
with open(pidfile, "w") as f:
    f.write(str(os.getpid()))
with open(gate) as g:
    g.read(1)
try:
    os.write(1, b"late-escaped\\n")
    result = "wrote"
except OSError as e:
    result = "refused: %s" % e.strerror
with open(donefile, "w") as f:
    f.write(result)
"""


DEADLINE = 20


class CaptureDescendants(Case):
    """AC-08: output from processes that outlive the command is captured or excluded.

    The descendant blocks on a FIFO gate. The gate opens only after the parent
    has exited and either the capture has returned or a second has passed, so
    a capture that stops at the parent's exit always loses the race."""

    def setUp(self):
        Case.setUp(self)
        for name in ("holder.pid", "escaped.pid"):
            self.addCleanup(self.kill_from_pidfile, os.path.join(self.dir, name))
        self.gate = os.path.join(self.dir, "gate")
        os.mkfifo(self.gate)
        self.parent_pid = os.path.join(self.dir, "parent.pid")
        old = ec.KILL_GRACE
        ec.KILL_GRACE = 0.5
        self.addCleanup(setattr, ec, "KILL_GRACE", old)

    def run(self, result=None):
        # A capture that never returns must fail this test by name, within
        # seconds, rather than hang the suite. SIGALRM is not one of the
        # signals capture() handles.
        def expired(_signum, _frame):
            raise AssertionError("the capture did not return within %ds" % DEADLINE)
        previous = signal.signal(signal.SIGALRM, expired)
        signal.alarm(DEADLINE)
        try:
            return Case.run(self, result)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)

    def kill_from_pidfile(self, path):
        try:
            with open(path) as f:
                kill_quietly(int(f.read()))
        except (OSError, ValueError):
            pass

    def release_after_parent_exits(self, returned, released):
        def run():
            self.wait_for(lambda: os.path.exists(self.parent_pid)
                          and os.path.getsize(self.parent_pid) > 0)
            with open(self.parent_pid) as f:
                pid = int(f.read())
            self.wait_for(lambda: not pid_alive(pid))
            returned.wait(1.0)
            released.set()
            with open(self.gate, "w") as g:
                g.write("x")
        t = threading.Thread(target=run, daemon=True)
        t.start()
        return t

    def late_writer(self, late):
        return sh("( read _ < '%s'; %s ) & echo $$ > '%s'; echo early"
                  % (self.gate, late, self.parent_pid))

    def test_a_descendant_writing_after_the_parent_exits_is_captured(self):
        returned, released = threading.Event(), threading.Event()
        t = self.release_after_parent_exits(returned, released)
        try:
            rec = self.run_capture(self.late_writer("echo late"))
            released_before_return = released.is_set()
        finally:
            returned.set()
            t.join(10)
        self.assertTrue(released_before_return, "the capture returned before the gate opened")
        self.assertEqual(self.read("cap", "stdout"), b"early\nlate\n")
        self.assertEqual(rec["status"], ec.COMPLETE)
        self.assertIs(rec["exit"].get("streams_closed"), True)
        ec.verify_capture(os.path.join(self.dir, "cap"))

    def test_a_descendant_printing_a_supplied_secret_late_is_withheld(self):
        returned, released = threading.Event(), threading.Event()
        t = self.release_after_parent_exits(returned, released)
        released_before_return = None
        try:
            with self.assertRaises(ec.SecretInEvidence):
                try:
                    self.run_capture(self.late_writer('echo "$OW_TEST_SECRET"'),
                                     secrets={"OW_TEST_SECRET": SECRET})
                finally:
                    released_before_return = released.is_set()
        finally:
            returned.set()
            t.join(10)
        self.assertTrue(released_before_return, "the capture returned before the gate opened")
        self.assertEqual(self.listing(), ["cap.withheld-secret", "gate", "parent.pid"])
        for root, _dirs, files in os.walk(self.dir):
            for n in files:
                if n == "gate":
                    continue
                with open(os.path.join(root, n), "rb") as f:
                    self.assertNotIn(SECRET.encode(), f.read(), n)

    def test_a_descendant_holding_the_streams_open_times_out(self):
        pidfile = os.path.join(self.dir, "holder.pid")
        t0 = time.monotonic()
        with self.assertRaises(ec.CaptureIncomplete) as cm:
            self.run_capture(sh("sleep 1000 & echo $! > '%s'; echo early" % pidfile),
                             timeout=1)
        self.assertLess(time.monotonic() - t0, 10)
        rec = cm.exception.record
        self.assertEqual(rec["status"], ec.TIMED_OUT)
        self.assertIs(rec["exit"].get("streams_closed"), True)
        with open(pidfile) as f:
            holder = int(f.read())
        self.assertTrue(self.wait_for(lambda: not pid_alive(holder)), "holder survived")
        self.assertEqual(self.read("cap.timed-out", "stdout"), b"early\n")
        with self.assertRaises(ec.VerifyError):
            ec.verify_capture(cm.exception.path)

    def test_interruption_while_a_descendant_holds_the_streams(self):
        timer = threading.Timer(0.5, os.kill, (os.getpid(), signal.SIGTERM))
        timer.start()
        pidfile = os.path.join(self.dir, "holder.pid")
        try:
            with self.assertRaises(ec.CaptureIncomplete) as cm:
                self.run_capture(sh("sleep 1000 & echo $! > '%s'; echo early" % pidfile))
        finally:
            # If the capture returned early, the signal must not reach a
            # process with no handler installed.
            timer.cancel()
        self.assertEqual(cm.exception.record["status"], ec.INTERRUPTED)
        self.assertEqual(self.read("cap.interrupted", "stdout"), b"early\n")

    def test_an_escaped_writer_cannot_reach_sealed_evidence(self):
        script = os.path.join(self.dir, "escaped.py")
        with open(script, "w") as f:
            f.write(ESCAPED)
        pidfile = os.path.join(self.dir, "escaped.pid")
        donefile = os.path.join(self.dir, "escaped.done")
        argv = ["sh", "-c", '"$0" -S "$1" "$2" "$3" "$4" & echo early',
                sys.executable, script, self.gate, pidfile, donefile]
        t0 = time.monotonic()
        with self.assertRaises(ec.CaptureIncomplete) as cm:
            self.run_capture(argv, timeout=1)
        self.assertLess(time.monotonic() - t0, 10)
        rec = cm.exception.record
        self.assertEqual(rec["status"], ec.TIMED_OUT)
        self.assertIs(rec["exit"].get("streams_closed"), False)
        path = cm.exception.path
        before = self.read("cap.timed-out", "stdout")
        self.assertTrue(os.path.exists(pidfile), "the escaped writer never started")
        with open(self.gate, "w") as g:
            g.write("x")
        self.assertTrue(self.wait_for(lambda: os.path.exists(donefile)))
        with open(donefile) as f:
            self.assertTrue(f.read().startswith("refused"), "the escaped write was accepted")
        self.assertEqual(self.read("cap.timed-out", "stdout"), before)
        self.assertEqual(before, b"early\n")
        ec.verify_capture(path, allow_incomplete=True)
        with self.assertRaises(ec.VerifyError):
            ec.verify_capture(path)

    def test_a_complete_record_with_open_streams_is_refused(self):
        self.run_capture(["true"])
        path = os.path.join(self.dir, "cap")
        rec_path = os.path.join(path, "record.json")
        os.chmod(rec_path, 0o600)
        with open(rec_path) as f:
            rec = json.load(f)
        rec["exit"]["streams_closed"] = False
        with open(rec_path, "w") as f:
            json.dump(rec, f)
        names = sorted(n for n in os.listdir(path) if n != "SHA256SUMS")
        sums = "".join("%s  %s\n" % (ec._sha256_file(os.path.join(path, n)), n) for n in names)
        os.chmod(os.path.join(path, "SHA256SUMS"), 0o600)
        with open(os.path.join(path, "SHA256SUMS"), "w") as f:
            f.write(sums)
        with self.assertRaises(ec.VerifyError) as cm:
            ec.verify_capture(path)
        self.assertIn("streams were still open", str(cm.exception))


class CaptureVerify(Case):
    """AC-06: verification catches any change to a sealed capture."""

    def setUp(self):
        Case.setUp(self)
        self.run_capture(sh("echo out; echo err >&2"))
        self.path = os.path.join(self.dir, "cap")

    def writable(self, name):
        p = os.path.join(self.path, name)
        os.chmod(p, 0o600)
        return p

    def test_an_untouched_capture_verifies(self):
        rec = ec.verify_capture(self.path, tag=TAG, commit=COMMIT)
        self.assertEqual(rec["status"], ec.COMPLETE)
        p = self.cli("verify", self.path, "--tag", TAG, "--commit", COMMIT)
        _o, err = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 0, err)

    def test_a_changed_stream_fails(self):
        with open(self.writable("stdout"), "ab") as f:
            f.write(b"x")
        with self.assertRaises(ec.VerifyError):
            ec.verify_capture(self.path)
        p = self.cli("verify", self.path)
        p.communicate(timeout=30)
        self.assertEqual(p.returncode, 1)

    def test_a_consistently_rewritten_stream_fails_against_the_record(self):
        with open(self.writable("stdout"), "wb") as f:
            f.write(b"filtered\n")
        self.reseal()
        with self.assertRaises(ec.VerifyError):
            ec.verify_capture(self.path)

    def test_a_changed_exit_fails_against_the_record(self):
        with open(self.writable("exit"), "wb") as f:
            f.write(b"exit=1\n")
        self.reseal()
        with self.assertRaises(ec.VerifyError):
            ec.verify_capture(self.path)

    def test_an_extra_file_fails(self):
        with open(os.path.join(self.path, "notes.txt"), "w") as f:
            f.write("x")
        with self.assertRaises(ec.VerifyError):
            ec.verify_capture(self.path)

    def test_a_missing_file_fails(self):
        os.unlink(os.path.join(self.path, "stderr"))
        with self.assertRaises(ec.VerifyError):
            ec.verify_capture(self.path)

    def test_a_renamed_incomplete_capture_fails(self):
        with self.assertRaises(ec.CaptureIncomplete) as cm:
            self.run_capture(sh("sleep 5"), name="slow", timeout=0.2)
        os.rename(cm.exception.path, os.path.join(self.dir, "slow"))
        with self.assertRaises(ec.VerifyError):
            ec.verify_capture(os.path.join(self.dir, "slow"), allow_incomplete=True)

    def test_an_incomplete_capture_relabeled_complete_fails(self):
        with self.assertRaises(ec.CaptureIncomplete) as cm:
            self.run_capture(sh("echo some; exec sleep 5"), name="slow", timeout=0.2)
        forged = os.path.join(self.dir, "slow")
        os.rename(cm.exception.path, forged)
        rec_path = os.path.join(forged, "record.json")
        os.chmod(rec_path, 0o600)
        with open(rec_path) as f:
            rec = json.load(f)
        rec["status"] = "complete"
        with open(rec_path, "w") as f:
            json.dump(rec, f)
        self.path = forged
        self.reseal()
        with self.assertRaises(ec.VerifyError) as err:
            ec.verify_capture(forged)
        self.assertIn("interrupted, timed out or never started", str(err.exception))

    def test_a_symlink_fails(self):
        os.unlink(os.path.join(self.path, "stderr"))
        os.symlink("/etc/hostname", os.path.join(self.path, "stderr"))
        with self.assertRaises(ec.VerifyError):
            ec.verify_capture(self.path)

    def reseal(self):
        names = sorted(n for n in os.listdir(self.path) if n != "SHA256SUMS")
        sums = "".join("%s  %s\n" % (ec._sha256_file(os.path.join(self.path, n)), n)
                       for n in names)
        with open(self.writable("SHA256SUMS"), "w") as f:
            f.write(sums)


class CaptureTransfer(Case):
    """AC-07: a remote capture is verified after transfer, before it is named."""

    def setUp(self):
        Case.setUp(self)
        self.remote = os.path.join(self.dir, "remote")
        self.local = os.path.join(self.dir, "local")
        os.mkdir(self.remote)
        os.mkdir(self.local)
        ec.capture(sh("echo staged-state; echo note >&2"), self.remote, "f2-staged", TAG,
                   COMMIT, host=HOST)

    def tar_cmd(self, name="f2-staged"):
        return ["tar", "-C", self.remote, "-cf", "-", name]

    def fetch(self, argv, **kw):
        kw.setdefault("tag", TAG)
        kw.setdefault("commit", COMMIT)
        return ec.fetch(argv, self.local, "f2-staged", **kw)

    def custom_tar(self, members):
        """members: list of (name, bytes or None for a dir, kind)."""
        path = os.path.join(self.dir, "crafted.tar")
        with tarfile.open(path, "w") as tf:
            for name, data, kind in members:
                ti = tarfile.TarInfo(name)
                if kind == "dir":
                    ti.type = tarfile.DIRTYPE
                    tf.addfile(ti)
                elif kind in ("sym", "hard"):
                    ti.type = tarfile.SYMTYPE if kind == "sym" else tarfile.LNKTYPE
                    ti.linkname = data.decode()
                    tf.addfile(ti)
                else:
                    ti.size = len(data)
                    tf.addfile(ti, io.BytesIO(data))
        return ["cat", path]

    def remote_members(self, top="f2-staged", mutate=None):
        out = [(top + "/", None, "dir")]
        src = os.path.join(self.remote, "f2-staged")
        for n in sorted(os.listdir(src)):
            with open(os.path.join(src, n), "rb") as f:
                data = f.read()
            if mutate:
                data = mutate(n, data)
            if data is not None:
                out.append((top + "/" + n, data, "file"))
        return out

    def assert_failed_kept(self):
        """Failed material is isolated in NAME.transfer-failed and never verifies."""
        self.assertEqual(os.listdir(self.local), ["f2-staged.transfer-failed"])
        failed = os.path.join(self.local, "f2-staged.transfer-failed")
        self.assertEqual(os.stat(failed).st_mode & 0o777, 0o700)
        self.assertEqual(sorted(os.listdir(failed)), ["REASON", "received", "transfer"])
        for sub in ("transfer", "received"):
            with self.assertRaises(ec.VerifyError, msg=sub):
                ec.verify_capture(os.path.join(failed, sub), allow_incomplete=True)
        with self.assertRaises(ec.VerifyError):
            ec.verify_capture(failed, allow_incomplete=True)

    def test_a_good_transfer_verifies_and_is_named(self):
        rec = self.fetch(self.tar_cmd(), machine_id=HOST["machine_id"])
        self.assertEqual(rec["path"], os.path.join(self.local, "f2-staged"))
        with open(os.path.join(self.local, "f2-staged", "stdout"), "rb") as f:
            self.assertEqual(f.read(), b"staged-state\n")
        self.assertEqual(sorted(os.listdir(self.local)), ["f2-staged", "f2-staged.transfer"])
        ec.verify_capture(os.path.join(self.local, "f2-staged.transfer"))
        ec.verify_capture(rec["path"], tag=TAG, commit=COMMIT)

    def test_cli_fetch(self):
        p = self.cli("fetch", "--out", self.local, "--name", "f2-staged", "--tag", TAG,
                     "--commit", COMMIT, "--", *self.tar_cmd())
        out, err = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 0, err)
        self.assertEqual(json.loads(out)["status"], "complete")

    def test_a_failed_transfer_command_keeps_its_stderr(self):
        with self.assertRaises(ec.TransferError):
            self.fetch(sh("echo 'ssh: connect to host rhn02 port 22: timed out' >&2; exit 255"))
        failed = os.path.join(self.local, "f2-staged.transfer-failed")
        self.assertEqual(os.listdir(self.local), ["f2-staged.transfer-failed"])
        self.assertEqual(sorted(os.listdir(failed)), ["REASON", "transfer"])
        with open(os.path.join(failed, "transfer", "stderr"), "rb") as f:
            self.assertIn(b"timed out", f.read())
        with self.assertRaises(ec.VerifyError):
            ec.verify_capture(os.path.join(failed, "transfer"))

    def test_an_interrupted_transfer_is_isolated(self):
        with self.assertRaises(ec.TransferError):
            self.fetch(sh("exec sleep 30"), timeout=0.3)
        failed = os.path.join(self.local, "f2-staged.transfer-failed")
        self.assertEqual(os.listdir(self.local), ["f2-staged.transfer-failed"])
        self.assertEqual(sorted(os.listdir(failed)), ["REASON", "transfer"])
        with self.assertRaises(ec.VerifyError):
            ec.verify_capture(os.path.join(failed, "transfer"), allow_incomplete=True)

    def test_no_supplied_secret_reaches_a_transferred_artifact(self):
        secrets = {"OW_TEST_SECRET": SECRET}
        with self.assertRaises(ec.SecretInEvidence):
            ec.capture(sh('echo "$OW_TEST_SECRET"'), self.remote, "leak", TAG, COMMIT,
                       host=HOST, secrets=secrets)
        cmd = ["tar", "-C", self.remote, "-cf", "-", "leak.withheld-secret"]
        with self.assertRaises(ec.TransferError):
            ec.fetch(cmd, self.local, "leak", TAG, COMMIT)
        shutil.rmtree(self.local)
        os.mkdir(self.local)
        rec = ec.fetch(cmd, self.local, "leak", TAG, COMMIT, allow_incomplete=True)
        self.assertEqual(rec["status"], ec.WITHHELD)
        for root, _dirs, files in os.walk(self.dir):
            for n in files:
                with open(os.path.join(root, n), "rb") as f:
                    self.assertNotIn(SECRET.encode(), f.read(), os.path.join(root, n))

    def test_a_truncated_transfer_fails(self):
        size = len(subprocess.run(self.tar_cmd(), stdout=subprocess.PIPE).stdout)
        with self.assertRaises(ec.TransferError):
            self.fetch(sh("tar -C '%s' -cf - f2-staged | head -c %d" % (self.remote, size // 3)))
        self.assert_failed_kept()

    def test_a_corrupted_file_fails(self):
        def flip(n, data):
            return b"staged-statf\n" if n == "stdout" else data
        with self.assertRaises(ec.TransferError):
            self.fetch(self.custom_tar(self.remote_members(mutate=flip)))
        self.assert_failed_kept()

    def test_a_missing_file_fails(self):
        with self.assertRaises(ec.TransferError):
            self.fetch(self.custom_tar(self.remote_members(
                mutate=lambda n, d: None if n == "stderr" else d)))
        self.assert_failed_kept()

    def test_an_unlisted_extra_file_fails(self):
        members = self.remote_members() + [("f2-staged/extra", b"x", "file")]
        with self.assertRaises(ec.TransferError):
            self.fetch(self.custom_tar(members))
        self.assert_failed_kept()

    def test_unsafe_members_are_refused(self):
        for bad, reason in (([("../escape", b"x", "file")], "refused tar member"),
                            ([("/abs", b"x", "file")], "refused tar member"),
                            ([("f2-staged/link", b"/etc/passwd", "sym")], "not a regular file"),
                            ([("f2-staged/up", b"../../outside", "sym")], "not a regular file"),
                            ([("f2-staged/hard", b"../../etc/passwd", "hard")],
                             "not a regular file"),
                            ([("f2-staged/hard2", b"f2-staged/stdout", "hard")],
                             "not a regular file"),
                            ([("f2-staged/../escape", b"x", "file")], "refused tar member"),
                            ([("../", None, "dir")], "refused tar member"),
                            ([("f2-staged/sub/deep", b"x", "file")], "refused tar member"),
                            ([("other/stdout", b"x", "file")], "top-level directories")):
            shutil.rmtree(self.local)
            os.mkdir(self.local)
            with self.assertRaises(ec.TransferError, msg=str(bad)) as cm:
                self.fetch(self.custom_tar(self.remote_members() + bad))
            self.assertIn(reason, str(cm.exception))
            self.assert_failed_kept()
            self.assertEqual(sorted(os.listdir(self.dir)), ["crafted.tar", "local", "remote"])
            self.assertFalse(os.path.lexists(os.path.join(self.dir, "outside")))
            self.assertFalse(os.path.lexists(os.path.join(self.dir, "escape")))
            self.assertFalse(os.path.lexists("/abs"))

    def test_a_symlink_in_place_of_a_stream_is_refused(self):
        members = [m for m in self.remote_members() if m[0] != "f2-staged/stdout"]
        members.append(("f2-staged/stdout", b"/etc/passwd", "sym"))
        with self.assertRaises(ec.TransferError) as cm:
            self.fetch(self.custom_tar(members))
        self.assertIn("not a regular file", str(cm.exception))
        self.assert_failed_kept()

    def test_the_wrong_capture_is_refused(self):
        ec.capture(["true"], self.remote, "other", TAG, COMMIT, host=HOST)
        with self.assertRaises(ec.TransferError):
            self.fetch(self.tar_cmd("other"))
        self.assert_failed_kept()

    def test_the_wrong_candidate_or_host_is_refused(self):
        with self.assertRaises(ec.TransferError):
            self.fetch(self.tar_cmd(), commit=OTHER_COMMIT)
        self.assert_failed_kept()
        shutil.rmtree(self.local)
        os.mkdir(self.local)
        with self.assertRaises(ec.TransferError):
            self.fetch(self.tar_cmd(), machine_id="n" * 32)
        self.assert_failed_kept()

    def test_an_interrupted_remote_capture_needs_allow_incomplete(self):
        with self.assertRaises(ec.CaptureIncomplete):
            ec.capture(sh("sleep 5"), self.remote, "slow", TAG, COMMIT, host=HOST, timeout=0.2)
        cmd = self.tar_cmd("slow.timed-out")
        with self.assertRaises(ec.TransferError):
            ec.fetch(cmd, self.local, "slow", TAG, COMMIT)
        shutil.rmtree(self.local)
        os.mkdir(self.local)
        rec = ec.fetch(cmd, self.local, "slow", TAG, COMMIT, allow_incomplete=True)
        self.assertEqual(rec["path"], os.path.join(self.local, "slow.timed-out"))

    def test_a_retry_after_failure_is_refused_until_moved_aside(self):
        with self.assertRaises(ec.TransferError):
            self.fetch(self.tar_cmd(), commit=OTHER_COMMIT)
        with self.assertRaises(ec.CaptureError):
            self.fetch(self.tar_cmd())


if __name__ == "__main__":
    unittest.main(verbosity=2)
